# KMS Test Library — New Infrastructure for Multi-Output & Multi-Feature Testing

---

## Goal

We want to make it easy to write KMS tests that exercise **multiple display
features simultaneously across multiple outputs** — things like DSC + Big Joiner
on one output while a second output runs normally, or HDR + DSC + Joiner on a
single output.

Today, writing such a test requires the author to manually handle output
scanning, pipe allocation (with joiner awareness), mode selection, framebuffer
creation, bandwidth validation, and debugfs state management. This proposal
adds composable library functions that handle each of these responsibilities,
so test authors can focus on the actual test logic.

**Everything below is purely additive.** Existing tests compile unchanged.
Existing library APIs are preserved as-is.

---

## Architecture at a Glance

The new infrastructure is organized into **eight independent layers**. Each layer
solves one specific responsibility. They can be used individually or composed
together.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           Test Code                                      │
│                                                                          │
│  igt_subtest("dsc-joiner-dual-output") {                                │
│      for_each_connected_output_where(display, output,                    │
│              igt_output_supports_dsc(fd, output) &&                      │
│              igt_output_get_max_joiner(fd, output) >= BIG_JOINER)        │
│      { ... }                                                             │
│  }                                                                       │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Layer 7: Composition Macros                                             │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │ for_each_connected_output_where(display, output, pred)         │      │
│  │ for_each_pipe_output_combo(display, crtc, output)              │      │
│  │ for_each_output_combo(display, outputs[], n, preds[])          │      │
│  └────────────────────────────────────────────────────────────────┘      │
│                                                                          │
│  Layer 3: Multi-Output Orchestrator                                      │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │ igt_multi_output_setup(display, specs[], n, &ctx)              │      │
│  │ igt_multi_output_commit(&ctx)                                  │      │
│  │ igt_multi_output_teardown(&ctx)                                │      │
│  └────────────────────────────────────────────────────────────────┘      │
│                                                                          │
│  Layer 4: BW-Safe Commit    │  Layer 5: Debugfs Guard                    │
│  ┌───────────────────────┐  │  ┌────────────────────────────────┐        │
│  │ igt_bw_safe_commit()  │  │  │ IGT_DEBUGFS_GUARD_DSC(fd, out) │        │
│  │ igt_try_bw_commit()   │  │  │ IGT_DEBUGFS_GUARD_JOINER(...)  │        │
│  └───────────────────────┘  │  └────────────────────────────────┘        │
│                                                                          │
│  Layer 2: Pipe Allocator    │  Layer 6: Output Classifier                │
│  ┌───────────────────────┐  │  ┌────────────────────────────────┐        │
│  │ igt_allocate_pipes()  │  │  │ igt_classify_outputs()         │        │
│  │ igt_find_consecutive  │  │  │ igt_find_output_with()         │        │
│  │   _pipes()            │  │  │ igt_count_outputs_with()       │        │
│  └───────────────────────┘  │  └────────────────────────────────┘        │
│                                                                          │
│  Layer 1: Predicate Functions                                            │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │ igt_output_supports_dsc(fd, output)                            │      │
│  │ igt_output_supports_hdr(fd, output)                            │      │
│  │ igt_output_supports_vrr(fd, output)                            │      │
│  │ igt_output_supports_psr(fd, output, mode)                      │      │
│  │ igt_output_get_max_joiner(fd, output)                          │      │
│  └────────────────────────────────────────────────────────────────┘      │
│                                                                          │
│  Layer 8: Convenience Helpers                                            │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │ igt_output_setup_fb(fd, output, format, modifier, &fb)         │      │
│  │ igt_output_require_dsc/hdr/vrr(fd, output)                     │      │
│  │ igt_find_joiner_mode(fd, output, level, &mode)                 │      │
│  └────────────────────────────────────────────────────────────────┘      │
│                                                                          │
│  Existing APIs (UNCHANGED)                                               │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │ lib/igt_dsc.c   — 14 functions (enable/force/bpc/format/frac)  │      │
│  │ lib/igt_psr.c   — 15 functions (enable/disable/wait/mode)      │      │
│  │ lib/i915/intel_fbc.c — 8 functions (enable/disable/wait)       │      │
│  │ igt_output_has_prop() / igt_crtc_has_prop()                    │      │
│  │ igt_display_commit2() / igt_display_try_commit2()              │      │
│  └────────────────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────────┘
```

**Key design decisions:**

- **Composable library functions** 
Functions return values. Tests make decisions.

- **Predicate functions for feature detection.** Each feature gets a predicate
  (`igt_output_supports_dsc()`) that checks the full prerequisite chain and
  prints diagnostic info. Predicates compose naturally with `&&` and `||`.

- **Preserves existing rich APIs.** PSR has 15 functions with mode parameters.
  These are untouched — the new API sits alongside them, not on top.

- **Each layer is independently useful.** A test can use just the pipe allocator,
  or just the predicates, or just the output classifier. No forced buy-in.

- **100% backward compatible.** Purely additive. No existing test needs changes.

---

## Layer 1 — Feature Detection Predicates

### What this is

A set of boolean functions in a new `lib/igt_kms_feature.h` that answer
"does this output support feature X?" by checking the full prerequisite chain
(source capability, sink capability, connector type requirements).

Each predicate prints `igt_info()` explaining *why* a feature isn't supported,
which helps with debugging skip reasons.

### Why predicates (not an enum)?

```c
/* lib/igt_kms_feature.h */

/**
 * igt_kms_feature_t - Display features that can be queried on source or sink
 *
 * Used with igt_source_supports_feature() and igt_sink_supports_feature()
 * to provide a uniform feature detection API across all KMS tests.
 */
typedef enum {
    IGT_FEATURE_DSC         = BIT(0),   /* Display Stream Compression */
    IGT_FEATURE_FBC         = BIT(1),   /* Frame Buffer Compression */
    IGT_FEATURE_PSR1        = BIT(2),   /* Panel Self-Refresh 1 */
    IGT_FEATURE_PSR2        = BIT(3),   /* Panel Self-Refresh 2 */
    IGT_FEATURE_PR          = BIT(4),   /* Panel Replay */
    IGT_FEATURE_PR_SEL_FETCH= BIT(5),   /* Panel Replay Selective Fetch */
    IGT_FEATURE_HDR         = BIT(6),   /* HDR Static Metadata Type 1 */
    IGT_FEATURE_VRR         = BIT(7),   /* Variable Refresh Rate */
    IGT_FEATURE_DRRS        = BIT(8),   /* Display Refresh Rate Switching */
    IGT_FEATURE_BIG_JOINER  = BIT(9),   /* 2-pipe join */
    IGT_FEATURE_ULTRA_JOINER= BIT(10),  /* 4-pipe join */
    IGT_FEATURE_CCS         = BIT(11),  /* Color Compression Surfaces */
    IGT_FEATURE_GAMMA_LUT   = BIT(12),  /* HW gamma LUT */
    IGT_FEATURE_DEGAMMA_LUT = BIT(13),  /* HW degamma LUT */
    IGT_FEATURE_CTM         = BIT(14),  /* Color Transformation Matrix */
    IGT_FEATURE_SCALING     = BIT(15),  /* HW plane scaling */
    IGT_FEATURE_ASYNC_FLIP  = BIT(16),  /* Async page flip */
    IGT_FEATURE_WRITEBACK   = BIT(17),  /* Writeback connector */
    IGT_FEATURE_CONTENT_PROT= BIT(18),  /* HDCP content protection */
    IGT_FEATURE_DITHER      = BIT(19),  /* HW dithering */
    IGT_FEATURE_SHARPNESS   = BIT(20),  /* Sharpness filter */
    IGT_FEATURE_COLOR_PIPELINE = BIT(21), /* Color pipeline / colorops */
    IGT_FEATURE_LOBF        = BIT(22),  /* Link Off Between Frames */
} igt_kms_feature_t;

/**
 * igt_source_supports_feature - Check if the source (GPU/driver) supports a feature
 * @fd: DRM file descriptor
 * @feature: Feature to query
 *
 * Returns true if the GPU/driver combination supports the given feature.
 * This checks driver capabilities, display version, debugfs, and properties.
 * It does NOT check the connected sink — use igt_sink_supports_feature() for that.
 */
bool igt_source_supports_feature(int fd, igt_kms_feature_t feature)
{
    switch (feature) {
    case IGT_FEATURE_DSC:
        return igt_is_dsc_supported_by_source(fd);

    case IGT_FEATURE_FBC:
        /* FBC has per-pipe support, but this is a coarse "any pipe" check */
        return intel_fbc_supported_on_chipset(fd, PIPE_A) ||
               intel_fbc_supported_on_chipset(fd, PIPE_B);

    case IGT_FEATURE_PSR1:
    case IGT_FEATURE_PSR2:
    case IGT_FEATURE_PR:
    case IGT_FEATURE_PR_SEL_FETCH:
        return is_psr_enable_possible(fd, _feature_to_psr_mode(feature));

    case IGT_FEATURE_HDR:
        /* Source always exposes HDR_OUTPUT_METADATA property if HW supports it.
         * Actual check is: does any connector have the property? */
        return _any_connector_has_prop(fd, IGT_CONNECTOR_HDR_OUTPUT_METADATA);

    case IGT_FEATURE_VRR:
        return _any_connector_has_prop(fd, IGT_CONNECTOR_VRR_CAPABLE);

    case IGT_FEATURE_BIG_JOINER:
        return igt_get_max_dotclock(fd) > 0; /* joiner exists if dotclock is queryable */

    case IGT_FEATURE_ULTRA_JOINER:
        return _ultra_joiner_platform(fd);

    case IGT_FEATURE_GAMMA_LUT:
        return _any_crtc_has_prop(fd, IGT_CRTC_GAMMA_LUT);

    case IGT_FEATURE_DEGAMMA_LUT:
        return _any_crtc_has_prop(fd, IGT_CRTC_DEGAMMA_LUT);

    case IGT_FEATURE_CTM:
        return _any_crtc_has_prop(fd, IGT_CRTC_CTM);

    case IGT_FEATURE_SHARPNESS:
        return _any_crtc_has_prop(fd, IGT_CRTC_SHARPNESS_STRENGTH);

    case IGT_FEATURE_ASYNC_FLIP:
        return drmGetCap(fd, DRM_CAP_ASYNC_PAGE_FLIP, &val) == 0 && val;

    /* ... etc for each feature */
    }
}
```

Currently if we look for ex DSC (`lib/igt_dsc.c` has 14
functions for BPC control, output format, fractional BPP). PSR has modes
(PSR1, PSR2, Panel Replay). A boolean predicate answers "can I use this
feature?" while the existing rich APIs control *how* to use it. This keeps
both concerns separate and preserves the full parameter space.

For features where a single DRM property check is sufficient (color
management, scaling), the existing `igt_output_has_prop()` /
`igt_crtc_has_prop()` is already the right abstraction — we don't wrap those.

### Full API

```c
/* ── lib/igt_kms_feature.h ──────────────────────────────────────── */

/*
 * Each predicate checks the full prerequisite chain for a feature.
 * Returns true if the output (both source GPU and sink panel) supports it.
 * Prints igt_info() with the specific reason on failure.
 */

/* DSC: source support + sink support + FEC (for external DP) */
bool igt_output_supports_dsc(int fd, igt_output_t *output);

/* HDR: HDR_OUTPUT_METADATA property + EDID CTA HDR metadata */
bool igt_output_supports_hdr(int fd, igt_output_t *output);

/* VRR: VRR_CAPABLE property exists and reads true */
bool igt_output_supports_vrr(int fd, igt_output_t *output);

/* VRR range: parses debugfs vrr_range file, returns min/max Hz */
bool igt_output_get_vrr_range(int fd, igt_output_t *output,
                              int *min_hz, int *max_hz);

/* PSR: preserves mode parameter (PSR_MODE_1, PSR_MODE_2, etc.) */
bool igt_output_supports_psr(int fd, igt_output_t *output,
                             enum psr_mode mode);

/* Joiner: returns JOINED_PIPES_NONE / BIG_JOINER / ULTRA_JOINER */
enum joined_pipes igt_output_get_max_joiner(int fd, igt_output_t *output);

/* FBC: per-pipe check */
bool igt_output_supports_fbc(int fd, enum pipe pipe);

/* HDCP */
bool igt_output_supports_content_protection(int fd, igt_output_t *output);

/* DRRS */
bool igt_output_supports_drrs(int fd, igt_output_t *output);

/* Force joiner: can debugfs force joiner be used on this output? */
bool igt_output_has_force_joiner(int fd, igt_output_t *output);

/* Force ultra joiner: force joiner + DSC sink + ≥8 DSC slices */
bool igt_output_can_force_ultra_joiner(int fd, igt_output_t *output);

/* Source-only checks (no output needed) */
bool igt_source_supports_dsc(int fd);
bool igt_source_supports_joiner(int fd);
```

### Implementation — `igt_output_supports_dsc()`

> **Note:** Walk through the chain of checks. Each early-return
> prints *why* DSC isn't available, which shows up in test logs when a
> subtest is skipped.

```c
bool igt_output_supports_dsc(int fd, igt_output_t *output)
{
    /* Check 1: Does the GPU have a DSC encoder? */
    if (!igt_is_dsc_supported_by_source(fd)) {
        igt_info("DSC: GPU does not have DSC encoder support\n");
        return false;
    }

    /* Check 2: Does the sink (panel/monitor) advertise DSC? */
    if (!igt_is_dsc_supported_by_sink(fd, output->name)) {
        igt_info("DSC: sink %s does not support DSC\n", output->name);
        return false;
    }

    /*
     * Check 3: External DP panels need FEC (Forward Error Correction)
     * as a prerequisite for DSC. Internal panels (eDP) don't.
     */
    if (!output_is_internal_panel(output) &&
        !igt_is_fec_supported(fd, output->name)) {
        igt_info("DSC: external connector %s requires FEC which "
                 "is not supported\n", output->name);
        return false;
    }

    return true;
}
```

### Implementation — `igt_output_supports_hdr()`

> **Note:** This promotes the `is_panel_hdr()` function from
> `tests/kms_hdr.c` into the library so any test can reuse it.

```c
bool igt_output_supports_hdr(int fd, igt_output_t *output)
{
    /* Check 1: Does the connector expose HDR_OUTPUT_METADATA property? */
    if (!igt_output_has_prop(output, IGT_CONNECTOR_HDR_OUTPUT_METADATA)) {
        igt_info("HDR: %s lacks HDR_OUTPUT_METADATA property\n",
                 output->name);
        return false;
    }

    /*
     * Check 2: Does the EDID have an HDR Static Metadata Descriptor
     * in its CTA extension block? Property existence alone isn't enough —
     * the panel must actually advertise HDR capability.
     */
    if (!igt_is_hdr_panel(fd, output)) {
        igt_info("HDR: %s EDID lacks HDR Static Metadata "
                 "Descriptor\n", output->name);
        return false;
    }

    return true;
}
```

### Functions promoted from test files to library

| Function | Currently in | Becomes |
|----------|-------------|---------|
| `is_panel_hdr()` | `tests/kms_hdr.c` | `igt_is_hdr_panel()` in `lib/igt_kms_feature.c` |
| `get_vrr_range()` | `tests/kms_vrr.c` | `igt_output_get_vrr_range()` in `lib/igt_kms_feature.c` |

### What we DON'T wrap

Single-property checks remain as-is — they're already the right abstraction:

```c
/* These don't need wrappers — the property check IS the full detection */
igt_output_has_prop(output, IGT_CONNECTOR_SCALING_MODE);
igt_crtc_has_prop(crtc, IGT_CRTC_DEGAMMA_LUT);
igt_crtc_has_prop(crtc, IGT_CRTC_GAMMA_LUT);
igt_crtc_has_prop(crtc, IGT_CRTC_CTM);
```

---

## Layer 2 — Joiner-Aware Pipe Allocator

### What this is

A pipe allocation API that understands joiner requirements. It assigns
pipes to N outputs in a single call, handling the constraint that big joiner
needs 2 consecutive pipes and ultra joiner needs 4.

### Where the code comes from

`tests/intel/kms_joiner_helper.c` already contains well-tested functions
for this: `find_consecutive_pipes()`, `get_required_pipes()`, and
`igt_assign_pipes_for_outputs()`. These are currently `static` in a test
helper file. We promote them to `lib/igt_kms.c` and make them public.

### Full API

```c
/* ── Added to lib/igt_kms.h ──────────────────────────────────────── */

/*
 * How many pipes does this output need for its current mode?
 * Returns: 1 (normal), 2 (big joiner), 4 (ultra joiner)
 *
 * Uses the output's override mode if set, otherwise scans
 * the output's mode list and checks against max_dotclock.
 */
int igt_output_get_required_pipes(int fd, igt_output_t *output);

/*
 * Find N consecutive free pipes starting from a valid master pipe.
 *
 * @n_crtcs:        Total pipes on this platform
 * @available_mask: Bitmask of pipes not yet assigned to other outputs
 * @master_mask:    Bitmask of pipes that can serve as joiner master
 *                  (platform constraint: pipe P is master-capable if
 *                   both pipe P and pipe P+1 exist and are valid)
 * @need:           How many consecutive pipes we need (1, 2, or 4)
 *
 * Returns: Starting pipe index, or -1 if no valid assignment exists.
 */
int igt_find_consecutive_pipes(int n_crtcs, uint32_t available_mask,
                               uint32_t master_mask, int need);

/*
 * Bitmask of pipes that can serve as joiner master.
 * Computed from display topology — pipe P is valid master if
 * pipe P and P+1 both exist and are not fused off.
 */
uint32_t igt_get_master_pipe_mask(igt_display_t *display);

/*
 * Bitmask of all valid (non-fused-off) pipes.
 */
uint32_t igt_get_valid_pipe_mask(igt_display_t *display);
```

### Implementation — Pipe Mask Helpers

> **Note:** These two functions are computed once during
> `igt_display_require()` and cached in the display struct. They encode
> the platform's pipe topology — which pipes exist and which can be
> joiner masters.

```c
uint32_t igt_get_valid_pipe_mask(igt_display_t *display)
{
    uint32_t mask = 0;

    for (int i = 0; i < display->n_pipes; i++) {
        /*
         * pipe_from_crtc_id_mapping[] maps pipe index to CRTC ID.
         * A non-zero entry means the pipe exists (not fused off).
         */
        if (display->pipes[i].crtc_id)
            mask |= BIT(i);
    }

    return mask;
}

uint32_t igt_get_master_pipe_mask(igt_display_t *display)
{
    uint32_t valid = display->valid_pipe_mask;
    uint32_t mask = 0;

    /*
     * Pipe P can be a joiner master if both pipe P and pipe P+1
     * are valid. This is a hardware constraint — the master pipe
     * drives the timing, and the slave must be the next physical pipe.
     *
     * For non-joiner modes (need=1), every valid pipe is usable,
     * so find_consecutive_pipes() handles that case separately.
     */
    for (int i = 0; i < display->n_pipes - 1; i++) {
        if ((valid & BIT(i)) && (valid & BIT(i + 1)))
            mask |= BIT(i);
    }

    return mask;
}
```

### Implementation — `igt_output_get_required_pipes()`

> **Note:** This is promoted from `kms_joiner_helper.c` where
> it exists as `get_required_pipes()`. The logic checks whether the output's
> mode exceeds the platform's single-pipe bandwidth limit.

```c
int igt_output_get_required_pipes(int fd, igt_output_t *output)
{
    drmModeModeInfo *mode;
    int max_dotclock;

    /*
     * Use the override mode if the test has set one,
     * otherwise use the output's preferred (default) mode.
     */
    mode = igt_output_get_mode(output);
    if (!mode)
        return 1;

    /*
     * Query the platform's maximum dot clock for a single pipe.
     * This comes from i915/xe device info via debugfs.
     */
    max_dotclock = igt_get_max_dotclock(fd);
    if (max_dotclock <= 0)
        return 1;

    /*
     * Ultra joiner: mode needs > 2x single-pipe bandwidth.
     * Big joiner:   mode needs > 1x single-pipe bandwidth.
     * Normal:       mode fits in a single pipe.
     */
    if (mode->clock > 2 * max_dotclock) {
        output->required_pipes = 4;
        return 4;
    }

    if (mode->clock > max_dotclock) {
        output->required_pipes = 2;
        return 2;
    }

    output->required_pipes = 1;
    return 1;
}
```

### Implementation — `igt_find_consecutive_pipes()`

> **Note:** This is promoted from `kms_joiner_helper.c`. It scans
> the available pipe mask for a run of N consecutive pipes that starts at
> a valid master pipe.

```c
int igt_find_consecutive_pipes(int n_crtcs, uint32_t available_mask,
                               uint32_t master_mask, int need)
{
    /*
     * For non-joiner modes (need=1), any available pipe works.
     * No master constraint — just find the first free pipe.
     */
    if (need == 1) {
        for (int p = 0; p < n_crtcs; p++)
            if (available_mask & BIT(p))
                return p;
        return -1;
    }

    /*
     * For joiner modes (need=2 or 4), the starting pipe must be
     * in master_mask, and all 'need' consecutive pipes must be
     * available.
     */
    for (int p = 0; p <= n_crtcs - need; p++) {
        /* Starting pipe must be a valid master */
        if (!(master_mask & BIT(p)))
            continue;

        /* Check that all 'need' consecutive pipes are free */
        bool all_free = true;
        for (int k = 0; k < need; k++) {
            if (!(available_mask & BIT(p + k))) {
                all_free = false;
                break;
            }
        }

        if (all_free)
            return p;
    }

    return -1;
}
```

### The Allocator — `igt_allocate_pipes()`

> **Note:** This is the central function. Walk through the algorithm
> step by step. The key insight is sorting by descending pipe requirement —
> outputs needing 4 pipes get assigned first so they don't get blocked by
> outputs needing 1.

```c
/*
 * Assign pipes to N outputs, respecting joiner constraints.
 *
 * @display:    igt_display_t
 * @outputs:    Array of output pointers to assign pipes to
 * @n_outputs:  Number of outputs
 * @used_pipes: [in/out] Bitmask of already-used pipes.
 *              Updated on success. Pass NULL for fresh allocation.
 *
 * Returns: 0 on success, -1 if no valid assignment exists.
 *
 * Does NOT commit — caller decides when to commit.
 */
int igt_allocate_pipes(igt_display_t *display,
                       igt_output_t **outputs, int n_outputs,
                       uint32_t *used_pipes);
```

### Implementation

```c
int igt_allocate_pipes(igt_display_t *display,
                       igt_output_t **outputs, int n_outputs,
                       uint32_t *used_pipes)
{
    uint32_t avail = display->valid_pipe_mask;
    uint32_t master_mask = display->master_pipe_mask;
    int fd = display->drm_fd;

    /* If caller passed in already-used pipes, exclude them */
    if (used_pipes)
        avail &= ~(*used_pipes);

    /*
     * Step 1: Determine pipe requirement for each output.
     *
     * This queries each output's current mode (or override mode)
     * and checks against the platform's max dotclock to determine
     * if joiner is needed.
     */
    int requirements[n_outputs];
    int order[n_outputs];

    for (int i = 0; i < n_outputs; i++) {
        requirements[i] = igt_output_get_required_pipes(fd, outputs[i]);
        order[i] = i;
    }

    /*
     * Step 2: Sort by descending pipe requirement.
     *
     * Ultra joiner (4 pipes) gets assigned first, then big joiner (2),
     * then normal (1). This prevents a 1-pipe output from taking a
     * position that blocks a 4-pipe output later.
     */
    for (int i = 0; i < n_outputs - 1; i++)
        for (int j = i + 1; j < n_outputs; j++)
            if (requirements[order[i]] < requirements[order[j]]) {
                int tmp = order[i];
                order[i] = order[j];
                order[j] = tmp;
            }

    /*
     * Step 3: For each output (in priority order), find consecutive
     * free pipes and assign.
     */
    for (int i = 0; i < n_outputs; i++) {
        int idx = order[i];
        int need = requirements[idx];

        int master = igt_find_consecutive_pipes(display->n_pipes,
                                                 avail, master_mask,
                                                 need);
        if (master < 0) {
            igt_info("Pipe allocation failed: cannot find %d "
                     "consecutive pipes for %s\n",
                     need, outputs[idx]->name);
            return -1;
        }

        /* Assign this output to the master pipe's CRTC */
        igt_output_set_crtc(outputs[idx],
                            igt_crtc_for_pipe(display, master));

        /* Mark all consumed pipes as used */
        for (int p = master; p < master + need; p++)
            avail &= ~BIT(p);
    }

    /* Report back which pipes are in use */
    if (used_pipes)
        *used_pipes = display->valid_pipe_mask & ~avail;

    return 0;
}
```

### Why we don't modify `__igt_pipe_populate_outputs()`

> **Note:** This is a common question — "why not just fix the
> existing function?" There's a fundamental chicken-and-egg constraint.

`__igt_pipe_populate_outputs()` runs during `igt_display_init()`, **before**
any mode is selected. But joiner detection requires knowing the mode (to
check against max_dotclock). You can't know how many pipes an output needs
until you've picked a mode, and the existing function runs before that.

Additionally, it fills `chosen_outputs[pipe]` — a 1:1 array indexed by pipe.
Joiner means one output spans multiple pipes, which doesn't fit that data
model.

So `igt_allocate_pipes()` is a **separate, opt-in API** called after mode
selection. The existing codepath is untouched.

---

## Layer 3 — Multi-Output Orchestrator

### What this is

A setup/commit/teardown API that handles the full lifecycle of a multi-output
test configuration. You declare what outputs you need (using predicates), and
the orchestrator finds matching outputs, selects modes, allocates pipes,
creates framebuffers, and validates bandwidth — all in one call.

### Data Structures

> **Note:** Walk through the two structs. `igt_output_spec_t` is
> what the test author fills in (2 fields). Everything else is filled by the
> orchestrator.

```c
/*
 * Describes what kind of output the test needs.
 * The test author fills in the predicate and optional mode finder.
 * The orchestrator fills in everything else.
 */
typedef struct {
    /* ── Filled by test author ── */

    /* Required: returns true for outputs that match what you need */
    bool (*predicate)(int fd, igt_output_t *output);

    /* Optional: finds a specific mode. NULL = use output's default mode */
    bool (*find_mode)(int fd, igt_output_t *output, drmModeModeInfo *mode);

    /* ── Filled by orchestrator ── */

    igt_output_t *output;       /* The matched output */
    drmModeModeInfo mode;       /* The selected mode */
    enum pipe master_pipe;      /* The assigned master pipe */
    igt_fb_t fb;                /* Framebuffer matching mode dimensions */
} igt_output_spec_t;


/*
 * Holds the state of a multi-output configuration.
 * Created by setup, consumed by commit, cleaned up by teardown.
 */
typedef struct {
    igt_display_t *display;
    int fd;
    int n_specs;
    igt_output_spec_t *specs;
    uint32_t used_pipes;
    bool committed;
} igt_multi_output_ctx_t;
```

### The Three Functions

```c
/*
 * igt_multi_output_setup — Find outputs, allocate pipes, create FBs
 *
 * For each spec:
 *   1. Iterates connected outputs, finds first matching the predicate
 *   2. Calls find_mode() if provided, else uses default mode
 *   3. Sets the mode as override on the output
 *
 * Then for all specs together:
 *   4. Calls igt_allocate_pipes() for all matched outputs
 *   5. Creates a primary-plane FB matching each output's mode
 *   6. Does a TEST_ONLY atomic commit to validate bandwidth
 *   7. If bandwidth is tight, calls
 *      igt_override_all_active_output_modes_to_fit_bw() to downscale
 *
 * If any step fails: calls igt_require() → test is SKIPped with message.
 * No partial state is left behind.
 */
void igt_multi_output_setup(igt_display_t *display, int fd,
                            igt_output_spec_t *specs, int n_specs,
                            igt_multi_output_ctx_t *ctx);

/*
 * Non-asserting variant. Returns 0 on success, -1 on failure.
 * Useful when the test wants to handle the "not enough outputs" case
 * differently (e.g., try a different combination).
 */
int igt_multi_output_try_setup(igt_display_t *display, int fd,
                               igt_output_spec_t *specs, int n_specs,
                               igt_multi_output_ctx_t *ctx);

/*
 * igt_multi_output_commit — Atomic commit for all outputs
 *
 * Calls igt_display_commit2(display, COMMIT_ATOMIC).
 */
void igt_multi_output_commit(igt_multi_output_ctx_t *ctx);

/*
 * Non-asserting variant. Returns 0 on success, errno on failure.
 * Used for negative testing (intentionally invalid configurations).
 */
int igt_multi_output_try_commit(igt_multi_output_ctx_t *ctx);

/*
 * igt_multi_output_teardown — Remove FBs, reset display
 *
 * Safe to call multiple times. Safe to call on partially-setup ctx.
 */
void igt_multi_output_teardown(igt_multi_output_ctx_t *ctx);
```

### Implementation

> **Note:** Walk through `igt_multi_output_try_setup` step by step.
> The asserting variant (`igt_multi_output_setup`) is a thin wrapper that
> calls `igt_require()` on failure. The non-asserting variant is shown here
> because it contains the actual logic.

```c
int igt_multi_output_try_setup(igt_display_t *display, int fd,
                               igt_output_spec_t *specs, int n_specs,
                               igt_multi_output_ctx_t *ctx)
{
    igt_output_t *output;
    igt_output_t *matched_outputs[n_specs];
    int matched = 0;

    memset(ctx, 0, sizeof(*ctx));
    ctx->display = display;
    ctx->fd = fd;
    ctx->n_specs = n_specs;
    ctx->specs = specs;

    /*
     * Step 1: For each spec, find the first connected output that
     * matches its predicate and hasn't been claimed by an earlier spec.
     */
    for (int i = 0; i < n_specs; i++) {
        specs[i].output = NULL;

        for_each_connected_output(display, output) {
            /* Skip if already claimed by a previous spec */
            bool claimed = false;
            for (int j = 0; j < i; j++) {
                if (specs[j].output == output) {
                    claimed = true;
                    break;
                }
            }
            if (claimed)
                continue;

            /* Check predicate */
            if (!specs[i].predicate(fd, output))
                continue;

            specs[i].output = output;
            break;
        }

        if (!specs[i].output) {
            igt_info("multi_output_setup: could not find output "
                     "for spec %d\n", i);
            return -1;
        }

        matched_outputs[matched++] = specs[i].output;
    }

    /*
     * Step 2: For each spec, select a mode.
     * If find_mode is provided, call it. Otherwise use default.
     */
    for (int i = 0; i < n_specs; i++) {
        if (specs[i].find_mode) {
            if (!specs[i].find_mode(fd, specs[i].output,
                                    &specs[i].mode)) {
                igt_info("multi_output_setup: mode finder failed "
                         "for %s (spec %d)\n",
                         specs[i].output->name, i);
                return -1;
            }
            igt_output_override_mode(specs[i].output,
                                     &specs[i].mode);
        } else {
            drmModeModeInfo *m =
                igt_output_get_mode(specs[i].output);
            memcpy(&specs[i].mode, m, sizeof(*m));
        }
    }

    /*
     * Step 3: Allocate pipes for all matched outputs.
     * This handles joiner constraints automatically.
     */
    if (igt_allocate_pipes(display, matched_outputs,
                           matched, &ctx->used_pipes) < 0) {
        igt_info("multi_output_setup: pipe allocation failed\n");
        return -1;
    }

    /* Record assigned master pipe for each spec */
    for (int i = 0; i < n_specs; i++) {
        enum pipe p;
        for_each_pipe(display, p) {
            if (igt_output_get_crtc(specs[i].output) ==
                igt_crtc_for_pipe(display, p)) {
                specs[i].master_pipe = p;
                break;
            }
        }
    }

    /*
     * Step 4: Create FBs matching each output's mode dimensions.
     * Uses XRGB8888 and LINEAR as safe defaults.
     */
    for (int i = 0; i < n_specs; i++) {
        igt_output_setup_fb(fd, specs[i].output,
                            DRM_FORMAT_XRGB8888,
                            DRM_FORMAT_MOD_LINEAR,
                            &specs[i].fb);
    }

    /*
     * Step 5: Bandwidth validation.
     * Do a TEST_ONLY commit. If it fails with ENOSPC,
     * try lower modes to fit bandwidth.
     */
    if (!igt_fit_modes_in_bw(display)) {
        igt_info("multi_output_setup: bandwidth insufficient "
                 "even after mode downscaling\n");
        /* Clean up FBs on failure */
        for (int i = 0; i < n_specs; i++)
            igt_remove_fb(fd, &specs[i].fb);
        return -1;
    }

    return 0;
}

void igt_multi_output_setup(igt_display_t *display, int fd,
                            igt_output_spec_t *specs, int n_specs,
                            igt_multi_output_ctx_t *ctx)
{
    int ret = igt_multi_output_try_setup(display, fd,
                                         specs, n_specs, ctx);
    igt_require_f(ret == 0,
                  "Multi-output setup failed: not enough matching "
                  "outputs or pipes\n");
}

int igt_multi_output_try_commit(igt_multi_output_ctx_t *ctx)
{
    int ret = igt_display_try_commit2(ctx->display, COMMIT_ATOMIC);
    if (ret == 0)
        ctx->committed = true;
    return ret;
}

void igt_multi_output_commit(igt_multi_output_ctx_t *ctx)
{
    igt_display_commit2(ctx->display, COMMIT_ATOMIC);
    ctx->committed = true;
}

void igt_multi_output_teardown(igt_multi_output_ctx_t *ctx)
{
    if (!ctx->display)
        return;

    /* Remove all framebuffers */
    for (int i = 0; i < ctx->n_specs; i++) {
        if (ctx->specs[i].fb.fb_id) {
            igt_remove_fb(ctx->fd, &ctx->specs[i].fb);
            ctx->specs[i].fb.fb_id = 0;
        }
    }

    /*
     * Reset display state: clear output-to-CRTC assignments
     * and mode overrides for all outputs we touched.
     */
    for (int i = 0; i < ctx->n_specs; i++) {
        if (ctx->specs[i].output) {
            igt_output_set_crtc(ctx->specs[i].output, NULL);
            ctx->specs[i].output = NULL;
        }
    }

    ctx->used_pipes = 0;
    ctx->committed = false;
}
```

### Usage Example — Dual Output DSC + Normal

> **Note:** This is the key demo. Show how spec declaration +
> one setup call replaces what would otherwise be ~60 lines of manual work.

```c
igt_subtest("dual-output-dsc-joiner-and-normal") {
    /*
     * Step 1: Declare what we need.
     *
     * Spec 0: an output that supports DSC AND has a big joiner mode.
     * Spec 1: any connected output (for the second display).
     */
    igt_output_spec_t specs[] = {
        {
            .predicate = dsc_and_big_joiner,
            .find_mode = find_big_joiner_mode,
        },
        {
            .predicate = any_connected,
            /* NULL find_mode → uses the output's default mode */
        },
    };
    igt_multi_output_ctx_t ctx;

    /*
     * Step 2: Let the orchestrator do the work.
     *
     * After this call:
     *   ctx.specs[0].output     = matched DSC+joiner output (e.g., DP-1)
     *   ctx.specs[0].mode       = a big-joiner-triggering mode
     *   ctx.specs[0].master_pipe = PIPE_A (allocated, 2 pipes consumed)
     *   ctx.specs[0].fb         = FB matching mode dimensions
     *   ctx.specs[1].output     = second output (e.g., HDMI-1)
     *   ctx.specs[1].master_pipe = PIPE_C (non-conflicting)
     *   ctx.specs[1].fb         = FB matching its mode
     *   Bandwidth already validated via TEST_ONLY commit.
     *
     * If fewer than 2 matching outputs exist, or if pipe allocation
     * fails, the test is SKIPped with a descriptive message.
     */
    igt_multi_output_setup(&display, fd, specs, 2, &ctx);

    /* Step 3: Feature-specific setup (using existing APIs) */
    IGT_DEBUGFS_GUARD_DSC(fd, ctx.specs[0].output);
    force_dsc_enable(fd, ctx.specs[0].output);

    /* Step 4: Commit both outputs atomically */
    igt_multi_output_commit(&ctx);

    /* Step 5: Validate */
    igt_assert(igt_is_dsc_enabled(fd, ctx.specs[0].output->name));

    /* Step 6: Cleanup — removes FBs, resets display state */
    igt_multi_output_teardown(&ctx);
}
```

### Writing predicates and mode finders

> **Note:** These are typically 3-5 line functions defined at the
> top of the test file. They compose Layer 1 predicates.

```c
/* Predicate: output supports DSC and has big joiner modes */
static bool dsc_and_big_joiner(int fd, igt_output_t *output)
{
    return igt_output_supports_dsc(fd, output) &&
           igt_output_get_max_joiner(fd, output) >= JOINED_PIPES_BIG_JOINER;
}

/* Predicate: any connected output */
static bool any_connected(int fd, igt_output_t *output)
{
    return igt_output_is_connected(output);
}

/* Mode finder: find a mode that triggers big joiner */
static bool find_big_joiner_mode(int fd, igt_output_t *output,
                                  drmModeModeInfo *mode)
{
    return igt_find_joiner_mode(fd, output,
                                JOINED_PIPES_BIG_JOINER, mode);
}
```

---

## Layer 4 — Bandwidth-Safe Commit

### What this is

A commit wrapper that uses `DRM_MODE_ATOMIC_TEST_ONLY` to validate bandwidth
before doing the real commit. If bandwidth is tight, it automatically
downscales modes via `igt_override_all_active_output_modes_to_fit_bw()`.

`igt_fit_modes_in_bw()` already exists in `lib/igt_kms.c` and does exactly
this TEST_ONLY + fallback logic. The new function wraps it together with
the actual commit into a single call.

### API

```c
/*
 * igt_bw_safe_commit — Commit with automatic bandwidth fallback
 *
 * 1. Runs igt_fit_modes_in_bw() which does:
 *    a. TEST_ONLY atomic commit to see if current modes fit
 *    b. If not: downgrades modes and retries
 * 2. If modes fit: does the real igt_display_commit2() atomic commit
 * 3. Returns true on success, false if bandwidth is insufficient
 *    even after downgrading
 */
bool igt_bw_safe_commit(igt_display_t *display);

/*
 * igt_try_bw_commit — TEST_ONLY check without committing
 *
 * Returns 0 if the configuration would fit, errno otherwise.
 * Does NOT modify display state. Used for probing.
 */
int igt_try_bw_commit(igt_display_t *display);
```

### Implementation

```c
bool igt_bw_safe_commit(igt_display_t *display)
{
    /*
     * igt_fit_modes_in_bw() already exists and does:
     *   1. TEST_ONLY atomic commit
     *   2. If ENOSPC: calls igt_override_all_active_output_modes_to_fit_bw()
     *   3. Returns true if modes now fit, false if unsolvable
     */
    if (!igt_fit_modes_in_bw(display))
        return false;

    igt_display_commit2(display, COMMIT_ATOMIC);
    return true;
}

int igt_try_bw_commit(igt_display_t *display)
{
    /*
     * TEST_ONLY atomic commit — probes whether the current
     * configuration fits within bandwidth limits without
     * modifying display state.
     *
     * Returns 0 if it would succeed, or errno (typically ENOSPC)
     * if bandwidth is insufficient.
     */
    return igt_display_try_commit2(display, COMMIT_ATOMIC);
}
```

---

## Layer 5 — Debugfs State Guard

### What this is

An RAII-style mechanism that saves a debugfs attribute's value and
automatically restores it when the scope exits — even if the test fails
or is skipped (both of which trigger `longjmp` in IGT).

This uses GCC's `__attribute__((cleanup()))`, the same mechanism used in
the Linux kernel for scoped resource management (`guard(mutex)` etc.).

### API

```c
/*
 * The guard struct holds the saved state.
 */
typedef struct {
    int restore_fd;            /* fd to the debugfs file */
    char original_value[64];   /* saved content */
    int original_len;          /* length of saved content */
    bool active;               /* guard is holding state */
} igt_debugfs_guard_t;

/* Generic: save/restore any debugfs attribute */
void igt_debugfs_guard_begin(int fd, igt_output_t *output,
                             const char *debugfs_attr,
                             igt_debugfs_guard_t *guard);
void igt_debugfs_guard_end(igt_debugfs_guard_t *guard);

/* Feature-specific: save/restore DSC force-enable state */
void igt_dsc_guard_begin(int fd, igt_output_t *output,
                         igt_debugfs_guard_t *guard);
void igt_dsc_guard_end(igt_debugfs_guard_t *guard);

/* Feature-specific: save/restore force joiner state */
void igt_joiner_guard_begin(int fd, igt_output_t *output,
                            igt_debugfs_guard_t *guard);
void igt_joiner_guard_end(igt_debugfs_guard_t *guard);
```

### Scope-based macros

> **Note:** These macros are the main way test authors will use
> guards. The GCC cleanup attribute calls the end function automatically
> when the variable goes out of scope.

```c
/*
 * IGT_DEBUGFS_GUARD_DSC — saves DSC force-enable state, restores on scope exit
 *
 * Usage:
 *   {
 *       IGT_DEBUGFS_GUARD_DSC(fd, output);
 *       force_dsc_enable(fd, output);
 *       // ... test code ...
 *   }  // ← DSC state automatically restored here
 *
 * The restore happens even if the test hits igt_assert() failure
 * or igt_require() skip, because __attribute__((cleanup)) fires
 * on longjmp scope exit.
 */
#define IGT_DEBUGFS_GUARD_DSC(fd, output) \
    igt_debugfs_guard_t __dsc_guard__ \
        __attribute__((cleanup(igt_dsc_guard_end))); \
    igt_dsc_guard_begin(fd, output, &__dsc_guard__)

#define IGT_DEBUGFS_GUARD_JOINER(fd, output) \
    igt_debugfs_guard_t __joiner_guard__ \
        __attribute__((cleanup(igt_joiner_guard_end))); \
    igt_joiner_guard_begin(fd, output, &__joiner_guard__)
```

### Implementation

```c
void igt_debugfs_guard_begin(int fd, igt_output_t *output,
                             const char *debugfs_attr,
                             igt_debugfs_guard_t *guard)
{
    /*
     * Open the debugfs file and read its current value.
     * Store both the fd and the value so we can write it back.
     */
    guard->restore_fd = igt_debugfs_connector_dir(fd, output->name, O_RDWR);
    igt_assert(guard->restore_fd >= 0);

    guard->original_len = igt_debugfs_read(guard->restore_fd,
                                            debugfs_attr,
                                            guard->original_value,
                                            sizeof(guard->original_value));
    guard->active = true;

    /*
     * Also register an exit handler so that if the process is
     * killed (SIGKILL, etc.), we still attempt restoration.
     */
    igt_install_exit_handler(_guard_exit_handler);
}

void igt_debugfs_guard_end(igt_debugfs_guard_t *guard)
{
    if (!guard->active)
        return;

    /* Write back the original value */
    igt_debugfs_write(guard->restore_fd, guard->original_value,
                      guard->original_len);
    close(guard->restore_fd);
    guard->active = false;
}
```

### Implementation — Feature-Specific Guards

> **Note:** These are thin wrappers around the generic guard.
> Each one knows which debugfs attribute to save/restore for its feature.
> The `_end` functions are identical to the generic `igt_debugfs_guard_end`
> — they just call the same restore logic.

```c
/*
 * DSC guard: saves/restores the "i915_dsc_fec_support" debugfs attr.
 * This is the attribute that force_dsc_enable() writes "1" to.
 */
void igt_dsc_guard_begin(int fd, igt_output_t *output,
                        igt_debugfs_guard_t *guard)
{
    igt_debugfs_guard_begin(fd, output, "i915_dsc_fec_support",
                           guard);
}

void igt_dsc_guard_end(igt_debugfs_guard_t *guard)
{
    igt_debugfs_guard_end(guard);
}

/*
 * Joiner guard: saves/restores the "i915_bigjoiner_force_enable"
 * debugfs attr. This is the attribute used by force-joiner tests.
 */
void igt_joiner_guard_begin(int fd, igt_output_t *output,
                           igt_debugfs_guard_t *guard)
{
    igt_debugfs_guard_begin(fd, output,
                           "i915_bigjoiner_force_enable",
                           guard);
}

void igt_joiner_guard_end(igt_debugfs_guard_t *guard)
{
    igt_debugfs_guard_end(guard);
}
```

---

## Layer 6 — Output Classifier

### What this is

A utility function that partitions connected outputs into "match" and
"no match" arrays based on a predicate. This is a common pattern when a test
needs to organize outputs by capability (e.g., joiner-capable vs non-joiner).

### API

```c
/*
 * Partition connected outputs by predicate.
 *
 * Iterates all connected outputs and places each into either
 * the match[] or no_match[] array depending on the predicate result.
 *
 * Pass NULL for no_match/no_match_count if you only need the matches.
 */
void igt_classify_outputs(igt_display_t *display, int fd,
                          bool (*predicate)(int fd, igt_output_t *),
                          igt_output_t **match, int *match_count,
                          igt_output_t **no_match, int *no_match_count);

/* Find first connected output matching predicate. Returns NULL if none. */
igt_output_t *igt_find_output_with(igt_display_t *display, int fd,
                                   bool (*pred)(int fd, igt_output_t *));

/* Count connected outputs matching predicate. */
int igt_count_outputs_with(igt_display_t *display, int fd,
                           bool (*pred)(int fd, igt_output_t *));
```

### Implementation

```c
void igt_classify_outputs(igt_display_t *display, int fd,
                          bool (*predicate)(int fd, igt_output_t *),
                          igt_output_t **match, int *match_count,
                          igt_output_t **no_match, int *no_match_count)
{
    igt_output_t *output;
    int m = 0, n = 0;

    for_each_connected_output(display, output) {
        if (predicate(fd, output)) {
            if (match)
                match[m] = output;
            m++;
        } else {
            if (no_match)
                no_match[n] = output;
            n++;
        }
    }

    if (match_count)
        *match_count = m;
    if (no_match_count)
        *no_match_count = n;
}

igt_output_t *igt_find_output_with(igt_display_t *display, int fd,
                                   bool (*pred)(int fd, igt_output_t *))
{
    igt_output_t *output;

    for_each_connected_output(display, output)
        if (pred(fd, output))
            return output;

    return NULL;
}

int igt_count_outputs_with(igt_display_t *display, int fd,
                           bool (*pred)(int fd, igt_output_t *))
{
    igt_output_t *output;
    int count = 0;

    for_each_connected_output(display, output)
        if (pred(fd, output))
            count++;

    return count;
}
```

### Example — classifying outputs for joiner testing

```c
/* Before: manual classification, test-specific */
igt_output_t *bj_outputs[IGT_MAX_PIPES];
int bj_count;
igt_output_t *non_bj_outputs[IGT_MAX_PIPES];
int non_bj_count;

igt_classify_outputs(&display, fd, is_big_joiner_capable,
                     bj_outputs, &bj_count,
                     non_bj_outputs, &non_bj_count);

igt_require_f(bj_count >= 1,
              "No big-joiner-capable outputs found\n");
```

---

## Layer 7 — Composition Macros

### What this is

Three new `for_each_*` macros added to `lib/igt_kms.h`. These extend the
existing family of 11 iteration macros. All three build on the existing
`for_each_if()` mechanism — no new macro magic.

### Macro 1: `for_each_connected_output_where`

> **Note:** This is the simplest new macro — a one-liner that
> filters the existing `for_each_connected_output` with an arbitrary
> predicate expression.

```c
/*
 * Iterate connected outputs that match an arbitrary condition.
 *
 * The condition can be any C expression involving 'output' (and
 * any variables in scope). Composes Layer 1 predicates naturally.
 */
#define for_each_connected_output_where(display, output, pred) \
    for_each_connected_output(display, output) \
        for_each_if(pred)
```

Usage:

```c
/* Find all outputs that support both DSC and HDR */
for_each_connected_output_where(&display, output,
        igt_output_supports_dsc(fd, output) &&
        igt_output_supports_hdr(fd, output)) {

    igt_dynamic_f("%s", output->name) {
        /* test code for this DSC+HDR output */
    }
}
```

### Macro 2: `for_each_pipe_output_combo`

> **Note:** This is the joiner-aware replacement for
> `for_each_crtc_with_valid_output`. It checks that the pipe has enough
> consecutive free pipes for the output's current mode requirement.

```c
/*
 * Iterate valid CRTC/output combinations, skipping pipes that
 * don't have enough room for joiner.
 *
 * _pipe_has_room_for_output() checks:
 *   - Output's required_pipes (1/2/4 based on mode)
 *   - Whether that many consecutive pipes are available starting
 *     at the given CRTC's pipe
 *   - Whether the pipe is a valid master pipe (for joiner)
 */
#define for_each_pipe_output_combo(display, crtc, output) \
    for_each_crtc_with_valid_output(display, crtc, output) \
        for_each_if(_pipe_has_room_for_output(display, crtc, output))
```

### Macro 3: `for_each_output_combo`

> **Note:** This is the most powerful macro — it finds all valid
> N-output combinations using a backtracking search. Each output must match
> its corresponding predicate, and pipes must not conflict.

```c
/*
 * Iterate all valid N-output combinations.
 *
 * Uses depth-first search with backtracking:
 *   For slot 0: try each connected output matching preds[0]
 *     For slot 1: try each remaining output matching preds[1]
 *       ...allocate pipes for all slots...
 *       if valid: execute body
 *       else: backtrack
 */
#define for_each_output_combo(display, outputs, n, preds) \
    for (int __combo_ok__ = \
             _first_output_combo(display, outputs, n, preds); \
         __combo_ok__; \
         __combo_ok__ = \
             _next_output_combo(display, outputs, n, preds))
```

Usage:

```c
bool (*preds[])(int, igt_output_t *) = {
    dsc_capable,       /* output 0 must support DSC */
    any_connected,     /* output 1 can be anything */
};
igt_output_t *outs[2];

for_each_output_combo(&display, outs, 2, preds) {
    /*
     * outs[0] supports DSC, outs[1] is any other connected output.
     * Pipes are pre-allocated and non-conflicting.
     */
    igt_dynamic_f("%s-%s", outs[0]->name, outs[1]->name) {
        /* test code */
    }
}
```

### Implementation — `_pipe_has_room_for_output()`

> **Note:** This is the helper used by `for_each_pipe_output_combo`.
> It checks whether a given CRTC's pipe has enough consecutive free pipes
> for the output's joiner requirement.

```c
static inline bool _pipe_has_room_for_output(igt_display_t *display,
                                             igt_crtc_t *crtc,
                                             igt_output_t *output)
{
    enum pipe p = crtc->pipe;
    int need = output->required_pipes;

    /* Non-joiner: any valid pipe works */
    if (need <= 1)
        return true;

    /* Joiner: starting pipe must be a valid master */
    if (!(display->master_pipe_mask & BIT(p)))
        return false;

    /*
     * Check that all 'need' consecutive pipes exist.
     * We check against valid_pipe_mask (not used_pipe_mask)
     * because the macro iterates all topologically valid combos —
     * actual availability is checked at commit time.
     */
    for (int k = 0; k < need; k++) {
        if (!(display->valid_pipe_mask & BIT(p + k)))
            return false;
    }

    return true;
}
```

### Implementation — Combo Iteration State

> **Note:** `_first_output_combo` and `_next_output_combo` drive
> the `for_each_output_combo` macro. They maintain a static iteration state
> that the backtracking search uses to yield one valid combination at a time.

```c
/*
 * Internal state for combo iteration.
 * Stored alongside the outputs[] array (the macro's variable).
 */
typedef struct {
    igt_display_t *display;
    bool (**preds)(int, igt_output_t *);
    int n;
    int cursor[IGT_MAX_PIPES];  /* per-slot: index into connected list */
    bool exhausted;
} _combo_iter_t;

static _combo_iter_t __combo_state__;

static int _first_output_combo(igt_display_t *display,
                               igt_output_t **outputs, int n,
                               bool (**preds)(int, igt_output_t *))
{
    memset(&__combo_state__, 0, sizeof(__combo_state__));
    __combo_state__.display = display;
    __combo_state__.preds = preds;
    __combo_state__.n = n;

    /* Find the first valid combination using DFS */
    return _find_next_combo(display, outputs, n, preds, 0, 0);
}

static int _next_output_combo(igt_display_t *display,
                              igt_output_t **outputs, int n,
                              bool (**preds)(int, igt_output_t *))
{
    /*
     * To find the NEXT combo: invalidate the last slot and
     * resume backtracking from there. The _find_next_combo
     * function's recursive structure handles this naturally
     * when we clear the last assigned output and retry.
     */
    if (__combo_state__.exhausted)
        return 0;

    /* Clear last slot and let backtracking find next */
    outputs[n - 1] = NULL;
    return _find_next_combo(display, outputs, n, preds, 0, 0);
}
```

### Implementation — Backtracking Search

```c
static int _find_next_combo(igt_display_t *display,
                            igt_output_t **outputs, int n,
                            bool (**preds)(int, igt_output_t *),
                            int slot, uint32_t used_pipes)
{
    if (slot == n) {
        /* All slots filled — try pipe allocation */
        return igt_allocate_pipes(display, outputs, n,
                                  &used_pipes) == 0;
    }

    int fd = display->drm_fd;
    igt_output_t *output;

    for_each_connected_output(display, output) {
        /* Skip if this output is already assigned to another slot */
        for (int j = 0; j < slot; j++)
            if (outputs[j] == output)
                goto next;

        /* Skip if it doesn't match this slot's predicate */
        if (!preds[slot](fd, output))
            continue;

        outputs[slot] = output;
        if (_find_next_combo(display, outputs, n, preds,
                              slot + 1, used_pipes))
            return 1;
    next:
        continue;
    }

    outputs[slot] = NULL;
    return 0;
}
```

---

## Layer 8 — Convenience Helpers

### `igt_output_setup_fb()` — Create FB and set on primary plane

> **Note:** Every test does the same 5-line sequence: get mode,
> create fb, get primary plane, set fb on plane. This helper does it in 1 call.

```c
/*
 * Create a framebuffer matching the output's current mode and set it
 * on the primary plane.
 *
 * Returns: pointer to the primary plane (with FB already set on it).
 */
igt_plane_t *igt_output_setup_fb(int fd, igt_output_t *output,
                                 uint32_t format, uint64_t modifier,
                                 igt_fb_t *fb)
{
    drmModeModeInfo *mode = igt_output_get_mode(output);

    igt_create_fb(fd, mode->hdisplay, mode->vdisplay,
                  format, modifier, fb);

    igt_plane_t *primary = igt_output_get_plane_type(
        output, DRM_PLANE_TYPE_PRIMARY);
    igt_plane_set_fb(primary, fb);

    return primary;
}
```

### Feature-require macros

> **Note:** These wrap `igt_require_f` with a descriptive message.
> When a subtest is skipped, the log shows exactly which feature was missing
> on which output.

```c
#define igt_output_require_dsc(fd, output) \
    igt_require_f(igt_output_supports_dsc(fd, output), \
                  "DSC not supported on %s\n", (output)->name)

#define igt_output_require_hdr(fd, output) \
    igt_require_f(igt_output_supports_hdr(fd, output), \
                  "HDR not supported on %s\n", (output)->name)

#define igt_output_require_vrr(fd, output) \
    igt_require_f(igt_output_supports_vrr(fd, output), \
                  "VRR not supported on %s\n", (output)->name)

#define igt_output_require_psr(fd, output, mode) \
    igt_require_f(igt_output_supports_psr(fd, output, mode), \
                  "PSR mode %d not supported on %s\n", \
                  (mode), (output)->name)
```

### Mode finder functions

> **Note:** These find modes suitable for specific features.
> `igt_find_joiner_mode()` replaces `bigjoiner_mode_found()` /
> `ultrajoiner_mode_found()` with a single parameterized function.

```c
/*
 * Find a mode that triggers joiner at the given level.
 * Scans the output's mode list for a mode whose horizontal
 * resolution exceeds the max_dotclock / joiner_level threshold.
 */
bool igt_find_joiner_mode(int fd, igt_output_t *output,
                          enum joined_pipes level,
                          drmModeModeInfo *mode);

/*
 * Find a mode that does NOT trigger joiner.
 * Returns the highest-resolution mode within single-pipe limits.
 */
bool igt_find_non_joiner_mode(int fd, igt_output_t *output,
                              drmModeModeInfo *mode);

/*
 * Find a mode with ≥10bpc support, suitable for HDR testing.
 */
bool igt_find_hdr_mode(int fd, igt_output_t *output,
                       drmModeModeInfo *mode);

/*
 * Find a mode whose refresh rate is within the VRR range.
 */
bool igt_find_vrr_mode(int fd, igt_output_t *output,
                       drmModeModeInfo *mode);
```

### Implementation — Mode Finders

> **Note:** These scan the output's mode list applying
> feature-specific criteria. `igt_find_joiner_mode` is a parameterized
> replacement for the separate `bigjoiner_mode_found()` and
> `ultrajoiner_mode_found()` functions in `kms_joiner_helper.c`.

```c
bool igt_find_joiner_mode(int fd, igt_output_t *output,
                          enum joined_pipes level,
                          drmModeModeInfo *mode)
{
    drmModeConnector *conn = output->config.connector;
    int max_dotclock = igt_get_max_dotclock(fd);
    int threshold;

    if (max_dotclock <= 0)
        return false;

    /*
     * Threshold depends on joiner level:
     *   BIG_JOINER:   mode must exceed 1x max_dotclock
     *   ULTRA_JOINER: mode must exceed 2x max_dotclock
     *
     * We scan all modes and pick the first one above threshold.
     * Modes are typically sorted by resolution (descending),
     * so we get the highest resolution joiner mode first.
     */
    switch (level) {
    case JOINED_PIPES_BIG_JOINER:
        threshold = max_dotclock;
        break;
    case JOINED_PIPES_ULTRA_JOINER:
        threshold = 2 * max_dotclock;
        break;
    default:
        return false;
    }

    for (int i = 0; i < conn->count_modes; i++) {
        if (conn->modes[i].clock > threshold) {
            memcpy(mode, &conn->modes[i], sizeof(*mode));
            return true;
        }
    }

    igt_info("No joiner mode (level %d) found for %s "
             "(max_dotclock=%d)\n", level, output->name,
             max_dotclock);
    return false;
}

bool igt_find_non_joiner_mode(int fd, igt_output_t *output,
                              drmModeModeInfo *mode)
{
    drmModeConnector *conn = output->config.connector;
    int max_dotclock = igt_get_max_dotclock(fd);
    drmModeModeInfo *best = NULL;

    if (max_dotclock <= 0)
        return false;

    /*
     * Find the highest-resolution mode that fits within
     * single-pipe bandwidth. "Highest" here means largest
     * hdisplay × vdisplay product.
     */
    for (int i = 0; i < conn->count_modes; i++) {
        if (conn->modes[i].clock > max_dotclock)
            continue;

        if (!best ||
            (conn->modes[i].hdisplay * conn->modes[i].vdisplay >
             best->hdisplay * best->vdisplay))
            best = &conn->modes[i];
    }

    if (best) {
        memcpy(mode, best, sizeof(*mode));
        return true;
    }

    return false;
}

bool igt_find_hdr_mode(int fd, igt_output_t *output,
                       drmModeModeInfo *mode)
{
    drmModeConnector *conn = output->config.connector;

    /*
     * HDR requires at least 10bpc. We look for modes where the
     * connector's max_bpc property allows ≥10. The mode itself
     * doesn't encode BPC — that comes from the connector property.
     *
     * So we return the preferred (default) mode if the output
     * supports HDR. The caller sets MAX_BPC to 10 separately.
     */
    if (!igt_output_supports_hdr(fd, output))
        return false;

    /* Use the preferred mode — HDR applies to any resolution */
    for (int i = 0; i < conn->count_modes; i++) {
        if (conn->modes[i].type & DRM_MODE_TYPE_PREFERRED) {
            memcpy(mode, &conn->modes[i], sizeof(*mode));
            return true;
        }
    }

    /* No preferred mode marked — fall back to first mode */
    if (conn->count_modes > 0) {
        memcpy(mode, &conn->modes[0], sizeof(*mode));
        return true;
    }

    return false;
}

bool igt_find_vrr_mode(int fd, igt_output_t *output,
                       drmModeModeInfo *mode)
{
    drmModeConnector *conn = output->config.connector;
    int min_hz, max_hz;

    /* Get the panel's VRR range from debugfs */
    if (!igt_output_get_vrr_range(fd, output, &min_hz, &max_hz))
        return false;

    /*
     * Find a mode whose refresh rate falls within the VRR range.
     * The panel will accept variable refresh between min_hz and
     * max_hz — we need a mode at or below max_hz.
     */
    for (int i = 0; i < conn->count_modes; i++) {
        int vrefresh = conn->modes[i].vrefresh;

        if (vrefresh >= min_hz && vrefresh <= max_hz) {
            memcpy(mode, &conn->modes[i], sizeof(*mode));
            return true;
        }
    }

    igt_info("No mode within VRR range [%d-%d Hz] for %s\n",
             min_hz, max_hz, output->name);
    return false;
}
```

---

## Struct Extensions

### `igt_output_t`

One new field: `required_pipes`.

```c
typedef struct {
    /* ... existing fields unchanged ... */

    /*
     * NEW: How many pipes does this output need for its current mode?
     *
     * 1 = normal single-pipe mode
     * 2 = big joiner (mode exceeds single-pipe bandwidth)
     * 4 = ultra joiner
     *
     * Initialized to 1. Updated by igt_output_override_mode() and
     * igt_output_get_required_pipes(). Avoids repeated mode scanning.
     */
    int required_pipes;
} igt_output_t;
```

### `igt_display_t`

Two new fields: cached pipe masks.

```c
struct igt_display {
    /* ... existing fields unchanged ... */

    /*
     * NEW: Computed once during igt_display_require() and cached.
     *
     * valid_pipe_mask:  bit P set if pipe P exists and is not fused off
     * master_pipe_mask: bit P set if pipe P can be a joiner master
     *                   (both pipe P and pipe P+1 are valid)
     */
    uint32_t valid_pipe_mask;
    uint32_t master_pipe_mask;
};
```

Both structs are allocated via `calloc`, so new fields auto-initialize to 0.
There are no ABI constraints — this is userspace-only, not a kernel UAPI.

---

## Complete Example — DSC + Big Joiner Test

> **Note:** Walk through this end-to-end. Show how
> the layers compose: Layer 1 (predicate) → Layer 8 (mode finder) →
> Layer 2 (pipe allocator) → Layer 5 (debugfs guard) → Layer 8 (FB setup)
> → Layer 4 (BW-safe commit).

```c
#include "igt.h"
#include "igt_kms_feature.h"

IGT_TEST_DESCRIPTION("Verify DSC with big joiner modeset");

typedef struct {
    int drm_fd;
    igt_display_t display;
} data_t;

igt_main
{
    data_t data = {};

    igt_fixture {
        data.drm_fd = drm_open_driver_master(DRIVER_INTEL | DRIVER_XE);
        igt_display_require(&data.display, data.drm_fd);

        /* Source-level early skip — no point scanning outputs */
        igt_require(igt_source_supports_dsc(data.drm_fd));
        igt_require(igt_source_supports_joiner(data.drm_fd));
    }

    igt_subtest_with_dynamic("dsc-with-big-joiner") {
        igt_output_t *output;

        /*
         * Iterate all outputs that pass BOTH predicates:
         *   - DSC supported (source + sink + FEC if external)
         *   - Big joiner mode available (mode exceeds single-pipe BW)
         */
        for_each_connected_output_where(&data.display, output,
                igt_output_supports_dsc(data.drm_fd, output) &&
                igt_output_get_max_joiner(data.drm_fd, output)
                    >= JOINED_PIPES_BIG_JOINER) {

            igt_dynamic_f("%s", output->name) {
                igt_fb_t fb;
                drmModeModeInfo mode;

                /* Find a mode that triggers big joiner */
                igt_require(igt_find_joiner_mode(data.drm_fd, output,
                            JOINED_PIPES_BIG_JOINER, &mode));
                igt_output_override_mode(output, &mode);

                /* Allocate 2 consecutive pipes for this output */
                igt_require(igt_allocate_pipes(&data.display,
                            &output, 1, NULL) == 0);

                /*
                 * Save DSC debugfs state — auto-restored when this
                 * scope exits, even on test failure/skip.
                 */
                IGT_DEBUGFS_GUARD_DSC(data.drm_fd, output);
                force_dsc_enable(data.drm_fd, output);

                /* Create FB, set on primary plane (1 call) */
                igt_output_setup_fb(data.drm_fd, output,
                    DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb);

                /* BW-safe commit: TEST_ONLY first, then real commit */
                igt_assert(igt_bw_safe_commit(&data.display));

                /* Verify DSC is actually active */
                igt_assert(igt_is_dsc_enabled(data.drm_fd,
                           output->name));

                igt_remove_fb(data.drm_fd, &fb);
            }
            /* Guard restores DSC state automatically here */
        }
    }

    igt_fixture {
        igt_display_fini(&data.display);
        drm_close_driver(data.drm_fd);
    }
}
```

---

## Complete Example — HDR + DSC + Big Joiner (Triple Feature)

> **Note:** This shows how predicates compose for multi-feature
> detection. The actual test setup is the same pattern — just a richer
> predicate.

```c
/*
 * Predicate: output supports all three features simultaneously.
 * Composes Layer 1 predicates with plain C &&.
 */
static bool hdr_dsc_big_joiner(int fd, igt_output_t *output)
{
    return igt_output_supports_hdr(fd, output) &&
           igt_output_supports_dsc(fd, output) &&
           igt_output_get_max_joiner(fd, output)
               >= JOINED_PIPES_BIG_JOINER;
}

igt_subtest_with_dynamic("hdr-dsc-big-joiner") {
    igt_output_t *output;

    for_each_connected_output_where(&data.display, output,
            hdr_dsc_big_joiner(data.drm_fd, output)) {

        igt_dynamic_f("%s", output->name) {
            igt_fb_t fb;
            drmModeModeInfo mode;

            igt_require(igt_find_joiner_mode(data.drm_fd, output,
                        JOINED_PIPES_BIG_JOINER, &mode));
            igt_output_override_mode(output, &mode);
            igt_require(igt_allocate_pipes(&data.display,
                        &output, 1, NULL) == 0);

            /* DSC setup with auto-restore guard */
            IGT_DEBUGFS_GUARD_DSC(data.drm_fd, output);
            force_dsc_enable(data.drm_fd, output);

            /* HDR setup — using existing property API directly */
            igt_output_set_prop_value(output,
                IGT_CONNECTOR_HDR_OUTPUT_METADATA, hdr_blob);
            igt_output_set_prop_value(output,
                IGT_CONNECTOR_MAX_BPC, 10);

            /* 10bpc HDR framebuffer */
            igt_output_setup_fb(data.drm_fd, output,
                DRM_FORMAT_XRGB2101010, DRM_FORMAT_MOD_LINEAR, &fb);

            igt_assert(igt_bw_safe_commit(&data.display));
            igt_assert(igt_is_dsc_enabled(data.drm_fd,
                       output->name));

            igt_remove_fb(data.drm_fd, &fb);
        }
    }
}
```

---

## Complete Example — Dual Output with Orchestrator

> **Note:** This shows the orchestrator handling the full lifecycle.
> Compare the spec declaration (5 lines) with the multi-step manual process
> it replaces: scanning, filtering, pipe management, FB creation, BW check.

```c
igt_subtest("dual-output-dsc-plus-normal") {
    igt_output_spec_t specs[] = {
        {
            .predicate  = dsc_and_big_joiner,
            .find_mode  = find_big_joiner_mode,
        },
        {
            .predicate  = any_connected,
            /* NULL find_mode = use default mode */
        },
    };
    igt_multi_output_ctx_t ctx;

    /*
     * This single call:
     *   1. Finds a DSC+joiner output and a second connected output
     *   2. Selects a big-joiner mode for output 0, default for output 1
     *   3. Allocates non-conflicting pipes (joiner-aware)
     *   4. Creates FBs matching each mode
     *   5. Validates bandwidth via TEST_ONLY commit
     *   6. If hardware doesn't have the outputs → SKIPs with message
     */
    igt_multi_output_setup(&data.display, data.drm_fd, specs, 2, &ctx);

    /* Feature-specific setup (existing APIs) */
    IGT_DEBUGFS_GUARD_DSC(data.drm_fd, ctx.specs[0].output);
    force_dsc_enable(data.drm_fd, ctx.specs[0].output);

    /* Atomic commit — both outputs go live simultaneously */
    igt_multi_output_commit(&ctx);

    /* Validate DSC is active on the first output */
    igt_assert(igt_is_dsc_enabled(data.drm_fd,
               ctx.specs[0].output->name));

    /* Full cleanup: FBs, display state, mode overrides */
    igt_multi_output_teardown(&ctx);
}
```

---

## What New Tests Become Possible

With the infrastructure above, the following test combinations become
straightforward to write:

| Test | Outputs | Features | Key API Used |
|------|---------|----------|-------------|
| DSC + Big Joiner | 1 | DSC, Joiner | `for_each_connected_output_where` + `igt_allocate_pipes` |
| HDR + DSC + Joiner | 1 | HDR, DSC, Joiner | Composed predicates |
| Dual-output DSC Joiner + Normal | 2 | DSC, Joiner | `igt_multi_output_setup()` |
| Dual-output VRR + AsyncFlip | 2 | VRR | `for_each_output_combo()` |
| PSR + FBC Dual-Pipe | 2 | PSR, FBC | `igt_multi_output_setup()` |
| Ultra Joiner + DSC | 1 | DSC, Ultra Joiner | `igt_find_joiner_mode(ULTRA_JOINER)` |
| DSC BPC sweep + Joiner | 1 | DSC (parameterized), Joiner | Predicate + existing BPC API |

---

## Implementation Roadmap

Each patch series is independently buildable and landable. The series are
ordered so that foundational layers land first.

### Series 1: Pipe Allocator Foundation (6 patches)

| # | Patch | What it does |
|---|-------|-------------|
| P01 | `lib/igt_kms: add igt_get_valid_pipe_mask()` | New function computing bitmask of non-fused pipes |
| P02 | `lib/igt_kms: add igt_get_master_pipe_mask()` | New function computing valid joiner master pipes |
| P03 | `lib/igt_kms: cache pipe masks in igt_display_t` | Compute at init time, add fields to struct |
| P04 | `lib/igt_kms: promote find_consecutive_pipes()` | Move from kms_joiner_helper.c to lib, make public |
| P05 | `lib/igt_kms: promote igt_output_get_required_pipes()` | Move from kms_joiner_helper.c to lib, make public |
| P06 | `lib/igt_kms: add igt_allocate_pipes()` | New allocator with priority sorting |

### Series 2: Feature Predicates (8 patches)

| # | Patch | What it does |
|---|-------|-------------|
| P07 | `lib: add igt_kms_feature.h/c skeleton` | New files with build integration |
| P08 | `lib/igt_kms_feature: add igt_output_supports_dsc()` | Full DSC prerequisite chain |
| P09 | `lib/igt_kms_feature: promote igt_is_hdr_panel()` | Move from tests/kms_hdr.c to lib |
| P10 | `lib/igt_kms_feature: add igt_output_supports_hdr()` | HDR predicate using promoted function |
| P11 | `lib/igt_kms_feature: promote igt_output_get_vrr_range()` | Move from tests/kms_vrr.c to lib |
| P12 | `lib/igt_kms_feature: add igt_output_supports_vrr()` | VRR predicate using promoted function |
| P13 | `lib/igt_kms_feature: add igt_output_supports_psr()` | PSR predicate with mode parameter |
| P14 | `lib/igt_kms_feature: add remaining predicates` | FBC, DRRS, content protection, force joiner |

### Series 3: Composition & Convenience (5 patches)

| # | Patch | What it does |
|---|-------|-------------|
| P15 | `lib/igt_kms: add for_each_connected_output_where()` | Predicate-filtered iteration macro |
| P16 | `lib/igt_kms: add igt_classify_outputs()` | Output classifier + find + count |
| P17 | `lib/igt_kms: add igt_output_setup_fb()` | FB + primary plane one-liner |
| P18 | `lib/igt_kms_feature: add mode finders` | joiner/hdr/vrr mode finders |
| P19 | `lib/igt_kms_feature: add require macros` | igt_output_require_dsc/hdr/vrr/psr |

### Series 4: Safety Infrastructure (3 patches)

| # | Patch | What it does |
|---|-------|-------------|
| P20 | `lib/igt_kms: add igt_bw_safe_commit()` | BW-safe commit wrapper |
| P21 | `lib/igt_kms_feature: add debugfs guard API` | Generic + DSC/joiner guards |
| P22 | `lib/igt_kms_feature: add scope macros` | IGT_DEBUGFS_GUARD_DSC/JOINER |

### Series 5: Multi-Output Orchestrator (3 patches)

| # | Patch | What it does |
|---|-------|-------------|
| P23 | `lib/igt_kms: add spec/ctx structs` | Data structures for multi-output |
| P24 | `lib/igt_kms: add setup/commit/teardown` | Orchestrator implementation |
| P25 | `lib/igt_kms: add for_each_output_combo()` | Multi-output combo iteration |

### Series 6: New Tests (3 patches)

| # | Patch | What it does |
|---|-------|-------------|
| P26 | `tests: add kms_feature_combo.c` | DSC+Joiner, HDR+DSC test file |
| P27 | `tests: add dual-output combo tests` | Multi-output feature tests |
| P28 | `tests: add triple-feature combo tests` | HDR+DSC+Joiner tests |

**Total: 28 patches across 6 series. ~5 weeks.**

---

## What This Does NOT Do

- **No declarative framework.** No YAML config, no test runner, no plugin system.
  Just C library functions.

- **No modification to existing tests.** All existing tests compile and run
  unchanged. Migration is optional and incremental.

- **No wrappers for single-property checks.** `igt_crtc_has_prop(crtc,
  IGT_CRTC_DEGAMMA_LUT)` is already the right API for color management
  features.

- **No unified enable/disable API.** DSC enable needs BPC control. PSR enable
  needs mode selection. FBC is per-pipe. The existing per-feature enable APIs
  (`force_dsc_enable()`, `psr_enable()`, `intel_fbc_enable()`) are richer
  and stay as-is.

- **No modification to `__igt_pipe_populate_outputs()`.** The new allocator
  is a separate, opt-in API.

- **No constraint solver.** The pipe allocator is greedy with priority sorting.
  If it can't find an assignment, the test skips. This is sufficient for
  platforms with up to 8 pipes.

---

## Quick Reference — All New API

### Feature Predicates (`lib/igt_kms_feature.h`)

```
igt_output_supports_dsc(fd, output)
igt_output_supports_hdr(fd, output)
igt_output_supports_vrr(fd, output)
igt_output_supports_psr(fd, output, mode)
igt_output_supports_fbc(fd, pipe)
igt_output_supports_content_protection(fd, output)
igt_output_supports_drrs(fd, output)
igt_output_get_max_joiner(fd, output)           → enum joined_pipes
igt_output_get_vrr_range(fd, output, &min, &max) → bool
igt_output_has_force_joiner(fd, output)
igt_output_can_force_ultra_joiner(fd, output)
igt_source_supports_dsc(fd)
igt_source_supports_joiner(fd)
```

### Mode Finders (`lib/igt_kms_feature.h`)

```
igt_find_joiner_mode(fd, output, level, &mode)     → bool
igt_find_non_joiner_mode(fd, output, &mode)         → bool
igt_find_hdr_mode(fd, output, &mode)                → bool
igt_find_vrr_mode(fd, output, &mode)                → bool
```

### Pipe Allocator (`lib/igt_kms.h`)

```
igt_output_get_required_pipes(fd, output)             → int (1/2/4)
igt_find_consecutive_pipes(n, avail, master, need)    → int (pipe or -1)
igt_get_master_pipe_mask(display)                      → uint32_t
igt_get_valid_pipe_mask(display)                       → uint32_t
igt_allocate_pipes(display, outputs, n, &used_pipes)  → int (0 or -1)
```

### Output Utilities (`lib/igt_kms.h`)

```
igt_classify_outputs(display, fd, pred, match, &m_count, nomatch, &nm_count)
igt_find_output_with(display, fd, pred)               → igt_output_t *
igt_count_outputs_with(display, fd, pred)             → int
igt_output_setup_fb(fd, output, fmt, mod, &fb)        → igt_plane_t *
```

### Commit Helpers (`lib/igt_kms.h`)

```
igt_bw_safe_commit(display)    → bool
igt_try_bw_commit(display)     → int (0 or errno)
```

### Multi-Output Orchestrator (`lib/igt_kms.h`)

```
igt_multi_output_setup(display, fd, specs, n, &ctx)
igt_multi_output_try_setup(display, fd, specs, n, &ctx) → int
igt_multi_output_commit(&ctx)
igt_multi_output_try_commit(&ctx)                        → int
igt_multi_output_teardown(&ctx)
```

### Macros (`lib/igt_kms.h`)

```
for_each_connected_output_where(display, output, pred)
for_each_pipe_output_combo(display, crtc, output)
for_each_output_combo(display, outputs, n, preds)
igt_output_require_dsc(fd, output)
igt_output_require_hdr(fd, output)
igt_output_require_vrr(fd, output)
igt_output_require_psr(fd, output, mode)
IGT_DEBUGFS_GUARD_DSC(fd, output)
IGT_DEBUGFS_GUARD_JOINER(fd, output)
```
