# KMS Test Library â€” New Infrastructure for Multi-Output & Multi-Feature Testing

---

## Goal

We want to make it easy to write KMS tests that exercise **multiple display
features simultaneously across multiple outputs** â€” things like DSC + Big Joiner
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
together. The diagram below shows the layers from bottom (foundational) to top
(highest-level composition).

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                           Test Code                                      â”‚
â”‚                                                                          â”‚
â”‚  igt_subtest("dsc-joiner-dual-output") {                                â”‚
â”‚      for_each_connected_output_where(display, output,                    â”‚
â”‚              igt_output_has_dsc(fd, output) &&                           â”‚
â”‚              igt_output_get_max_joiner(fd, output) >= BIG_JOINER)        â”‚
â”‚      { ... }                                                             â”‚
â”‚  }                                                                       â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚                                                                          â”‚
â”‚  Layer 8: Convenience Helpers                                            â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”‚
â”‚  â”‚ igt_output_setup_fb(fd, output, format, modifier, &fb)         â”‚      â”‚
â”‚  â”‚ igt_find_joiner_mode(fd, output, level, &mode)                 â”‚      â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜      â”‚
â”‚                                                                          â”‚
â”‚  Layer 7: Composition Macros                                             â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”‚
â”‚  â”‚ for_each_connected_output_where(display, output, pred)         â”‚      â”‚
â”‚  â”‚ for_each_pipe_output_combo(display, crtc, output)              â”‚      â”‚
â”‚  â”‚ for_each_output_combo(display, &iter, outputs[], n, preds[])   â”‚      â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜      â”‚
â”‚                                                                          â”‚
â”‚  Layer 5: Debugfs State Helpers  â”‚  Layer 6: Output Classifier           â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”       â”‚
â”‚  â”‚ igt_intel_dsc_guard_begin â”‚   â”‚  â”‚ igt_classify_outputs()     â”‚       â”‚
â”‚  â”‚ igt_intel_dsc_guard_end   â”‚   â”‚  â”‚ igt_find_output_with()     â”‚       â”‚
â”‚  â”‚ igt_debugfs_guard_begin   â”‚   â”‚  â”‚ igt_count_outputs_with()   â”‚       â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â”‚
â”‚                                                                          â”‚
â”‚  Layer 4: BW-Safe Commit         â”‚  Layer 3: Multi-Output Builder        â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”       â”‚
â”‚  â”‚ igt_bw_safe_commit()      â”‚   â”‚  â”‚ igt_multi_output_find()    â”‚       â”‚
â”‚  â”‚ igt_try_bw_commit()       â”‚   â”‚  â”‚ igt_multi_output_setup()   â”‚       â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â”‚  â”‚ igt_multi_output_teardown()â”‚       â”‚
â”‚                                  â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â”‚
â”‚                                                                          â”‚
â”‚  Layer 2: Pipe Allocator                                                 â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”‚
â”‚  â”‚ igt_allocate_pipes()  igt_find_consecutive_pipes()              â”‚      â”‚
â”‚  â”‚ igt_compute_required_pipes()  igt_output_get_required_pipes()   â”‚      â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜      â”‚
â”‚                                                                          â”‚
â”‚  Layer 1: Feature Detection Predicates                                   â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”‚
â”‚  â”‚ igt_output_has_dsc(fd, output)         â€” silent bool           â”‚      â”‚
â”‚  â”‚ igt_output_require_dsc(fd, output)     â€” skip with message     â”‚      â”‚
â”‚  â”‚ igt_output_has_hdr / vrr / psr / fbc                           â”‚      â”‚
â”‚  â”‚ igt_output_get_max_joiner(fd, output)                          â”‚      â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜      â”‚
â”‚                                                                          â”‚
â”‚  Existing APIs (UNCHANGED)                                               â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”      â”‚
â”‚  â”‚ lib/igt_dsc.c   â€” 14 functions (enable/force/bpc/format/frac)  â”‚      â”‚
â”‚  â”‚ lib/igt_psr.c   â€” 15 functions (enable/disable/wait/mode)      â”‚      â”‚
â”‚  â”‚ lib/i915/intel_fbc.c â€” 8 functions (enable/disable/wait)       â”‚      â”‚
â”‚  â”‚ igt_output_has_prop() / igt_crtc_has_prop()                    â”‚      â”‚
â”‚  â”‚ igt_display_commit2() / igt_display_try_commit2()              â”‚      â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜      â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

**Key design decisions:**

- **Composable library functions.**
  Functions return values. Tests make decisions.

- **Silent predicate functions + explicit require variants.** Each feature gets
  a pure boolean predicate (`igt_output_has_dsc()`) that checks the full
  prerequisite chain *without printing anything*. A separate
  `igt_output_require_dsc()` prints a diagnostic and skips. This avoids
  log spam when predicates run inside loops.

- **No RAII / `__attribute__((cleanup))`.** IGT uses `setjmp`/`longjmp` for
  failure/skip flow, which makes C scope cleanup unreliable. All state
  management uses explicit `begin`/`end` pairs, with `igt_install_exit_handler()`
  as a safety net for process-level cleanup.

- **No global/static macro state.** Combo iteration uses caller-allocated
  iterator objects with proper backtracking cursors, not hidden globals.
  Safe for nesting, forking, and re-entrancy.

- **Intel-specific debugfs helpers are namespaced.** Anything that depends on
  `i915`/`xe` debugfs nodes uses `igt_intel_*` naming, not generic `igt_*`.

- **Preserves existing rich APIs.** PSR has 15 functions with mode parameters.
  These are untouched â€” the new API sits alongside them, not on top.

- **Each layer is independently useful.** A test can use just the pipe allocator,
  or just the predicates, or just the output classifier. No forced buy-in.

- **100% backward compatible.** Purely additive. No existing test needs changes.
## Layer 1 â€” Feature Detection Predicates

### What this is

A set of boolean functions in a new `lib/igt_kms_feature.h` that answer
"does this output support feature X?" by checking the full prerequisite chain
(source capability, sink capability, connector type requirements).

### Design: Silent predicates + Require variants

Predicates are **pure boolean checks** â€” they never print anything. This is
critical because predicates are typically evaluated inside loops (e.g.,
`for_each_connected_output_where`), and printing on every false evaluation
would spam logs.

Diagnostic output is provided by separate **require** functions, which print
once and skip the subtest. These are implemented as **functions** (not macros)
to enable richer status handling via the `igt_feature_status_t` enum, and to
avoid name collisions between macro and function definitions.

For structured diagnostics beyond simple bool, a status enum is available:

```c
/**
 * igt_feature_status - Rich reason code for feature detection
 *
 * Returned by igt_output_check_dsc() etc. for cases where the
 * caller wants to know *why* a feature isn't available.
 */
typedef enum {
    IGT_FEATURE_OK = 0,
    IGT_FEATURE_NO_SOURCE,       /* GPU/driver doesn't support it */
    IGT_FEATURE_NO_SINK,         /* Panel/monitor doesn't support it */
    IGT_FEATURE_NO_FEC,          /* External DP needs FEC for DSC */
    IGT_FEATURE_NO_PROPERTY,     /* DRM property missing */
    IGT_FEATURE_NO_EDID_DATA,    /* EDID lacks required metadata */
    IGT_FEATURE_WRONG_CONNECTOR, /* Wrong connector type */
} igt_feature_status_t;
```

### Full API

```c
/* â”€â”€ lib/igt_kms_feature.h â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

/*
 * Silent boolean predicates â€” pure checks, never print.
 * Safe to call inside loops without log spam.
 */

/* DSC: source support + sink support + FEC (for external DP) */
bool igt_output_has_dsc(int fd, igt_output_t *output);

/* HDR: HDR_OUTPUT_METADATA property + EDID CTA HDR metadata */
bool igt_output_has_hdr(int fd, igt_output_t *output);

/* VRR: VRR_CAPABLE property exists and reads true */
bool igt_output_has_vrr(int fd, igt_output_t *output);

/* VRR range: parses debugfs vrr_range file, returns min/max Hz */
bool igt_output_get_vrr_range(int fd, igt_output_t *output,
                              int *min_hz, int *max_hz);

/* PSR: preserves mode parameter (PSR_MODE_1, PSR_MODE_2, etc.) */
bool igt_output_has_psr(int fd, igt_output_t *output,
                        enum psr_mode mode);

/* Joiner: returns JOINED_PIPES_NONE / BIG_JOINER / ULTRA_JOINER */
enum joined_pipes igt_output_get_max_joiner(int fd, igt_output_t *output);

/* FBC: per-pipe check (named igt_pipe_* because it's a pipe property) */
bool igt_pipe_has_fbc(int fd, enum pipe pipe);

/* HDCP */
bool igt_output_has_content_protection(int fd, igt_output_t *output);

/* DRRS */
bool igt_output_has_drrs(int fd, igt_output_t *output);

/* Force joiner: can debugfs force joiner be used on this output? */
bool igt_output_has_force_joiner(int fd, igt_output_t *output);

/* Source-only checks (no output needed) */
bool igt_source_has_dsc(int fd);
bool igt_source_has_joiner(int fd);

/*
 * Require variants â€” print diagnostic and skip if not supported.
 * Use at the "decision boundary" (once per subtest), not in loops.
 *
 * These are FUNCTIONS, not macros, to enable richer diagnostics
 * via igt_feature_status_t and to avoid name collisions.
 */
void igt_output_require_dsc(int fd, igt_output_t *output);
void igt_output_require_hdr(int fd, igt_output_t *output);
void igt_output_require_vrr(int fd, igt_output_t *output);
void igt_output_require_psr(int fd, igt_output_t *output,
                            enum psr_mode mode);

/*
 * Rich status check â€” returns structured reason code.
 * Use when the caller needs to distinguish failure reasons.
 */
igt_feature_status_t igt_output_check_dsc(int fd, igt_output_t *output);
```

### Implementation â€” `igt_output_has_dsc()`

> **Note:** The predicate checks the full chain silently. No `igt_info()` calls.

```c
bool igt_output_has_dsc(int fd, igt_output_t *output)
{
    if (!igt_is_dsc_supported_by_source(fd))
        return false;

    if (!igt_is_dsc_supported_by_sink(fd, output->name))
        return false;

    if (!output_is_internal_panel(output) &&
        !igt_is_fec_supported(fd, output->name))
        return false;

    return true;
}
```

### Implementation â€” `igt_output_check_dsc()` (Rich Status)

```c
igt_feature_status_t igt_output_check_dsc(int fd, igt_output_t *output)
{
    if (!igt_is_dsc_supported_by_source(fd))
        return IGT_FEATURE_NO_SOURCE;

    if (!igt_is_dsc_supported_by_sink(fd, output->name))
        return IGT_FEATURE_NO_SINK;

    if (!output_is_internal_panel(output) &&
        !igt_is_fec_supported(fd, output->name))
        return IGT_FEATURE_NO_FEC;

    return IGT_FEATURE_OK;
}
```

### Implementation â€” `igt_output_require_dsc()` (Function, not macro)

> **Note:** Prints once-and-skips at the decision boundary, not inside loops.

```c
void igt_output_require_dsc(int fd, igt_output_t *output)
{
    igt_feature_status_t st = igt_output_check_dsc(fd, output);

    switch (st) {
    case IGT_FEATURE_OK:
        return;
    case IGT_FEATURE_NO_SOURCE:
        igt_skip("DSC: GPU does not have DSC encoder\n");
    case IGT_FEATURE_NO_SINK:
        igt_skip("DSC: sink %s does not support DSC\n", output->name);
    case IGT_FEATURE_NO_FEC:
        igt_skip("DSC: external %s requires FEC\n", output->name);
    default:
        igt_skip("DSC: not supported on %s\n", output->name);
    }
}
```

### Implementation â€” Other require variants

```c
void igt_output_require_hdr(int fd, igt_output_t *output)
{
    igt_require_f(igt_output_has_hdr(fd, output),
                  "HDR not supported on %s\n", output->name);
}

void igt_output_require_vrr(int fd, igt_output_t *output)
{
    igt_require_f(igt_output_has_vrr(fd, output),
                  "VRR not supported on %s\n", output->name);
}

void igt_output_require_psr(int fd, igt_output_t *output,
                            enum psr_mode mode)
{
    igt_require_f(igt_output_has_psr(fd, output, mode),
                  "PSR mode %d not supported on %s\n",
                  mode, output->name);
}
```

### Implementation â€” `igt_output_has_hdr()`

```c
bool igt_output_has_hdr(int fd, igt_output_t *output)
{
    if (!igt_output_has_prop(output, IGT_CONNECTOR_HDR_OUTPUT_METADATA))
        return false;
    if (!igt_is_hdr_panel(fd, output))
        return false;
    return true;
}
```

### Functions promoted from test files to library

| Function | Currently in | Becomes |
|----------|-------------|---------|
| `is_panel_hdr()` | `tests/kms_hdr.c` | `igt_is_hdr_panel()` in `lib/igt_kms_feature.c` |
| `get_vrr_range()` | `tests/kms_vrr.c` | `igt_output_get_vrr_range()` in `lib/igt_kms_feature.c` |

### What we DON'T wrap

Single-property checks remain as-is â€” they're already the right abstraction:

```c
igt_output_has_prop(output, IGT_CONNECTOR_SCALING_MODE);
igt_crtc_has_prop(crtc, IGT_CRTC_DEGAMMA_LUT);
igt_crtc_has_prop(crtc, IGT_CRTC_GAMMA_LUT);
igt_crtc_has_prop(crtc, IGT_CRTC_CTM);
```
## Layer 2 â€” Joiner-Aware Pipe Allocator

### What this is

A pipe allocation API that understands joiner requirements. It assigns
pipes to N outputs in a single call, handling the constraint that big joiner
needs 2 consecutive pipes and ultra joiner needs 4.

### Where the code comes from

`tests/intel/kms_joiner_helper.c` already contains well-tested functions
for this: `find_consecutive_pipes()`, `get_required_pipes()`, and
`igt_assign_pipes_for_outputs()`. These are currently `static` in a test
helper file. We promote them to `lib/igt_kms.c` and make them public.

### Design: Compute pipe requirement from modeset intent, not cache it

Pipe requirement depends on more than just dotclock â€” it can vary with
BPC, DSC state, format, display width, and platform constraints. Caching a
single `required_pipes` value inside `igt_output_t` would become stale as
soon as the test changes format or DSC state.

Instead, pipe requirement is computed from an explicit **modeset intent**
structure that captures all the relevant parameters:

```c
/**
 * igt_modeset_intent - Describes a planned modeset configuration
 *
 * Pass this to igt_compute_required_pipes() to get deterministic
 * pipe count. The result depends on these parameters together.
 *
 * Note: DSC and BPC are intentionally NOT included here. DSC
 * compression ratio varies by sink/driver policy and cannot be
 * assumed. BPC impact on effective clock is format-dependent.
 * Joiner decisions are based on hard constraints only:
 *   - hdisplay vs max_pipe_width
 *   - mode clock vs max_dotclock
 * Tests that need to force joiner regardless should use min_joiner.
 */
struct igt_modeset_intent {
    drmModeModeInfo mode;    /* Target mode */
    uint32_t format;         /* Pixel format (affects bandwidth) */
    uint64_t modifier;       /* FB modifier (affects bandwidth) */
    enum joiner_level min_joiner; /* Force minimum joiner level */
};

/**
 * igt_compute_required_pipes - How many pipes does this config need?
 *
 * Returns: 1 (normal), 2 (big joiner), 4 (ultra joiner)
 *
 * Checks both dotclock vs max_dotclock AND hdisplay vs max_pipe_width
 * to determine joiner requirement. Either dimension exceeding the
 * single-pipe limit triggers joiner.
 *
 * This is a pure function â€” its result depends only on the intent
 * parameters and platform limits. No side effects.
 */
int igt_compute_required_pipes(int fd, igt_output_t *output,
                               const struct igt_modeset_intent *intent);

/*
 * Simplified variant for the common case where only mode matters.
 * Equivalent to igt_compute_required_pipes() with default intent.
 */
int igt_output_get_required_pipes(int fd, igt_output_t *output);
```

### Full Pipe Allocator API

```c
/* â”€â”€ Added to lib/igt_kms.h â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

int igt_find_consecutive_pipes(int n_crtcs, uint32_t available_mask,
                               int need);

uint32_t igt_get_master_pipe_mask(igt_display_t *display);
uint32_t igt_get_valid_pipe_mask(igt_display_t *display);

/*
 * Split API: check feasibility without mutating state, then apply.
 * igt_check_pipe_assignment() is pure â€” safe for iteration loops.
 * igt_apply_pipe_assignment() sets CRTCs on outputs.
 * igt_allocate_pipes() is the combined convenience wrapper.
 */
int igt_check_pipe_assignment(igt_display_t *display,
                              igt_output_t **outputs, int n_outputs,
                              int *master_pipes);
void igt_apply_pipe_assignment(igt_display_t *display,
                               igt_output_t **outputs, int n_outputs,
                               const int *master_pipes);
int igt_allocate_pipes(igt_display_t *display,
                       igt_output_t **outputs, int n_outputs,
                       uint32_t *used_pipes);
```

### Implementation â€” `igt_compute_required_pipes()`

```c
/**
 * igt_get_max_pipe_width - Maximum horizontal pixels per pipe
 *
 * Platform-specific limit. Modes wider than this need joiner.
 * Returns 0 if unknown (caller should fall through to dotclock check).
 *
 * Uses existing intel_get_device_info() tables for platform values
 * rather than ad-hoc constants. If the platform is not recognized,
 * returns 0 and the dotclock path is used as fallback.
 */
static int igt_get_max_pipe_width(int fd)
{
    const struct intel_device_info *info;
    uint16_t devid;

    devid = intel_get_drm_devid(fd);
    info = intel_get_device_info(devid);
    if (!info)
        return 0;

    /*
     * get_max_pipe_hdisplay(fd) is the existing IGT helper that
     * queries the platform's maximum horizontal display width.
     * If available, use it directly.
     */
    return get_max_pipe_hdisplay(fd);
}

int igt_compute_required_pipes(int fd, igt_output_t *output,
                               const struct igt_modeset_intent *intent)
{
    int max_dotclock = igt_get_max_dotclock(fd);
    int max_pipe_width = igt_get_max_pipe_width(fd);
    int hdisplay = intent->mode.hdisplay;

    /* Forced minimum joiner always wins */
    if (intent->min_joiner >= ULTRA_JOINER)
        return 4;
    if (intent->min_joiner >= BIG_JOINER)
        return 2;

    /* Check width-based joiner requirement (hard constraint) */
    if (max_pipe_width > 0) {
        if (hdisplay > 2 * max_pipe_width)
            return 4;  /* Ultra joiner: too wide for 2 pipes */
        if (hdisplay > max_pipe_width)
            return 2;  /* Big joiner: too wide for 1 pipe */
    }

    /*
     * Check dotclock-based joiner requirement (hard constraint).
     *
     * We use the raw mode clock here. DSC and BPC do not factor in
     * because:
     *  - DSC compression ratio is not fixed (varies by sink/driver)
     *  - BPC impact on effective clock is format-dependent
     *  - The joiner decision should be based on the display timing
     *    requirement, not on compression guesses
     *
     * If a test needs to force joiner regardless, it should set
     * intent->min_joiner explicitly.
     */
    if (max_dotclock <= 0)
        return 1;

    if (intent->mode.clock > 2 * max_dotclock)
        return 4;
    if (intent->mode.clock > max_dotclock)
        return 2;

    return 1;
}

/* Simplified variant â€” mode-only check */
int igt_output_get_required_pipes(int fd, igt_output_t *output)
{
    struct igt_modeset_intent intent = {0};
    drmModeModeInfo *mode = igt_output_get_mode(output);

    if (!mode)
        return 1;

    memcpy(&intent.mode, mode, sizeof(intent.mode));
    return igt_compute_required_pipes(fd, output, &intent);
}
```

### Implementation â€” Pipe Mask Helpers

The pipe masks are computed once during `igt_display_require()` and cached in
`igt_display_t`. The computation uses `display->pipes[i].crtc_id` which is
already populated by DRM resource enumeration at that point.

```c
uint32_t igt_get_valid_pipe_mask(igt_display_t *display)
{
    uint32_t mask = 0;
    for (int i = 0; i < display->n_pipes; i++)
        if (display->pipes[i].crtc_id)
            mask |= BIT(i);
    return mask;
}

uint32_t igt_get_master_pipe_mask(igt_display_t *display)
{
    uint32_t valid = display->valid_pipe_mask;
    uint32_t mask = 0;

    for (int i = 0; i < display->n_pipes - 1; i++)
        if ((valid & BIT(i)) && (valid & BIT(i + 1)))
            mask |= BIT(i);
    return mask;
}
```

> **Note on caching:** `valid_pipe_mask` and `master_pipe_mask` are set during
> `igt_display_require()`, immediately after pipe enumeration completes. No
> other code references these fields before that point. The sequence is:
> 1. `drmModeGetResources()` populates `pipes[].crtc_id`
> 2. `valid_pipe_mask = igt_get_valid_pipe_mask(display)` (new)
> 3. `master_pipe_mask = igt_get_master_pipe_mask(display)` (new)

### Implementation â€” `igt_find_consecutive_pipes()`

For `need == 1` (no joiner), any available pipe works. For `need >= 2`
(big/ultra joiner), we verify that the full range `[p, p+need)` is valid and
available. The `master_pipe_mask` is used only for `need == 2` as a fast check;
for `need == 4` we check the full 4-pipe range directly.

```c
int igt_find_consecutive_pipes(int n_crtcs, uint32_t available_mask,
                               int need)
{
    if (need == 1) {
        for (int p = 0; p < n_crtcs; p++)
            if (available_mask & BIT(p))
                return p;
        return -1;
    }

    /* For need >= 2: check that all pipes [p, p+need) are available */
    for (int p = 0; p <= n_crtcs - need; p++) {
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

### The Allocator â€” Split: Feasibility Check + Apply

The allocator is split into two explicit entry points:

1. **`igt_check_pipe_assignment()`** â€” Pure feasibility check. Computes
   which master pipe each output would be assigned to, but does NOT call
   `igt_output_set_crtc()` or mutate any display state. Returns the
   result in a caller-provided `master_pipes[]` array. This is safe to
   call from iteration loops, combo searches, and nested contexts.

2. **`igt_apply_pipe_assignment()`** â€” Applies the assignment computed by
   the check function. Calls `igt_output_set_crtc()` for each output.

The combined **`igt_allocate_pipes()`** calls both in sequence for callers
that want the traditional one-call behavior.

```c
/**
 * igt_check_pipe_assignment - Pure feasibility check for pipe allocation
 *
 * Computes a valid pipe assignment without modifying display state.
 * Results are stored in master_pipes[i] = master pipe index for output i.
 *
 * Returns: 0 on success, -1 if no valid assignment exists.
 */
int igt_check_pipe_assignment(igt_display_t *display,
                              igt_output_t **outputs, int n_outputs,
                              int *master_pipes);

/**
 * igt_apply_pipe_assignment - Apply a previously computed assignment
 *
 * Calls igt_output_set_crtc() for each output using the master_pipes[]
 * array from igt_check_pipe_assignment().
 */
void igt_apply_pipe_assignment(igt_display_t *display,
                               igt_output_t **outputs, int n_outputs,
                               const int *master_pipes);

/**
 * igt_allocate_pipes - Check + apply in one call (convenience wrapper)
 */
int igt_allocate_pipes(igt_display_t *display,
                       igt_output_t **outputs, int n_outputs,
                       uint32_t *used_pipes);
```

```c
int igt_check_pipe_assignment(igt_display_t *display,
                              igt_output_t **outputs, int n_outputs,
                              int *master_pipes)
{
    uint32_t avail = display->valid_pipe_mask;
    int fd = display->drm_fd;

    /* Determine pipe requirements */
    int requirements[n_outputs];
    int order[n_outputs];
    for (int i = 0; i < n_outputs; i++) {
        requirements[i] = igt_output_get_required_pipes(fd, outputs[i]);
        order[i] = i;
    }

    /* Sort by descending requirement (4-pipe first, then 2, then 1) */
    for (int i = 0; i < n_outputs - 1; i++)
        for (int j = i + 1; j < n_outputs; j++)
            if (requirements[order[i]] < requirements[order[j]]) {
                int tmp = order[i];
                order[i] = order[j];
                order[j] = tmp;
            }

    /* Find assignment without mutating state */
    for (int i = 0; i < n_outputs; i++) {
        int idx = order[i];
        int need = requirements[idx];
        int master = igt_find_consecutive_pipes(display->n_pipes,
                                                 avail, need);
        if (master < 0)
            return -1;

        master_pipes[idx] = master;

        /* Mark consumed pipes as used (locally only) */
        for (int p = master; p < master + need; p++)
            avail &= ~BIT(p);
    }

    return 0;
}

void igt_apply_pipe_assignment(igt_display_t *display,
                               igt_output_t **outputs, int n_outputs,
                               const int *master_pipes)
{
    for (int i = 0; i < n_outputs; i++)
        igt_output_set_crtc(outputs[i],
                            igt_crtc_for_pipe(display, master_pipes[i]));
}

int igt_allocate_pipes(igt_display_t *display,
                       igt_output_t **outputs, int n_outputs,
                       uint32_t *used_pipes)
{
    int master_pipes[n_outputs];
    uint32_t avail = display->valid_pipe_mask;

    if (used_pipes)
        avail &= ~(*used_pipes);

    int ret = igt_check_pipe_assignment(display, outputs,
                                        n_outputs, master_pipes);
    if (ret < 0)
        return -1;

    /* Apply: set CRTCs on outputs */
    igt_apply_pipe_assignment(display, outputs, n_outputs,
                              master_pipes);

    /* Report back which pipes are in use */
    if (used_pipes) {
        for (int i = 0; i < n_outputs; i++) {
            int need = igt_output_get_required_pipes(
                display->drm_fd, outputs[i]);
            for (int p = master_pipes[i];
                 p < master_pipes[i] + need; p++)
                *used_pipes |= BIT(p);
        }
    }

    return 0;
}
```

### Why we don't modify `__igt_pipe_populate_outputs()`

`__igt_pipe_populate_outputs()` runs during `igt_display_init()`, **before**
any mode is selected. Joiner detection requires knowing the mode. You can't
know how many pipes an output needs until you've picked a mode.

So `igt_allocate_pipes()` is a **separate, opt-in API** called after mode
selection. The existing codepath is untouched.
## Layer 3 â€” Multi-Output Setup Builder

### What this is

A step-by-step builder API that handles the lifecycle of a multi-output
test configuration. Unlike a monolithic "one call does everything" orchestrator,
each step is an explicit function call that the test author can see, skip,
or replace.

### Design: Explicit steps, not magic

The builder is deliberately **not opaque**. Each step does one thing:

1. **Find** â€” match outputs to specs using predicates
2. **Select modes** â€” call mode finders or use defaults
3. **Allocate pipes** â€” joiner-aware pipe assignment
4. **Create FBs** â€” framebuffers matching mode dimensions
5. **Validate BW** â€” TEST_ONLY commit to check bandwidth

Any step can be skipped or replaced with custom logic. For example:
- Want custom planes/formats? Skip `create_fbs`, do it yourself.
- Want negative testing? Skip `validate_bw`, commit and expect failure.
- Want to control which output is chosen? Set `spec.output` directly
  and skip `find`.
- Need MST branch selection? Write your own find logic.

### Data Structures

```c
/*
 * Describes what kind of output the test needs.
 * The test author fills in the predicate and optional mode finder.
 * The builder functions fill in the rest.
 */
typedef struct {
    /* â”€â”€ Filled by test author â”€â”€ */

    /* Required: returns true for outputs that match */
    bool (*predicate)(int fd, igt_output_t *output);

    /* Optional: finds a specific mode. NULL = use default mode */
    bool (*find_mode)(int fd, igt_output_t *output, drmModeModeInfo *mode);

    /* Optional: pixel format. 0 = XRGB8888 */
    uint32_t format;

    /* Optional: FB modifier. 0 = LINEAR */
    uint64_t modifier;

    /* â”€â”€ Filled by builder â”€â”€ */

    igt_output_t *output;       /* The matched output */
    drmModeModeInfo mode;       /* The selected mode */
    enum pipe master_pipe;      /* The assigned master pipe */
    igt_fb_t fb;                /* Framebuffer (if create_fbs was called) */
} igt_output_spec_t;


typedef struct {
    igt_display_t *display;
    int fd;
    int n_specs;
    igt_output_spec_t *specs;
    uint32_t used_pipes;
    bool committed;
} igt_multi_output_ctx_t;
```

### The Builder Functions

```c
/*
 * Step 1: Find matching outputs.
 *
 * For each spec, iterates connected outputs and finds the first
 * matching the predicate that hasn't been claimed by an earlier spec.
 *
 * If spec->output is already set (by the test author), this step
 * skips that spec â€” allowing manual output selection.
 *
 * Returns: 0 on success, -1 if any spec couldn't be matched.
 */
int igt_multi_output_find(igt_display_t *display, int fd,
                          igt_output_spec_t *specs, int n_specs,
                          igt_multi_output_ctx_t *ctx);

/*
 * Step 2: Select modes for all matched outputs.
 *
 * Calls find_mode() for specs that provide one. Otherwise uses
 * the output's default mode. Sets override mode on each output.
 *
 * Returns: 0 on success, -1 if any mode finder failed.
 */
int igt_multi_output_select_modes(igt_multi_output_ctx_t *ctx);

/*
 * Step 3: Allocate pipes (joiner-aware).
 *
 * Calls igt_allocate_pipes() for all matched outputs.
 *
 * Returns: 0 on success, -1 if pipe allocation failed.
 */
int igt_multi_output_allocate_pipes(igt_multi_output_ctx_t *ctx);

/*
 * Step 4: Create framebuffers.
 *
 * For each spec, creates an FB matching its mode dimensions and
 * sets it on the primary plane. Uses spec->format and spec->modifier
 * if provided, otherwise defaults to XRGB8888 + LINEAR.
 */
void igt_multi_output_create_fbs(igt_multi_output_ctx_t *ctx);

/*
 * Step 5: Bandwidth validation.
 *
 * Does a TEST_ONLY atomic commit. If it fails with ENOSPC,
 * tries igt_override_all_active_output_modes_to_fit_bw().
 *
 * Returns: 0 on success, -1 if bandwidth is insufficient.
 */
int igt_multi_output_validate_bw(igt_multi_output_ctx_t *ctx);

/*
 * Convenience: runs all 5 steps. Skips with message on failure.
 *
 * This IS the "one call" variant â€” but it calls the explicit steps
 * above, so the test author can always drop down to individual steps.
 */
void igt_multi_output_setup(igt_display_t *display, int fd,
                            igt_output_spec_t *specs, int n_specs,
                            igt_multi_output_ctx_t *ctx);

/*
 * Non-asserting variant. Returns 0 on success, -1 on failure.
 */
int igt_multi_output_try_setup(igt_display_t *display, int fd,
                               igt_output_spec_t *specs, int n_specs,
                               igt_multi_output_ctx_t *ctx);

/* Commit + teardown */
void igt_multi_output_commit(igt_multi_output_ctx_t *ctx);
int  igt_multi_output_try_commit(igt_multi_output_ctx_t *ctx);
void igt_multi_output_teardown(igt_multi_output_ctx_t *ctx);
```

### Implementation â€” `igt_multi_output_try_setup` as builder

```c
int igt_multi_output_try_setup(igt_display_t *display, int fd,
                               igt_output_spec_t *specs, int n_specs,
                               igt_multi_output_ctx_t *ctx)
{
    int ret;

    ret = igt_multi_output_find(display, fd, specs, n_specs, ctx);
    if (ret < 0)
        return ret;

    ret = igt_multi_output_select_modes(ctx);
    if (ret < 0)
        return ret;

    ret = igt_multi_output_allocate_pipes(ctx);
    if (ret < 0)
        return ret;

    igt_multi_output_create_fbs(ctx);

    ret = igt_multi_output_validate_bw(ctx);
    if (ret < 0) {
        igt_multi_output_teardown(ctx);
        return ret;
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
```

### Usage Example â€” Custom setup with fine control

```c
igt_subtest("dsc-joiner-custom-format") {
    igt_output_spec_t specs[] = {
        { .predicate = dsc_and_big_joiner,
          .find_mode = find_big_joiner_mode,
          .format = DRM_FORMAT_XRGB2101010,
        },
        { .predicate = any_connected },
    };
    igt_multi_output_ctx_t ctx;

    /* Use individual steps for fine control */
    igt_require(igt_multi_output_find(&display, fd, specs, 2, &ctx) == 0);
    igt_require(igt_multi_output_select_modes(&ctx) == 0);
    igt_require(igt_multi_output_allocate_pipes(&ctx) == 0);

    /* Custom FB setup â€” skip the standard create_fbs */
    igt_create_pattern_fb(fd,
        specs[0].mode.hdisplay, specs[0].mode.vdisplay,
        specs[0].format, DRM_FORMAT_MOD_Y_TILED, &specs[0].fb);
    igt_plane_set_fb(
        igt_output_get_plane_type(specs[0].output, DRM_PLANE_TYPE_PRIMARY),
        &specs[0].fb);

    /* Still use standard for the second output */
    igt_output_setup_fb(fd, specs[1].output,
        DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &specs[1].fb);

    igt_multi_output_commit(&ctx);
    /* ... validate ... */
    igt_multi_output_teardown(&ctx);
}
```

### Usage Example â€” Convenience (one-call)

```c
igt_subtest("dual-output-dsc-plus-normal") {
    igt_output_spec_t specs[] = {
        { .predicate = dsc_and_big_joiner,
          .find_mode = find_big_joiner_mode },
        { .predicate = any_connected },
    };
    igt_multi_output_ctx_t ctx;

    igt_multi_output_setup(&display, fd, specs, 2, &ctx);

    igt_intel_dsc_guard_begin(fd, ctx.specs[0].output, &dsc_guard);
    force_dsc_enable(fd, ctx.specs[0].output);
    igt_multi_output_commit(&ctx);
    igt_assert(igt_is_dsc_enabled(fd, ctx.specs[0].output->name));

    igt_intel_dsc_guard_end(&dsc_guard);
    igt_multi_output_teardown(&ctx);
}
```
## Layer 4 â€” Bandwidth-Safe Commit

### What this is

A commit wrapper that validates bandwidth before the real atomic commit.
It builds on **existing IGT infrastructure** â€” specifically
`igt_fit_modes_in_bw()` which is already upstream and used by tests today.

### Behavior details

1. **TEST_ONLY validation:** `igt_fit_modes_in_bw()` internally does a
   `DRM_MODE_ATOMIC_TEST_ONLY` commit. If it returns `ENOSPC`, it calls
   `igt_override_all_active_output_modes_to_fit_bw()` to try lower modes,
   then retries. This is existing IGT behavior â€” we don't change it.

2. **Mode mutation:** `igt_bw_safe_commit()` **may downscale modes** if
   bandwidth is tight. The caller should be aware that output modes can
   change after this call. If the test needs the exact requested mode,
   use `igt_try_bw_commit()` + manual handling instead.

3. **Non-Intel drivers:** `igt_fit_modes_in_bw()` is Intel-specific (it
   depends on i915/xe bandwidth validation returning `ENOSPC`). On other
   drivers, the TEST_ONLY commit will typically succeed (no BW check),
   so `igt_bw_safe_commit()` effectively degrades to a normal commit.
   This is acceptable â€” the wrapper adds safety on platforms that need it
   and is a no-op on platforms that don't.

4. **Return semantics:**
   - `igt_bw_safe_commit()` returns `false` only if BW fitting completely
     fails (couldn't find modes that fit). On success, commits atomically.
   - `igt_try_bw_commit()` is the raw `try_commit2` â€” no BW fitting,
     returns errno on failure. Use this for negative tests or when the
     caller handles BW failures explicitly.

### API

```c
/**
 * igt_bw_safe_commit - Validate BW, optionally downscale, then commit
 *
 * Calls igt_fit_modes_in_bw() which does TEST_ONLY + auto-downscale.
 * Then does the real COMMIT_ATOMIC.
 *
 * WARNING: May change output modes if bandwidth is tight.
 * Intel-specific: relies on i915/xe ENOSPC signaling for BW limits.
 * On non-Intel: degrades to a normal atomic commit (TEST_ONLY succeeds).
 *
 * Returns: true on success, false if BW fitting completely failed.
 */
bool igt_bw_safe_commit(igt_display_t *display);

/**
 * igt_try_bw_commit - Raw atomic try-commit (no BW fitting)
 *
 * Simply calls igt_display_try_commit2(COMMIT_ATOMIC).
 * Returns 0 on success, errno on failure.
 * Use for: negative tests, or when caller handles BW explicitly.
 */
int  igt_try_bw_commit(igt_display_t *display);
```

### Implementation

```c
bool igt_bw_safe_commit(igt_display_t *display)
{
    if (!igt_fit_modes_in_bw(display))
        return false;
    igt_display_commit2(display, COMMIT_ATOMIC);
    return true;
}

int igt_try_bw_commit(igt_display_t *display)
{
    return igt_display_try_commit2(display, COMMIT_ATOMIC);
}
```
## Layer 5 â€” Debugfs State Helpers

### What this is

Explicit `begin`/`end` functions that save a debugfs attribute's value and
restore it when the test is done. These are **not RAII or scope-based** â€” IGT
uses `setjmp`/`longjmp` for failure/skip control flow, which means automatic
(stack) variables are unspecified after `longjmp` and `__attribute__((cleanup))`
does not reliably fire.

Instead, cleanup is handled through two complementary mechanisms:

1. **Explicit `begin`/`end` pairs** that the test calls directly
2. **`igt_install_exit_handler()`** as a safety net for process-level cleanup
   (runs at process exit, covering `igt_assert`/`igt_require` failures)

### Namespacing: Intel-specific

All debugfs state helpers that depend on i915/xe debugfs node names are
namespaced under `igt_intel_*`, not generic `igt_*`. This makes it clear
that these helpers are Intel-specific and prevents confusion when used
alongside vendor-neutral KMS library code.

### API

```c
/* â”€â”€ lib/igt_kms_feature.h â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

typedef struct {
    int dir_fd;                /* fd to connector debugfs dir */
    const char *attr_name;     /* debugfs attribute name */
    char original_value[64];   /* saved content */
    int original_len;          /* length of saved content */
    bool active;               /* guard is holding state */
    pid_t owner_pid;           /* PID that created the guard */
} igt_debugfs_guard_t;

/*
 * Generic debugfs guard: save any debugfs attribute.
 * Caller is responsible for calling _end() in all exit paths.
 * An exit handler is also registered as a safety net.
 */
void igt_debugfs_guard_begin(int fd, igt_output_t *output,
                             const char *debugfs_attr,
                             igt_debugfs_guard_t *guard);
void igt_debugfs_guard_end(igt_debugfs_guard_t *guard);

/*
 * Intel-specific DSC guard: saves/restores "i915_dsc_fec_support".
 * Namespaced under igt_intel_* because it depends on i915 debugfs.
 */
void igt_intel_dsc_guard_begin(int fd, igt_output_t *output,
                               igt_debugfs_guard_t *guard);
void igt_intel_dsc_guard_end(igt_debugfs_guard_t *guard);

/*
 * Intel-specific joiner guard: saves/restores
 * "i915_bigjoiner_force_enable".
 */
void igt_intel_joiner_guard_begin(int fd, igt_output_t *output,
                                  igt_debugfs_guard_t *guard);
void igt_intel_joiner_guard_end(igt_debugfs_guard_t *guard);
```

### Usage Pattern

```c
igt_dynamic_f("%s", output->name) {
    igt_debugfs_guard_t dsc_guard;

    /* Save DSC state */
    igt_intel_dsc_guard_begin(fd, output, &dsc_guard);

    /* Modify debugfs state */
    force_dsc_enable(fd, output);

    /* ... test code ... */

    /* Restore DSC state.
     * If igt_assert() above fails, the exit handler
     * registered by _begin() will restore at process exit. */
    igt_intel_dsc_guard_end(&dsc_guard);
}
```

### Implementation

Uses `igt_debugfs_simple_read()` / `igt_debugfs_simple_write()` which are
the correct upstream IGT helpers for directory-fd-based debugfs access.
The exit handler is installed exactly once via a static guard.

> **Note on `O_RDONLY` for the directory fd:** `igt_debugfs_connector_dir()`
> opens the connector's debugfs directory. The `igt_debugfs_simple_write()`
> helper opens the individual attribute file by name relative to this
> directory fd using `openat(dir_fd, attr, O_WRONLY)`. So the directory fd
> itself only needs `O_RDONLY` for `openat()` lookups â€” write permission
> is requested on the attribute file, not the directory.

```c
/*
 * Global list of active guards for exit handler safety net.
 * Limited to a reasonable max â€” tests rarely need more than a few.
 */
#define MAX_ACTIVE_GUARDS 16
static igt_debugfs_guard_t *active_guards[MAX_ACTIVE_GUARDS];
static int n_active_guards;
static bool exit_handler_installed;

static void _guard_exit_handler(int sig)
{
    /*
     * Consistent with established IGT practice: existing exit handlers
     * (e.g. igt_cleanup_aperture_trashers, connector state reset)
     * perform filesystem I/O from the same context. We follow the
     * same pattern here rather than introducing different behavior.
     *
     * Fork safety: only restore guards owned by this process.
     * After fork(), parent and child share initial state but diverge.
     * Without this check, both processes would attempt to restore
     * the same debugfs attributes, causing race conditions.
     */
    pid_t my_pid = getpid();
    for (int i = 0; i < n_active_guards; i++) {
        if (active_guards[i] && active_guards[i]->active &&
            active_guards[i]->owner_pid == my_pid) {
            igt_debugfs_simple_write(active_guards[i]->dir_fd,
                                     active_guards[i]->attr_name,
                                     active_guards[i]->original_value);
            active_guards[i]->active = false;
        }
    }
    n_active_guards = 0;
}

void igt_debugfs_guard_begin(int fd, igt_output_t *output,
                             const char *debugfs_attr,
                             igt_debugfs_guard_t *guard)
{
    memset(guard, 0, sizeof(*guard));

    guard->dir_fd = igt_debugfs_connector_dir(fd, output->name, O_RDONLY);
    igt_assert(guard->dir_fd >= 0);

    guard->attr_name = debugfs_attr;
    guard->original_len = igt_debugfs_simple_read(guard->dir_fd,
                                                   debugfs_attr,
                                                   guard->original_value,
                                                   sizeof(guard->original_value));
    guard->active = true;
    guard->owner_pid = getpid();

    /* Register in global list */
    igt_assert(n_active_guards < MAX_ACTIVE_GUARDS);
    active_guards[n_active_guards++] = guard;

    /* Install exit handler exactly once */
    if (!exit_handler_installed) {
        igt_install_exit_handler(_guard_exit_handler);
        exit_handler_installed = true;
    }
}

void igt_debugfs_guard_end(igt_debugfs_guard_t *guard)
{
    if (!guard->active)
        return;

    igt_debugfs_simple_write(guard->dir_fd, guard->attr_name,
                             guard->original_value);
    close(guard->dir_fd);
    guard->active = false;

    /* Remove from global list */
    for (int i = 0; i < n_active_guards; i++) {
        if (active_guards[i] == guard) {
            active_guards[i] = active_guards[--n_active_guards];
            break;
        }
    }
}

/* Intel-specific thin wrappers */
void igt_intel_dsc_guard_begin(int fd, igt_output_t *output,
                               igt_debugfs_guard_t *guard)
{
    igt_debugfs_guard_begin(fd, output, "i915_dsc_fec_support", guard);
}

void igt_intel_dsc_guard_end(igt_debugfs_guard_t *guard)
{
    igt_debugfs_guard_end(guard);
}

void igt_intel_joiner_guard_begin(int fd, igt_output_t *output,
                                  igt_debugfs_guard_t *guard)
{
    igt_debugfs_guard_begin(fd, output,
                           "i915_bigjoiner_force_enable", guard);
}

void igt_intel_joiner_guard_end(igt_debugfs_guard_t *guard)
{
    igt_debugfs_guard_end(guard);
}
```

### Why not `__attribute__((cleanup))`?

IGT's control flow model uses `setjmp`/`longjmp`:

- `igt_assert()` failure â†’ `longjmp` to subtest boundary
- `igt_require()` skip â†’ `longjmp` to subtest boundary

After `longjmp`, automatic (stack) variables have **unspecified values**
per the C standard. There is **no stack unwinding**, so `cleanup` attributes
do not fire. This means:

- `__attribute__((cleanup(fn)))` is **not guaranteed to run** on test failure
- The guard variable itself may have corrupted values after `longjmp`

The explicit `begin`/`end` pattern combined with `igt_install_exit_handler()`
provides reliable cleanup:

- Normal path: `_end()` is called explicitly
- Failure path: exit handler restores all active guards at process exit
- Skip path: same as failure â€” exit handler fires
## Layer 6 â€” Output Classifier

### What this is

A utility function that partitions connected outputs into "match" and
"no match" arrays based on a predicate.

### API

```c
void igt_classify_outputs(igt_display_t *display, int fd,
                          bool (*predicate)(int fd, igt_output_t *),
                          igt_output_t **match, int *match_count,
                          igt_output_t **no_match, int *no_match_count);

igt_output_t *igt_find_output_with(igt_display_t *display, int fd,
                                   bool (*pred)(int fd, igt_output_t *));

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
            if (match) match[m] = output;
            m++;
        } else {
            if (no_match) no_match[n] = output;
            n++;
        }
    }
    if (match_count) *match_count = m;
    if (no_match_count) *no_match_count = n;
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
## Layer 7 â€” Composition Macros

### What this is

Three new `for_each_*` macros added to `lib/igt_kms.h`. These extend the
existing family of 11 iteration macros. The first two build on the existing
`for_each_if()` mechanism. The third uses a **caller-allocated iterator**
with proper backtracking to enumerate all valid output combinations.

### Macro 1: `for_each_connected_output_where`

```c
#define for_each_connected_output_where(display, output, pred) \
    for_each_connected_output(display, output) \
        for_each_if(pred)
```

Usage:

```c
for_each_connected_output_where(&display, output,
        igt_output_has_dsc(fd, output) &&
        igt_output_has_hdr(fd, output)) {
    igt_dynamic_f("%s", output->name) { /* ... */ }
}
```

### Macro 2: `for_each_pipe_output_combo`

```c
#define for_each_pipe_output_combo(display, crtc, output) \
    for_each_crtc_with_valid_output(display, crtc, output) \
        for_each_if(_pipe_has_room_for_output(display, crtc, output))
```

### Macro 3: `for_each_output_combo` â€” Caller-allocated iterator

This macro uses a **caller-allocated iterator** with proper backtracking
cursors. It is safe for nesting, forking, re-entrancy, and dynamic subtests.

**How iteration works:**

1. On first call, `_first_output_combo()` builds a `connected[]` snapshot
   (stable ordering) and initializes all cursors to 0.
2. For each combo attempt, the iterator walks slots left-to-right, advancing
   each slot's cursor through `connected[]` until it finds an output that
   matches the predicate and hasn't been claimed by an earlier slot.
3. On `_next_output_combo()`, the iterator backtracks: it advances the
   **deepest** (rightmost) slot's cursor. If that slot overflows, it resets
   that cursor and advances the next-deeper slot (standard odometer pattern).
4. When all slots overflow (slot 0 exhausts its candidates), `exhausted`
   is set to true and iteration terminates.

```c
/**
 * igt_combo_iter_t - Iterator state for output combo enumeration
 *
 * Allocated by the caller (on stack or heap). Passed to the macro.
 * No global state, so safe for:
 *   - Nested combo loops
 *   - Forked child processes (IGT sometimes forks)
 *   - Re-entrancy from dynamic subtests
 *   - Future refactors that reorder control flow
 */
typedef struct {
    igt_display_t *display;
    int fd;
    bool (**preds)(int, igt_output_t *);
    int n_slots;

    /*
     * Snapshot of connected outputs (stable ordering).
     * Sized to IGT_MAX_CONNECTORS â€” the number of connected outputs
     * can far exceed the pipe count (MST, docks, virtual outputs).
     */
    igt_output_t *connected[IGT_MAX_CONNECTORS];
    int n_connected;

    /* Per-slot cursor into connected[]: the index of the output
     * currently assigned to this slot. Advanced during backtracking.
     * Sized to IGT_MAX_PIPES since slot count <= pipe count. */
    int cursor[IGT_MAX_PIPES];

    bool exhausted;
    bool initialized;
} igt_combo_iter_t;

#define for_each_output_combo(display, iter, outputs, n, preds) \
    for (int __combo_ok__ = \
             _first_output_combo(display, iter, outputs, n, preds); \
         __combo_ok__; \
         __combo_ok__ = \
             _next_output_combo(iter, outputs))
```

Usage:

```c
bool (*preds[])(int, igt_output_t *) = {
    dsc_capable,       /* output 0 must support DSC */
    any_connected,     /* output 1 can be anything */
};
igt_output_t *outs[2];
igt_combo_iter_t iter;   /* â† caller-allocated, no global state */

for_each_output_combo(&display, &iter, outs, 2, preds) {
    igt_dynamic_f("%s-%s", outs[0]->name, outs[1]->name) {
        /* outs[0] supports DSC, outs[1] is any other.
         * Pipes are pre-allocated and non-conflicting. */
    }
}
```

### Implementation â€” Combo iteration with backtracking

```c
/**
 * _try_assign_slot - Try to find a valid output for the given slot
 * starting from cursor[slot]. Skips outputs claimed by earlier slots.
 *
 * Returns true if a valid assignment was found (cursor[slot] updated).
 */
static bool _try_assign_slot(igt_combo_iter_t *iter,
                             igt_output_t **outputs, int slot)
{
    for (int c = iter->cursor[slot]; c < iter->n_connected; c++) {
        igt_output_t *candidate = iter->connected[c];

        /* Skip if already assigned to an earlier slot */
        bool claimed = false;
        for (int j = 0; j < slot; j++) {
            if (outputs[j] == candidate) {
                claimed = true;
                break;
            }
        }
        if (claimed)
            continue;

        /* Check predicate */
        if (!iter->preds[slot](iter->fd, candidate))
            continue;

        /* Valid assignment found */
        iter->cursor[slot] = c;
        outputs[slot] = candidate;
        return true;
    }

    /* No valid candidate from cursor[slot] onward */
    return false;
}

/**
 * _find_combo_from_slot - Fill slots [start_slot .. n_slots) with valid
 * outputs. For each slot, start searching from cursor[slot].
 *
 * Returns true if a complete combo is found. On failure, returns false
 * and the caller should backtrack.
 */
static bool _find_combo_from_slot(igt_combo_iter_t *iter,
                                  igt_output_t **outputs,
                                  int start_slot)
{
    for (int slot = start_slot; slot < iter->n_slots; slot++) {
        if (!_try_assign_slot(iter, outputs, slot)) {
            /* This slot failed: need to backtrack */
            return false;
        }
        /* Reset deeper slots to search from beginning */
        for (int d = slot + 1; d < iter->n_slots; d++)
            iter->cursor[d] = 0;
    }

    /*
     * All slots filled. Verify pipe allocation feasibility.
     * Uses igt_check_pipe_assignment() which is a pure feasibility
     * check â€” it only returns whether a valid assignment exists
     * and fills master_pipes[] with the result. It does NOT call
     * igt_output_set_crtc() or mutate any display state.
     * This keeps the iterator side-effect-free during enumeration.
     */
    int masters[iter->n_slots];
    return igt_check_pipe_assignment(iter->display, outputs,
                                     iter->n_slots, masters) == 0;
}

static int _first_output_combo(igt_display_t *display,
                               igt_combo_iter_t *iter,
                               igt_output_t **outputs, int n,
                               bool (**preds)(int, igt_output_t *))
{
    igt_output_t *output;

    memset(iter, 0, sizeof(*iter));
    iter->display = display;
    iter->fd = display->drm_fd;
    iter->preds = preds;
    iter->n_slots = n;

    /* Build connected[] snapshot (stable ordering) */
    iter->n_connected = 0;
    for_each_connected_output(display, output)
        iter->connected[iter->n_connected++] = output;

    /* Initialize all cursors to 0 */
    for (int s = 0; s < n; s++)
        iter->cursor[s] = 0;

    iter->initialized = true;

    /* Try to find the first valid combo starting from slot 0 */
    while (!iter->exhausted) {
        if (_find_combo_from_slot(iter, outputs, 0))
            return 1;

        /* Combo failed (predicate, uniqueness, or pipe allocation).
         * Backtrack: advance the deepest possible slot. */
        int advanced = _backtrack(iter, outputs);
        if (advanced < 0)
            return 0;
    }
    return 0;
}

/**
 * _backtrack - Advance the deepest slot that has remaining candidates.
 *
 * Standard odometer pattern: advance the rightmost digit. If it
 * overflows, reset it and advance the next digit to the left.
 * When slot 0 overflows, iteration is exhausted.
 *
 * Returns the slot index that was advanced (>= 0), so the caller
 * can resume _find_combo_from_slot() from exactly that slot.
 * Returns -1 if all combos are exhausted.
 */
static int _backtrack(igt_combo_iter_t *iter, igt_output_t **outputs)
{
    for (int slot = iter->n_slots - 1; slot >= 0; slot--) {
        /* Clear this slot's assignment */
        outputs[slot] = NULL;
        /* Advance cursor past the current position */
        iter->cursor[slot]++;

        if (iter->cursor[slot] < iter->n_connected) {
            /* Reset all deeper slots */
            for (int d = slot + 1; d < iter->n_slots; d++)
                iter->cursor[d] = 0;
            return slot;
        }
        /* This slot overflowed â€” reset and try the next shallower */
        iter->cursor[slot] = 0;
    }

    /* All slots overflowed */
    iter->exhausted = true;
    return -1;
}

static int _next_output_combo(igt_combo_iter_t *iter,
                              igt_output_t **outputs)
{
    if (iter->exhausted)
        return 0;

    /* Backtrack from the deepest slot to find the next combo */
    while (true) {
        int advanced_slot = _backtrack(iter, outputs);
        if (advanced_slot < 0)
            return 0;  /* exhausted */

        if (_find_combo_from_slot(iter, outputs, advanced_slot))
            return 1;
        /* Combo invalid â€” backtrack again */
    }
}
```

### Why this works correctly

1. **No repeated combos:** `cursor[slot]` is strictly advanced past the
   current position before searching. Deeper slots are reset to 0 only
   after a shallower slot advances, ensuring no combo is revisited.

2. **Complete enumeration:** The odometer pattern guarantees every valid
   combination of cursor positions is visited exactly once.

3. **Uniqueness:** `_try_assign_slot()` checks that no earlier slot already
   claims the candidate output.

4. **Pipe feasibility:** Each complete combo is validated through
   `igt_check_pipe_assignment()` â€” a pure feasibility check that does NOT
   mutate display state (no `igt_output_set_crtc` calls). Only after the
   macro body runs does the caller apply assignments via
   `igt_apply_pipe_assignment()`. If feasibility fails, the iterator
   backtracks to try the next combo.

5. **No side effects during iteration:** The feasibility check uses a fully
   local `masters[]` array and never modifies `used_pipes`, output CRTC
   assignments, or any other display state. This prevents surprising
   interactions with outer loops, nested combos, and dynamic subtests.

### Implementation â€” `_pipe_has_room_for_output()`

```c
static inline bool _pipe_has_room_for_output(igt_display_t *display,
                                             igt_crtc_t *crtc,
                                             igt_output_t *output)
{
    enum pipe p = crtc->pipe;
    int need = igt_output_get_required_pipes(display->drm_fd, output);

    if (need <= 1)
        return true;

    /* Check that all pipes [p, p+need) are valid */
    for (int k = 0; k < need; k++)
        if (!(display->valid_pipe_mask & BIT(p + k)))
            return false;

    return true;
}
```
## Layer 8 â€” Convenience Helpers

### `igt_output_setup_fb()` â€” Create FB and set on primary plane

```c
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

### Mode finder functions

```c
bool igt_find_joiner_mode(int fd, igt_output_t *output,
                          enum joined_pipes level,
                          drmModeModeInfo *mode);

bool igt_find_non_joiner_mode(int fd, igt_output_t *output,
                              drmModeModeInfo *mode);

bool igt_find_hdr_mode(int fd, igt_output_t *output,
                       drmModeModeInfo *mode);

bool igt_find_vrr_mode(int fd, igt_output_t *output,
                       drmModeModeInfo *mode);
```

### Implementation â€” `igt_find_joiner_mode()`

Checks both dotclock and hdisplay thresholds to find a mode that triggers
joiner at the requested level.

```c
bool igt_find_joiner_mode(int fd, igt_output_t *output,
                          enum joined_pipes level,
                          drmModeModeInfo *mode)
{
    drmModeConnector *conn = output->config.connector;
    int max_dotclock = igt_get_max_dotclock(fd);
    int max_pipe_width = igt_get_max_pipe_width(fd);
    int clock_threshold, width_threshold;

    if (max_dotclock <= 0 && max_pipe_width <= 0)
        return false;

    switch (level) {
    case JOINED_PIPES_BIG_JOINER:
        clock_threshold = max_dotclock;
        width_threshold = max_pipe_width;
        break;
    case JOINED_PIPES_ULTRA_JOINER:
        clock_threshold = 2 * max_dotclock;
        width_threshold = 2 * max_pipe_width;
        break;
    default:
        return false;
    }

    for (int i = 0; i < conn->count_modes; i++) {
        bool needs_joiner = false;

        if (max_dotclock > 0 && conn->modes[i].clock > clock_threshold)
            needs_joiner = true;
        if (max_pipe_width > 0 &&
            conn->modes[i].hdisplay > width_threshold)
            needs_joiner = true;

        if (needs_joiner) {
            memcpy(mode, &conn->modes[i], sizeof(*mode));
            return true;
        }
    }
    return false;
}
```
## Struct Extensions

### `igt_display_t`

Two new fields: cached pipe masks. Computed once during `igt_display_require()`
after pipe enumeration, before any test code runs.

```c
struct igt_display {
    /* ... existing fields unchanged ... */

    /*
     * NEW: Computed once during igt_display_require() and cached.
     *
     * valid_pipe_mask:  bit P set if pipe P exists and is not fused off
     * master_pipe_mask: bit P set if pipe P can be a joiner master
     *                   (both pipe P and pipe P+1 are valid)
     *
     * Initialization sequence in igt_display_require():
     *   1. drmModeGetResources() populates pipes[].crtc_id
     *   2. valid_pipe_mask = igt_get_valid_pipe_mask(display)
     *   3. master_pipe_mask = igt_get_master_pipe_mask(display)
     *
     * These fields are not accessed before step 2/3. Other code only
     * reads them after igt_display_require() returns.
     */
    uint32_t valid_pipe_mask;
    uint32_t master_pipe_mask;
};
```

Both structs are allocated via `calloc`, so new fields auto-initialize to 0.
There are no ABI constraints â€” this is userspace-only, not a kernel UAPI.

> **Note:** `igt_output_t` is **not modified**. Pipe requirements are computed
> on-demand from `igt_modeset_intent` or from the output's current mode via
> `igt_output_get_required_pipes()`. No cached `required_pipes` field â€” the
> value is always fresh.
## Complete Examples

### Example 1 â€” DSC + Big Joiner Test

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

        igt_require(igt_source_has_dsc(data.drm_fd));
        igt_require(igt_source_has_joiner(data.drm_fd));
    }

    igt_subtest_with_dynamic("dsc-with-big-joiner") {
        igt_output_t *output;

        for_each_connected_output_where(&data.display, output,
                igt_output_has_dsc(data.drm_fd, output) &&
                igt_output_get_max_joiner(data.drm_fd, output)
                    >= JOINED_PIPES_BIG_JOINER) {

            igt_dynamic_f("%s", output->name) {
                igt_fb_t fb;
                drmModeModeInfo mode;
                igt_debugfs_guard_t dsc_guard;

                igt_require(igt_find_joiner_mode(data.drm_fd, output,
                            JOINED_PIPES_BIG_JOINER, &mode));
                igt_output_override_mode(output, &mode);

                igt_require(igt_allocate_pipes(&data.display,
                            &output, 1, NULL) == 0);

                /* Explicit begin/end â€” no RAII dependency */
                igt_intel_dsc_guard_begin(data.drm_fd, output, &dsc_guard);
                force_dsc_enable(data.drm_fd, output);

                igt_output_setup_fb(data.drm_fd, output,
                    DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb);

                igt_assert(igt_bw_safe_commit(&data.display));
                igt_assert(igt_is_dsc_enabled(data.drm_fd, output->name));

                igt_remove_fb(data.drm_fd, &fb);
                igt_intel_dsc_guard_end(&dsc_guard);
            }
        }
    }

    igt_fixture {
        igt_display_fini(&data.display);
        drm_close_driver(data.drm_fd);
    }
}
```

---

### Example 2 â€” HDR + DSC + Big Joiner (Triple Feature)

```c
static bool hdr_dsc_big_joiner(int fd, igt_output_t *output)
{
    return igt_output_has_hdr(fd, output) &&
           igt_output_has_dsc(fd, output) &&
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
            igt_debugfs_guard_t dsc_guard;

            igt_require(igt_find_joiner_mode(data.drm_fd, output,
                        JOINED_PIPES_BIG_JOINER, &mode));
            igt_output_override_mode(output, &mode);
            igt_require(igt_allocate_pipes(&data.display,
                        &output, 1, NULL) == 0);

            igt_intel_dsc_guard_begin(data.drm_fd, output, &dsc_guard);
            force_dsc_enable(data.drm_fd, output);

            igt_output_set_prop_value(output,
                IGT_CONNECTOR_HDR_OUTPUT_METADATA, hdr_blob);
            igt_output_set_prop_value(output,
                IGT_CONNECTOR_MAX_BPC, 10);

            igt_output_setup_fb(data.drm_fd, output,
                DRM_FORMAT_XRGB2101010, DRM_FORMAT_MOD_LINEAR, &fb);

            igt_assert(igt_bw_safe_commit(&data.display));
            igt_assert(igt_is_dsc_enabled(data.drm_fd, output->name));

            igt_remove_fb(data.drm_fd, &fb);
            igt_intel_dsc_guard_end(&dsc_guard);
        }
    }
}
```

---

### Example 3 â€” Dual-Output Combo with for_each_output_combo

```c
static bool dsc_capable(int fd, igt_output_t *output)
{
    return igt_output_has_dsc(fd, output);
}

static bool any_connected(int fd, igt_output_t *output)
{
    (void)fd;
    (void)output;
    return true;
}

igt_subtest_with_dynamic("dsc-plus-normal-dual") {
    bool (*preds[])(int, igt_output_t *) = {
        dsc_capable,
        any_connected,
    };
    igt_output_t *outs[2];
    igt_combo_iter_t iter;

    for_each_output_combo(&data.display, &iter, outs, 2, preds) {
        igt_dynamic_f("%s-%s", outs[0]->name, outs[1]->name) {
            igt_debugfs_guard_t dsc_guard;
            igt_fb_t fb[2];

            igt_intel_dsc_guard_begin(data.drm_fd, outs[0], &dsc_guard);
            force_dsc_enable(data.drm_fd, outs[0]);

            igt_output_setup_fb(data.drm_fd, outs[0],
                DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb[0]);
            igt_output_setup_fb(data.drm_fd, outs[1],
                DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb[1]);

            igt_assert(igt_bw_safe_commit(&data.display));
            igt_assert(igt_is_dsc_enabled(data.drm_fd, outs[0]->name));

            igt_remove_fb(data.drm_fd, &fb[0]);
            igt_remove_fb(data.drm_fd, &fb[1]);
            igt_intel_dsc_guard_end(&dsc_guard);
        }
    }
}
```

---

### What New Tests Become Possible

| Test | Outputs | Features | Key API Used |
|------|---------|----------|-------------|
| DSC + Big Joiner | 1 | DSC, Joiner | `for_each_connected_output_where` + `igt_allocate_pipes` |
| HDR + DSC + Joiner | 1 | HDR, DSC, Joiner | Composed predicates |
| Dual-output DSC Joiner + Normal | 2 | DSC, Joiner | `igt_multi_output_setup()` |
| Dual-output VRR + AsyncFlip | 2 | VRR | `for_each_output_combo()` |
| PSR + FBC Dual-Pipe | 2 | PSR, FBC | `igt_multi_output_setup()` |
| Ultra Joiner + DSC | 1 | DSC, Ultra Joiner | `igt_find_joiner_mode(ULTRA_JOINER)` |
| DSC BPC sweep + Joiner | 1 | DSC, Joiner | Predicate + existing BPC API |
## Implementation Roadmap

Each patch series is independently buildable and landable.

### Series 1: Pipe Allocator Foundation (6 patches)

| # | Patch | What it does |
|---|-------|-------------|
| P01 | `lib/igt_kms: add igt_get_valid_pipe_mask()` | Bitmask of non-fused pipes |
| P02 | `lib/igt_kms: add igt_get_master_pipe_mask()` | Valid joiner master pipes |
| P03 | `lib/igt_kms: cache pipe masks in igt_display_t` | Compute at init, add fields |
| P04 | `lib/igt_kms: promote find_consecutive_pipes()` | Move from kms_joiner_helper.c to lib |
| P05 | `lib/igt_kms: add igt_modeset_intent + compute_required_pipes()` | Intent-based pipe computation (dotclock + hdisplay) |
| P06 | `lib/igt_kms: add igt_check/apply/allocate_pipes()` | Split allocator: pure feasibility check + apply + convenience wrapper |

### Series 2: Feature Predicates (8 patches)

| # | Patch | What it does |
|---|-------|-------------|
| P07 | `lib: add igt_kms_feature.h/c skeleton` | New files with build integration |
| P08 | `lib/igt_kms_feature: add igt_output_has_dsc()` | Silent DSC predicate + check + require (function) |
| P09 | `lib/igt_kms_feature: promote igt_is_hdr_panel()` | Move from tests/kms_hdr.c to lib |
| P10 | `lib/igt_kms_feature: add igt_output_has_hdr()` | HDR predicate |
| P11 | `lib/igt_kms_feature: promote igt_output_get_vrr_range()` | Move from tests/kms_vrr.c |
| P12 | `lib/igt_kms_feature: add igt_output_has_vrr()` | VRR predicate |
| P13 | `lib/igt_kms_feature: add igt_output_has_psr()` | PSR predicate with mode param |
| P14 | `lib/igt_kms_feature: add remaining predicates` | FBC (as `igt_pipe_has_fbc`), DRRS, content protection |

### Series 3: Composition & Convenience (5 patches)

| # | Patch | What it does |
|---|-------|-------------|
| P15 | `lib/igt_kms: add for_each_connected_output_where()` | Filtered iteration macro |
| P16 | `lib/igt_kms: add igt_classify_outputs()` | Output classifier + find + count |
| P17 | `lib/igt_kms: add igt_output_setup_fb()` | FB + primary plane one-liner |
| P18 | `lib/igt_kms_feature: add mode finders` | joiner/hdr/vrr mode finders (hdisplay-aware) |
| P19 | `lib/igt_kms_feature: add require functions` | igt_output_require_dsc/hdr/vrr/psr (functions only, no macros) |

### Series 4: Safety Infrastructure (3 patches)

| # | Patch | What it does |
|---|-------|-------------|
| P20 | `lib/igt_kms: add igt_bw_safe_commit()` | BW-safe commit wrapper |
| P21 | `lib/igt_kms_feature: add debugfs guard API` | Generic begin/end + once-only exit handler, uses `igt_debugfs_simple_read/write` |
| P22 | `lib/igt_kms_feature: add igt_intel_dsc/joiner guard` | Intel-namespaced guards |

### Series 5: Multi-Output Builder (3 patches)

| # | Patch | What it does |
|---|-------|-------------|
| P23 | `lib/igt_kms: add spec/ctx structs` | Data structures for multi-output |
| P24 | `lib/igt_kms: add builder steps` | find/select_modes/allocate/create_fbs/validate |
| P25 | `lib/igt_kms: add for_each_output_combo()` | Combo iteration with caller-allocated iter + backtracking cursors |

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

- **No RAII or scope-based cleanup.** All state management uses explicit
  `begin`/`end` pairs, compatible with IGT's `setjmp`/`longjmp` model.

- **No global/static macro state.** Combo iteration uses caller-allocated
  iterators with proper backtracking cursors.

- **No wrappers for single-property checks.** `igt_crtc_has_prop(crtc,
  IGT_CRTC_DEGAMMA_LUT)` is already the right API.

- **No unified enable/disable API.** Existing per-feature enable APIs stay.

- **No modification to `__igt_pipe_populate_outputs()`.** The new allocator
  is separate and opt-in.

- **No constraint solver.** Greedy allocation with priority sorting.

---

## Quick Reference â€” All New API

### Feature Predicates (`lib/igt_kms_feature.h`)

```
igt_output_has_dsc(fd, output)          â€” silent bool
igt_output_has_hdr(fd, output)          â€” silent bool
igt_output_has_vrr(fd, output)          â€” silent bool
igt_output_has_psr(fd, output, mode)    â€” silent bool
igt_pipe_has_fbc(fd, pipe)              â€” silent bool (pipe check)
igt_output_has_content_protection(fd, output) â€” silent bool
igt_output_has_drrs(fd, output)         â€” silent bool
igt_output_get_max_joiner(fd, output)   â†’ enum joined_pipes
igt_output_get_vrr_range(fd, output, &min, &max) â†’ bool
igt_output_has_force_joiner(fd, output) â€” silent bool
igt_source_has_dsc(fd)                  â€” silent bool
igt_source_has_joiner(fd)               â€” silent bool
igt_output_check_dsc(fd, output)        â†’ igt_feature_status_t
```

### Require Functions (`lib/igt_kms_feature.h`)

```
igt_output_require_dsc(fd, output)       â€” function, prints + skips
igt_output_require_hdr(fd, output)       â€” function, prints + skips
igt_output_require_vrr(fd, output)       â€” function, prints + skips
igt_output_require_psr(fd, output, mode) â€” function, prints + skips
```

### Mode Finders (`lib/igt_kms_feature.h`)

```
igt_find_joiner_mode(fd, output, level, &mode)     â†’ bool
igt_find_non_joiner_mode(fd, output, &mode)         â†’ bool
igt_find_hdr_mode(fd, output, &mode)                â†’ bool
igt_find_vrr_mode(fd, output, &mode)                â†’ bool
```

### Pipe Allocator (`lib/igt_kms.h`)

```
igt_compute_required_pipes(fd, output, &intent)     â†’ int (1/2/4)
igt_output_get_required_pipes(fd, output)            â†’ int (1/2/4)
igt_find_consecutive_pipes(n, avail, need)           â†’ int (pipe or -1)
igt_get_master_pipe_mask(display)                     â†’ uint32_t
igt_get_valid_pipe_mask(display)                      â†’ uint32_t
igt_check_pipe_assignment(display, outputs, n, master_pipes[])  â†’ int (0 or -1)
igt_apply_pipe_assignment(display, outputs, n, master_pipes[])   â€” sets CRTCs
igt_allocate_pipes(display, outputs, n, &used_pipes) â†’ int (0 or -1, check+apply)
```

### Output Utilities (`lib/igt_kms.h`)

```
igt_classify_outputs(display, fd, pred, match, &m, nomatch, &nm)
igt_find_output_with(display, fd, pred)               â†’ igt_output_t *
igt_count_outputs_with(display, fd, pred)             â†’ int
igt_output_setup_fb(fd, output, fmt, mod, &fb)        â†’ igt_plane_t *
```

### Commit Helpers (`lib/igt_kms.h`)

```
igt_bw_safe_commit(display)    â†’ bool
igt_try_bw_commit(display)     â†’ int (0 or errno)
```

### Multi-Output Builder (`lib/igt_kms.h`)

```
igt_multi_output_find(display, fd, specs, n, &ctx)        â†’ int
igt_multi_output_select_modes(&ctx)                        â†’ int
igt_multi_output_allocate_pipes(&ctx)                      â†’ int
igt_multi_output_create_fbs(&ctx)
igt_multi_output_validate_bw(&ctx)                         â†’ int
igt_multi_output_setup(display, fd, specs, n, &ctx)       â€” convenience
igt_multi_output_try_setup(display, fd, specs, n, &ctx)   â†’ int
igt_multi_output_commit(&ctx)
igt_multi_output_try_commit(&ctx)                          â†’ int
igt_multi_output_teardown(&ctx)
```

### Debugfs State Helpers (`lib/igt_kms_feature.h`)

```
igt_debugfs_guard_begin(fd, output, attr, &guard)
igt_debugfs_guard_end(&guard)
igt_intel_dsc_guard_begin(fd, output, &guard)     â€” Intel-namespaced
igt_intel_dsc_guard_end(&guard)
igt_intel_joiner_guard_begin(fd, output, &guard)  â€” Intel-namespaced
igt_intel_joiner_guard_end(&guard)
```

### Macros (`lib/igt_kms.h`)

```
for_each_connected_output_where(display, output, pred)
for_each_pipe_output_combo(display, crtc, output)
for_each_output_combo(display, &iter, outputs, n, preds)
```
