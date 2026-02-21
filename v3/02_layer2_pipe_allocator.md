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

### Design: Compute pipe requirement from modeset intent, not cache it

Pipe requirement depends on more than just dotclock — it can vary with
BPC, DSC state, format, display width, and platform constraints. Caching a
single `required_pipes` value inside `igt_output_t` would become stale as
soon as the test changes format or DSC state.

Instead, pipe requirement is computed from an explicit **modeset intent**
structure that captures the relevant parameters:

```c
/**
 * igt_modeset_intent - Describes what determines joiner requirement
 *
 * Pass this to igt_compute_required_pipes() to get deterministic
 * pipe count. Only fields that directly affect the joiner decision
 * are included:
 *   - mode:       hdisplay vs max_pipe_width, clock vs max_dotclock
 *   - min_joiner: force a minimum joiner level regardless of mode
 *
 * DSC, BPC, format, and modifier are intentionally excluded. DSC
 * compression ratio varies by sink/driver and cannot be assumed.
 * BPC impact on clock is format-dependent. Joiner decisions are
 * based on hard display timing constraints only.
 */
struct igt_modeset_intent {
    drmModeModeInfo mode;         /* Target mode */
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
 * This is a pure function — its result depends only on the intent
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
/* ── Added to lib/igt_kms.h ──────────────────────────────────────── */

int igt_find_consecutive_pipes(int n_crtcs, uint32_t available_mask,
                               int need);

uint32_t igt_get_master_pipe_mask(igt_display_t *display);
uint32_t igt_get_valid_pipe_mask(igt_display_t *display);

/*
 * Split API: check feasibility without mutating state, then apply.
 * igt_check_pipe_assignment() is pure — safe for iteration loops.
 * igt_apply_pipe_assignment() sets CRTCs on outputs.
 * igt_allocate_pipes() is the combined convenience wrapper.
 *
 * Constraint: n_outputs must be in [1, IGT_MAX_PIPES].
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

### Implementation — `igt_compute_required_pipes()`

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

/* Simplified variant — mode-only check */
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

### Implementation — Pipe Mask Helpers

The pipe masks are computed once during `igt_display_require()` and cached in
`igt_display_t`. The computation uses `display->pipes[i].crtc_id` which is
already populated by DRM resource enumeration at that point.

All bitmask helpers use `uint32_t` and operate on pipe indices in the range
`[0, 31]`. A one-time assertion at init ensures this is safe:

```c
/*
 * All pipe bitmask operations assume n_pipes fits in 32 bits.
 * Assert once at init to prevent undefined behavior from BIT(p)
 * when p >= 32. Current hardware has at most 8 pipes.
 */
igt_assert_f(display->n_pipes <= 32,
             "n_pipes=%d exceeds bitmask width\n", display->n_pipes);
```

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

### Implementation — `igt_find_consecutive_pipes()`

For `need == 1` (no joiner), any available pipe works. For `need >= 2`
(big/ultra joiner), we verify that the full range `[p, p+need)` is valid and
available. The `master_pipe_mask` is used only for `need == 2` as a fast check;
for `need == 4` we check the full 4-pipe range directly.

```c
int igt_find_consecutive_pipes(int n_crtcs, uint32_t available_mask,
                               int need)
{
    /* Bounds safety: n_crtcs must fit in uint32_t bitmask */
    igt_assert(n_crtcs <= 32);
    igt_assert(need > 0 && need <= n_crtcs);

    if (need == 1) {
        for (int p = 0; p < n_crtcs; p++)
            if (available_mask & BIT(p))
                return p;
        return -1;
    }

    /*
     * For need >= 2: check that all pipes [p, p+need) are available.
     * The loop bound p <= n_crtcs - need ensures p + need - 1 < n_crtcs,
     * so BIT(p + k) for k < need is always within [0, n_crtcs - 1].
     */
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

### The Allocator — Split: Feasibility Check + Apply

The allocator is split into two explicit entry points:

1. **`igt_check_pipe_assignment()`** — Pure feasibility check. Computes
   which master pipe each output would be assigned to, but does NOT call
   `igt_output_set_crtc()` or mutate any display state. Returns the
   result in a caller-provided `master_pipes[]` array. This is safe to
   call from iteration loops, combo searches, and nested contexts.

2. **`igt_apply_pipe_assignment()`** — Applies the assignment computed by
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

    /*
     * Enforce upper bound: n_outputs cannot exceed pipe count.
     * Uses fixed-size arrays (no VLAs) to avoid stack overflow
     * and comply with -Wvla / MISRA guidelines.
     */
    igt_assert_f(n_outputs > 0 && n_outputs <= IGT_MAX_PIPES,
                 "n_outputs=%d out of range [1, %d]\n",
                 n_outputs, IGT_MAX_PIPES);

    /* Fixed-size arrays — no VLAs in library code */
    int requirements[IGT_MAX_PIPES];
    int order[IGT_MAX_PIPES];
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
    int master_pipes[IGT_MAX_PIPES];
    uint32_t avail = display->valid_pipe_mask;

    igt_assert_f(n_outputs > 0 && n_outputs <= IGT_MAX_PIPES,
                 "n_outputs=%d out of range [1, %d]\n",
                 n_outputs, IGT_MAX_PIPES);

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
