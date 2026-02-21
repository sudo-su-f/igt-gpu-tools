## Layer 3 — Multi-Output Setup Builder

### What this is

A step-by-step builder API that handles the lifecycle of a multi-output
test configuration. Unlike a monolithic "one call does everything" orchestrator,
each step is an explicit function call that the test author can see, skip,
or replace.

### Design: Explicit steps, not magic

The builder is deliberately **not opaque**. Each step does one thing:

1. **Find** — match outputs to specs using predicates
2. **Select modes** — call mode finders or use defaults
3. **Allocate pipes** — joiner-aware pipe assignment
4. **Create FBs** — framebuffers matching mode dimensions
5. **Validate BW** — TEST_ONLY commit to check bandwidth

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
    /* ── Filled by test author ── */

    /* Required: returns true for outputs that match */
    bool (*predicate)(int fd, igt_output_t *output);

    /* Optional: finds a specific mode. NULL = use default mode */
    bool (*find_mode)(int fd, igt_output_t *output, drmModeModeInfo *mode);

    /* Optional: pixel format. 0 = XRGB8888 */
    uint32_t format;

    /* Optional: FB modifier. 0 = LINEAR */
    uint64_t modifier;

    /* ── Filled by builder ── */

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
 * skips that spec — allowing manual output selection.
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
 * This IS the "one call" variant — but it calls the explicit steps
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

### Teardown Contract

`igt_multi_output_teardown()` is responsible for cleaning up all resources
allocated by the builder steps. The contract:

1. **Framebuffers:** Removes all FBs created by `igt_multi_output_create_fbs()`.
   Uses `igt_remove_fb()` for each spec that has a valid `fb.fb_id`.
2. **Pipe assignments:** Resets `igt_output_set_pipe(output, PIPE_NONE)` for
   each matched output, releasing the pipe for other tests.
3. **Mode overrides:** Clears mode overrides set by `select_modes`.
4. **Context state:** Zeros the `igt_multi_output_ctx_t`, resetting
   `used_pipes`, `committed`, and all spec output pointers.

**What it does NOT do:**

- Close the DRM fd or free the `igt_display_t` (caller's responsibility)
- Restore debugfs state (that's the guard's responsibility — Layer 5)
- Free the `igt_output_spec_t` array (caller-allocated, typically on stack)

**Idempotency:** Safe to call multiple times. Second call is a no-op
(all FBs already removed, all pipes already released, all pointers NULL).

**When to call:** Always — even on failure paths. If `try_setup` returns
failure, it calls teardown internally. But if the caller uses individual
builder steps and one fails mid-way, the caller must call teardown explicitly.

### Implementation — `igt_multi_output_try_setup` as builder

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

### Usage Example — Custom setup with fine control

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

    /* Custom FB setup — skip the standard create_fbs */
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

### Usage Example — Convenience (one-call)

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
