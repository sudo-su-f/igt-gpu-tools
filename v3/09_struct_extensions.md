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
There are no ABI constraints — this is userspace-only, not a kernel UAPI.

> **Note:** `igt_output_t` is **not modified**. Pipe requirements are computed
> on-demand from `igt_modeset_intent` or from the output's current mode via
> `igt_output_get_required_pipes()`. No cached `required_pipes` field — the
> value is always fresh.
