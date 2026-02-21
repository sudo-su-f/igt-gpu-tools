## Layer 4 — Bandwidth-Safe Commit

### What this is

A commit wrapper that validates bandwidth before the real atomic commit.
It builds on **existing IGT infrastructure** — specifically
`igt_fit_modes_in_bw()` which is already upstream and used by tests today.

### Behavior details

1. **TEST_ONLY validation:** `igt_fit_modes_in_bw()` internally does a
   `DRM_MODE_ATOMIC_TEST_ONLY` commit. If it returns `ENOSPC`, it calls
   `igt_override_all_active_output_modes_to_fit_bw()` to try lower modes,
   then retries. This is existing IGT behavior — we don't change it.

2. **Mode mutation:** `igt_bw_safe_commit()` **may downscale modes** if
   bandwidth is tight. The caller should be aware that output modes can
   change after this call. If the test needs the exact requested mode,
   use `igt_try_bw_commit()` + manual handling instead.

3. **Non-Intel drivers:** `igt_bw_safe_commit()` is explicitly gated by
   `is_i915_device()` / `is_xe_device()`. On non-Intel drivers, the BW
   fitting step is skipped entirely and a normal atomic commit is done.
   This makes the Intel-specific dependency explicit in the code path
   rather than relying on behavioral differences in TEST_ONLY results.

4. **Return semantics:**
   - `igt_bw_safe_commit()` returns `false` only if BW fitting completely
     fails (couldn't find modes that fit). On success, commits atomically.
   - `igt_try_bw_commit()` is the raw `try_commit2` — no BW fitting,
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
 * Intel-specific: explicitly gated by is_i915_device()/is_xe_device().
 * On non-Intel drivers, skips BW fitting and does a normal atomic commit.
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
    /*
     * igt_fit_modes_in_bw() depends on i915/xe ENOSPC signaling.
     * On non-Intel, skip BW fitting — just do normal commit.
     */
    if (is_i915_device(display->drm_fd) ||
        is_xe_device(display->drm_fd)) {
        if (!igt_fit_modes_in_bw(display))
            return false;
    }
    igt_display_commit2(display, COMMIT_ATOMIC);
    return true;
}

int igt_try_bw_commit(igt_display_t *display)
{
    return igt_display_try_commit2(display, COMMIT_ATOMIC);
}
```
