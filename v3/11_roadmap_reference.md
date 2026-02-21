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

## Quick Reference — All New API

### Feature Predicates (`lib/igt_kms_feature.h`)

```
igt_output_has_dsc(fd, output)          — silent bool
igt_output_has_hdr(fd, output)          — silent bool
igt_output_has_vrr(fd, output)          — silent bool
igt_output_has_psr(fd, output, mode)    — silent bool
igt_pipe_has_fbc(fd, pipe)              — silent bool (pipe check)
igt_output_has_content_protection(fd, output) — silent bool
igt_output_has_drrs(fd, output)         — silent bool
igt_output_get_max_joiner(fd, output)   → enum joined_pipes
igt_output_get_vrr_range(fd, output, &min, &max) → bool
igt_output_has_force_joiner(fd, output) — silent bool
igt_source_has_dsc(fd)                  — silent bool
igt_source_has_joiner(fd)               — silent bool
igt_output_check_dsc(fd, output)        → igt_feature_status_t
```

### Require Functions (`lib/igt_kms_feature.h`)

```
igt_output_require_dsc(fd, output)       — function, prints + skips
igt_output_require_hdr(fd, output)       — function, prints + skips
igt_output_require_vrr(fd, output)       — function, prints + skips
igt_output_require_psr(fd, output, mode) — function, prints + skips
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
igt_compute_required_pipes(fd, output, &intent)     → int (1/2/4)
igt_output_get_required_pipes(fd, output)            → int (1/2/4)
igt_find_consecutive_pipes(n, avail, need)           → int (pipe or -1)
igt_get_master_pipe_mask(display)                     → uint32_t
igt_get_valid_pipe_mask(display)                      → uint32_t
igt_check_pipe_assignment(display, outputs, n, master_pipes[])  → int (0 or -1)
igt_apply_pipe_assignment(display, outputs, n, master_pipes[])   — sets CRTCs
igt_allocate_pipes(display, outputs, n, &used_pipes) → int (0 or -1, check+apply)
```

### Output Utilities (`lib/igt_kms.h`)

```
igt_classify_outputs(display, fd, pred, match, &m, nomatch, &nm)
igt_find_output_with(display, fd, pred)               → igt_output_t *
igt_count_outputs_with(display, fd, pred)             → int
igt_output_setup_fb(fd, output, fmt, mod, &fb)        → igt_plane_t *
```

### Commit Helpers (`lib/igt_kms.h`)

```
igt_bw_safe_commit(display)    → bool
igt_try_bw_commit(display)     → int (0 or errno)
```

### Multi-Output Builder (`lib/igt_kms.h`)

```
igt_multi_output_find(display, fd, specs, n, &ctx)        → int
igt_multi_output_select_modes(&ctx)                        → int
igt_multi_output_allocate_pipes(&ctx)                      → int
igt_multi_output_create_fbs(&ctx)
igt_multi_output_validate_bw(&ctx)                         → int
igt_multi_output_setup(display, fd, specs, n, &ctx)       — convenience
igt_multi_output_try_setup(display, fd, specs, n, &ctx)   → int
igt_multi_output_commit(&ctx)
igt_multi_output_try_commit(&ctx)                          → int
igt_multi_output_teardown(&ctx)
```

### Debugfs State Helpers (`lib/igt_kms_feature.h`)

```
igt_debugfs_guard_begin(fd, output, attr, &guard)
igt_debugfs_guard_end(&guard)
igt_intel_dsc_guard_begin(fd, output, &guard)     — Intel-namespaced
igt_intel_dsc_guard_end(&guard)
igt_intel_joiner_guard_begin(fd, output, &guard)  — Intel-namespaced
igt_intel_joiner_guard_end(&guard)
```

### Macros (`lib/igt_kms.h`)

```
for_each_connected_output_where(display, output, pred)
for_each_pipe_output_combo(display, crtc, output)
for_each_output_combo(display, &iter, outputs, n, preds)
```
