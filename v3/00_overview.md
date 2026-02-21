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
together. The diagram below shows the layers from bottom (foundational) to top
(highest-level composition).

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           Test Code                                      │
│                                                                          │
│  igt_subtest("dsc-joiner-dual-output") {                                │
│      for_each_connected_output_where(display, output,                    │
│              igt_output_has_dsc(fd, output) &&                           │
│              igt_output_get_max_joiner(fd, output) >= BIG_JOINER)        │
│      { ... }                                                             │
│  }                                                                       │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Layer 8: Convenience Helpers                                            │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │ igt_output_setup_fb(fd, output, format, modifier, &fb)         │      │
│  │ igt_find_joiner_mode(fd, output, level, &mode)                 │      │
│  └────────────────────────────────────────────────────────────────┘      │
│                                                                          │
│  Layer 7: Composition Macros                                             │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │ for_each_connected_output_where(display, output, pred)         │      │
│  │ for_each_pipe_output_combo(display, crtc, output)              │      │
│  │ for_each_output_combo(display, &iter, outputs[], n, preds[])   │      │
│  └────────────────────────────────────────────────────────────────┘      │
│                                                                          │
│  Layer 5: Debugfs State Helpers  │  Layer 6: Output Classifier           │
│  ┌───────────────────────────┐   │  ┌────────────────────────────┐       │
│  │ igt_intel_dsc_guard_begin │   │  │ igt_classify_outputs()     │       │
│  │ igt_intel_dsc_guard_end   │   │  │ igt_find_output_with()     │       │
│  │ igt_debugfs_guard_begin   │   │  │ igt_count_outputs_with()   │       │
│  └───────────────────────────┘   │  └────────────────────────────┘       │
│                                                                          │
│  Layer 4: BW-Safe Commit         │  Layer 3: Multi-Output Builder        │
│  ┌───────────────────────────┐   │  ┌────────────────────────────┐       │
│  │ igt_bw_safe_commit()      │   │  │ igt_multi_output_find()    │       │
│  │ igt_try_bw_commit()       │   │  │ igt_multi_output_setup()   │       │
│  └───────────────────────────┘   │  │ igt_multi_output_teardown()│       │
│                                  │  └────────────────────────────┘       │
│                                                                          │
│  Layer 2: Pipe Allocator                                                 │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │ igt_allocate_pipes()  igt_find_consecutive_pipes()              │      │
│  │ igt_compute_required_pipes()  igt_output_get_required_pipes()   │      │
│  └────────────────────────────────────────────────────────────────┘      │
│                                                                          │
│  Layer 1: Feature Detection Predicates                                   │
│  ┌────────────────────────────────────────────────────────────────┐      │
│  │ igt_output_has_dsc(fd, output)         — silent bool           │      │
│  │ igt_output_require_dsc(fd, output)     — skip with message     │      │
│  │ igt_output_has_hdr / vrr / psr / fbc                           │      │
│  │ igt_output_get_max_joiner(fd, output)                          │      │
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
  These are untouched — the new API sits alongside them, not on top.

- **Each layer is independently useful.** A test can use just the pipe allocator,
  or just the predicates, or just the output classifier. No forced buy-in.

- **100% backward compatible.** Purely additive. No existing test needs changes.
