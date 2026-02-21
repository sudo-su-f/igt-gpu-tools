# Sandbox — KMS Test Architecture Validation

Self-contained sandbox that validates and showcases the proposed 8-layer
KMS test architecture. No real GPU or DRM device required — all hardware
is simulated.

## Quick Start (Linux / WSL)

```bash
# Option 1: Make (recommended for quick testing)
make && make test

# Option 2: Meson
meson setup builddir
meson compile -C builddir
meson test -C builddir -v
```

## What This Demonstrates

| Test File | Layers | What It Proves |
|-----------|--------|----------------|
| `test_predicates` | L1 | Silent predicates, require variants (skip via longjmp), rich status, `for_each_connected_output_where` |
| `test_pipe_alloc` | L2 | Pipe masks, dotclock+hdisplay joiner detection, ultra joiner (4-pipe), intent-based computation, priority sorting |
| `test_multi_output` | L3, L4 | Step-by-step builder, convenience setup, manual override, try_setup failure, BW-safe commit |
| `test_debugfs_guard` | L5 | begin/end pattern, Intel-namespaced wrappers, longjmp safety net, double-end idempotency |
| `test_combo_iterator` | L7 | Backtracking correctness, no repeated combos, 2/3-slot enumeration, caller-allocated state, dynamic subtests |
| `test_full_examples` | L6, L8, All | Classifier, convenience helpers, DSC+BigJoiner, dual-output, triple-feature, ultra joiner, VRR |

## Configurable Simulation

Each test creates its own hardware topology:

```c
static const sandbox_display_config_t config = {
    .n_pipes = 6,                    // Number of pipes (A-F)
    .pipe_fused_off = { [4] = true }, // Fuse off pipe E
    .max_dotclock = 594000,          // kHz — joiner threshold
    .max_pipe_width = 5120,          // pixels — width-based joiner
    .n_outputs = 3,
    .outputs = {
        { .name = "DP-1",
          .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = {
              .dsc_source = true, .dsc_sink = true, .fec = true,
              .hdr_panel = true, .hdr_prop = true,
              .max_joiner_level = 1, // big joiner
          },
          .n_modes = 2,
          .modes = { { 3840, 2160, 594000 }, { 1920, 1080, 148500 } },
        },
        // ... more outputs ...
    },
};
```

## Output Format

Matches IGT's stdout format:

```
IGT-Version: sandbox-1.0
Starting test: test_predicates

  Starting subtest: dsc-predicate-silent
  Subtest dsc-predicate-silent: SUCCESS

  Starting subtest: require-dsc-on-unsupported-output
  Subtest require-dsc-on-unsupported-output: SKIP (DSC: ...)

  Starting subtest: dsc-outputs-enumeration
    Starting dynamic subtest: DP-1
    Dynamic subtest: SUCCESS
    Starting dynamic subtest: eDP-1
    Dynamic subtest: SUCCESS
  Subtest dsc-outputs-enumeration: SUCCESS (2 passed, 0 skipped, 0 failed)

=== Results for test_predicates ===
  Passed: 10
  Skipped: 1
  Failed: 0
  Total:  11
```

## File Structure

```
sandbox-concurrency-arch/
├── meson.build              # Root build
├── Makefile                 # GNU Make alternative
├── README.md
├── lib/
│   ├── meson.build
│   ├── igt_sandbox.h        # All types + API declarations
│   └── igt_sandbox.c        # All implementations
└── tests/
    ├── meson.build
    ├── test_predicates.c     # Layer 1
    ├── test_pipe_alloc.c     # Layer 2
    ├── test_multi_output.c   # Layers 3+4
    ├── test_debugfs_guard.c  # Layer 5
    ├── test_combo_iterator.c # Layer 7
    └── test_full_examples.c  # Layers 6+8 + full examples
```
