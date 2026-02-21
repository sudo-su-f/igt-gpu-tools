/*
 * test_debugfs_guard.c — Layer 5: Debugfs State Helpers
 *
 * Demonstrates:
 *   - Explicit begin/end pattern
 *   - Exit handler safety net (registered once)
 *   - Intel-namespaced wrappers (igt_intel_dsc_guard)
 *   - Proves cleanup works even when longjmp skips the body
 */

#include "igt_sandbox.h"

IGT_TEST_DESCRIPTION("Validate Layer 5: Debugfs Guard begin/end + exit handler");

static const sandbox_display_config_t guard_config = {
    .n_pipes = 4,
    .max_dotclock = 594000,
    .max_pipe_width = 5120,
    .n_outputs = 2,
    .outputs = {
        { .name = "DP-1", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = { .dsc_source = true, .dsc_sink = true, .fec = true },
          .n_modes = 1,
          .modes = { { 3840, 2160, 594000 } } },

        { .name = "eDP-1", .connector_type = DRM_MODE_CONNECTOR_eDP,
          .connected = true, .is_internal = true,
          .caps = { .dsc_source = true, .dsc_sink = true },
          .n_modes = 1,
          .modes = { { 2560, 1440, 241500 } } },
    },
};

igt_main
{
    igt_display_t display;
    int fd = SANDBOX_FD;

    _sandbox_init("test_debugfs_guard");

    igt_fixture {
        sandbox_display_init(&display, &guard_config);
    }

    /* ── Normal begin/end pattern ────────────────────────────── */

    igt_subtest("guard-normal-begin-end") {
        igt_debugfs_guard_t guard;

        igt_intel_dsc_guard_begin(fd, &display.outputs[0], &guard);
        igt_assert(guard.active);

        /* Modify state */
        force_dsc_enable(fd, &display.outputs[0]);
        igt_assert(display.outputs[0].dsc_enabled);

        /* Restore state */
        igt_intel_dsc_guard_end(&guard);
        igt_assert(!guard.active);
        /* State should be restored to original "0" */
        igt_info("DSC state after guard_end: %s (expect 0)\n",
                 display.outputs[0].debugfs_dsc_state);
    }

    /* ── Double-end is safe ──────────────────────────────────── */

    igt_subtest("guard-double-end-safe") {
        igt_debugfs_guard_t guard;

        igt_intel_dsc_guard_begin(fd, &display.outputs[0], &guard);
        igt_intel_dsc_guard_end(&guard);
        igt_intel_dsc_guard_end(&guard); /* Should be a no-op */
        igt_info("Double-end did not crash\n");
    }

    /* ── Joiner guard ────────────────────────────────────────── */

    igt_subtest("joiner-guard-begin-end") {
        igt_debugfs_guard_t guard;

        igt_intel_joiner_guard_begin(fd, &display.outputs[0], &guard);
        igt_assert(guard.active);
        igt_assert(strcmp(guard.attr_name,
                   "i915_bigjoiner_force_enable") == 0);

        igt_intel_joiner_guard_end(&guard);
        igt_assert(!guard.active);
    }

    /* ── Multiple guards on different outputs ────────────────── */

    igt_subtest("multi-output-guards") {
        igt_debugfs_guard_t dsc_guard, joiner_guard;

        igt_intel_dsc_guard_begin(fd, &display.outputs[0], &dsc_guard);
        igt_intel_joiner_guard_begin(fd, &display.outputs[1], &joiner_guard);

        igt_assert(dsc_guard.active);
        igt_assert(joiner_guard.active);

        force_dsc_enable(fd, &display.outputs[0]);

        igt_intel_dsc_guard_end(&dsc_guard);
        igt_intel_joiner_guard_end(&joiner_guard);

        igt_assert(!dsc_guard.active);
        igt_assert(!joiner_guard.active);
    }

    /* ── Simulate longjmp scenario (skip inside guarded region) ─ */

    igt_subtest_with_dynamic("guard-longjmp-safety") {
        igt_dynamic_f("skip-inside-guard") {
            igt_debugfs_guard_t guard;

            igt_intel_dsc_guard_begin(fd, &display.outputs[0], &guard);
            force_dsc_enable(fd, &display.outputs[0]);

            /*
             * This igt_require will longjmp, simulating how IGT
             * handles igt_assert/igt_require failures. The guard_end
             * below never runs — but the exit handler registered by
             * guard_begin will clean up at process exit.
             *
             * This is THE fundamental reason we use begin/end + exit
             * handler instead of RAII/__attribute__((cleanup)):
             * after longjmp, cleanup attributes do NOT fire.
             */
            igt_require(false);

            /* This line is never reached */
            igt_intel_dsc_guard_end(&guard);
        }

        igt_dynamic_f("normal-after-skip") {
            igt_debugfs_guard_t guard;

            igt_intel_dsc_guard_begin(fd, &display.outputs[1], &guard);
            igt_info("Guard active on %s after previous skip\n",
                     display.outputs[1].name);
            igt_intel_dsc_guard_end(&guard);
        }
    }

    /* ── Generic guard with custom attribute ──────────────────── */

    igt_subtest("generic-guard-custom-attr") {
        igt_debugfs_guard_t guard;

        igt_debugfs_guard_begin(fd, &display.outputs[0],
                                "i915_custom_test_attr", &guard);
        igt_assert(guard.active);
        igt_assert(strcmp(guard.attr_name, "i915_custom_test_attr") == 0);

        igt_debugfs_guard_end(&guard);
    }

    igt_fixture {
        sandbox_display_fini(&display);
    }

    _sandbox_exit();
}
