/*
 * test_predicates.c — Layer 1: Feature Detection Predicates
 *
 * Validates that silent predicates, require variants, and rich status
 * checks work correctly with the configurable display simulation.
 */

#include "igt_sandbox.h"

IGT_TEST_DESCRIPTION("Validate Layer 1: Feature Detection Predicates");

/*
 * Simulated hardware: 4 pipes, 4 outputs with varying capabilities.
 *
 *   DP-1:    DSC(src+sink+fec), HDR, VRR, Big Joiner — full featured
 *   HDMI-A-1: No DSC (no FEC), HDR, no VRR — partial
 *   eDP-1:   DSC(src+sink, internal—no FEC needed), PSR, DRRS — laptop panel
 *   DP-2:    No DSC (no sink), no HDR — minimal
 */
static const sandbox_display_config_t test_config = {
    .n_pipes = 4,
    .max_dotclock = 594000,
    .max_pipe_width = 5120,
    .n_outputs = 4,
    .outputs = {
        { .name = "DP-1", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = { .dsc_source = true, .dsc_sink = true, .fec = true,
                    .hdr_panel = true, .hdr_prop = true,
                    .vrr_capable = true, .vrr_min_hz = 48, .vrr_max_hz = 144,
                    .max_joiner_level = 1, .force_joiner = true },
          .n_modes = 2,
          .modes = { { 3840, 2160, 594000 }, { 1920, 1080, 148500 } } },

        { .name = "HDMI-A-1", .connector_type = DRM_MODE_CONNECTOR_HDMIA,
          .connected = true,
          .caps = { .dsc_source = true, .dsc_sink = true, .fec = false,
                    .hdr_panel = true, .hdr_prop = true },
          .n_modes = 1,
          .modes = { { 1920, 1080, 148500 } } },

        { .name = "eDP-1", .connector_type = DRM_MODE_CONNECTOR_eDP,
          .connected = true, .is_internal = true,
          .caps = { .dsc_source = true, .dsc_sink = true, .fec = false,
                    .psr = true, .fbc = true, .drrs = true },
          .n_modes = 1,
          .modes = { { 2560, 1440, 241500 } } },

        { .name = "DP-2", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = { .dsc_source = true, .dsc_sink = false, .fec = true },
          .n_modes = 1,
          .modes = { { 1920, 1080, 148500 } } },
    },
};

igt_main
{
    igt_display_t display;
    int fd = SANDBOX_FD;

    _sandbox_init("test_predicates");

    igt_fixture {
        sandbox_display_init(&display, &test_config);
    }

    /* ── Silent predicate checks ─────────────────────────────── */

    igt_subtest("dsc-predicate-silent") {
        /* DP-1: full DSC support → true */
        igt_assert(igt_output_has_dsc(fd, &display.outputs[0]));
        /* HDMI-A-1: DSC source+sink but no FEC, external → false */
        igt_assert(!igt_output_has_dsc(fd, &display.outputs[1]));
        /* eDP-1: internal, no FEC needed → true */
        igt_assert(igt_output_has_dsc(fd, &display.outputs[2]));
        /* DP-2: no DSC sink → false */
        igt_assert(!igt_output_has_dsc(fd, &display.outputs[3]));
    }

    igt_subtest("hdr-predicate-silent") {
        igt_assert(igt_output_has_hdr(fd, &display.outputs[0]));
        igt_assert(igt_output_has_hdr(fd, &display.outputs[1]));
        igt_assert(!igt_output_has_hdr(fd, &display.outputs[2]));
        igt_assert(!igt_output_has_hdr(fd, &display.outputs[3]));
    }

    igt_subtest("vrr-predicate-silent") {
        int min_hz, max_hz;
        igt_assert(igt_output_has_vrr(fd, &display.outputs[0]));
        igt_assert(!igt_output_has_vrr(fd, &display.outputs[1]));
        igt_assert(igt_output_get_vrr_range(fd, &display.outputs[0],
                                             &min_hz, &max_hz));
        igt_assert(min_hz == 48 && max_hz == 144);
    }

    igt_subtest("psr-predicate-silent") {
        igt_assert(igt_output_has_psr(fd, &display.outputs[2], PSR_MODE_1));
        igt_assert(!igt_output_has_psr(fd, &display.outputs[0], PSR_MODE_1));
    }

    igt_subtest("joiner-level") {
        igt_assert(igt_output_get_max_joiner(fd, &display.outputs[0])
                   >= JOINED_PIPES_BIG_JOINER);
        igt_assert(igt_output_get_max_joiner(fd, &display.outputs[1])
                   == JOINED_PIPES_NONE);
    }

    igt_subtest("fbc-is-pipe-check") {
        /* igt_pipe_has_fbc uses pipe, not output — correct naming */
        igt_output_set_crtc(&display.outputs[2], PIPE_A);
        igt_assert(igt_pipe_has_fbc(fd, PIPE_A));
    }

    /* ── Rich status check ───────────────────────────────────── */

    igt_subtest("dsc-rich-status") {
        igt_assert(igt_output_check_dsc(fd, &display.outputs[0])
                   == IGT_FEATURE_OK);
        igt_assert(igt_output_check_dsc(fd, &display.outputs[1])
                   == IGT_FEATURE_NO_FEC);
        igt_assert(igt_output_check_dsc(fd, &display.outputs[3])
                   == IGT_FEATURE_NO_SINK);
    }

    /* ── Require variant (prints + skips) ────────────────────── */

    igt_subtest("require-dsc-on-supported-output") {
        /* Should NOT skip — DP-1 has DSC */
        igt_output_require_dsc(fd, &display.outputs[0]);
        igt_info("igt_output_require_dsc passed (did not skip)\n");
    }

    igt_subtest("require-dsc-on-unsupported-output") {
        /* Should SKIP — DP-2 has no DSC sink */
        igt_output_require_dsc(fd, &display.outputs[3]);
        /* If we reach here, require didn't work */
        igt_assert(false);
    }

    /* ── Source-level checks ─────────────────────────────────── */

    igt_subtest("source-has-dsc") {
        igt_assert(igt_source_has_dsc(fd));
    }

    igt_subtest("source-has-joiner") {
        igt_assert(igt_source_has_joiner(fd));
    }

    /* ── for_each_connected_output_where ─────────────────────── */

    igt_subtest_with_dynamic("dsc-outputs-enumeration") {
        igt_output_t *output;
        for_each_connected_output_where(&display, output,
                igt_output_has_dsc(fd, output)) {
            igt_dynamic_f("%s", output->name) {
                igt_info("Output %s has DSC support\n", output->name);
            }
        }
    }

    igt_fixture {
        sandbox_display_fini(&display);
    }

    _sandbox_exit();
}
