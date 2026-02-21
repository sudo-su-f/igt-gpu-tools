/*
 * test_multi_output.c — Layer 3: Multi-Output Builder + Layer 4: BW Commit
 *
 * Validates the step-by-step builder (find, select_modes, allocate_pipes,
 * create_fbs, validate_bw), convenience setup, and custom step usage.
 */

#include "igt_sandbox.h"

IGT_TEST_DESCRIPTION("Validate Layer 3 & 4: Multi-Output Builder + BW Commit");

static bool dsc_predicate(int fd, igt_output_t *output)
{
    return igt_output_has_dsc(fd, output);
}

static bool any_connected(int fd, igt_output_t *output)
{
    (void)fd; (void)output;
    return true;
}

static bool hdr_predicate(int fd, igt_output_t *output)
{
    return igt_output_has_hdr(fd, output);
}

/* Mode finders */
static bool find_4k_mode(int fd, igt_output_t *output, drmModeModeInfo *mode)
{
    int i;
    (void)fd;
    for (i = 0; i < output->n_modes; i++) {
        if (output->modes[i].hdisplay >= 3840) {
            memcpy(mode, &output->modes[i], sizeof(*mode));
            return true;
        }
    }
    return false;
}

static const sandbox_display_config_t multi_config = {
    .n_pipes = 4,
    .max_dotclock = 594000,
    .max_pipe_width = 5120,
    .n_outputs = 3,
    .outputs = {
        { .name = "DP-1", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = { .dsc_source = true, .dsc_sink = true, .fec = true,
                    .hdr_panel = true, .hdr_prop = true,
                    .max_joiner_level = 1 },
          .n_modes = 2,
          .modes = { { 3840, 2160, 594000 }, { 1920, 1080, 148500 } } },

        { .name = "HDMI-A-1", .connector_type = DRM_MODE_CONNECTOR_HDMIA,
          .connected = true,
          .caps = { .hdr_panel = true, .hdr_prop = true },
          .n_modes = 1,
          .modes = { { 1920, 1080, 148500 } } },

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

    _sandbox_init("test_multi_output");

    igt_fixture {
        sandbox_display_init(&display, &multi_config);
    }

    /* ── Convenience one-call setup ──────────────────────────── */

    igt_subtest("multi-output-convenience-setup") {
        igt_output_spec_t specs[] = {
            { .predicate = dsc_predicate },
            { .predicate = any_connected },
        };
        igt_multi_output_ctx_t ctx;

        igt_multi_output_setup(&display, fd, specs, 2, &ctx);

        igt_info("Spec[0]: %s (pipe %d)\n",
                 specs[0].output->name, specs[0].output->pipe);
        igt_info("Spec[1]: %s (pipe %d)\n",
                 specs[1].output->name, specs[1].output->pipe);

        igt_assert(specs[0].output != NULL);
        igt_assert(specs[1].output != NULL);
        igt_assert(specs[0].output != specs[1].output);

        igt_multi_output_teardown(&ctx);
    }

    /* ── Step-by-step builder ────────────────────────────────── */

    igt_subtest("multi-output-step-by-step") {
        igt_output_spec_t specs[] = {
            { .predicate = dsc_predicate, .find_mode = find_4k_mode,
              .format = DRM_FORMAT_XRGB2101010 },
            { .predicate = any_connected },
        };
        igt_multi_output_ctx_t ctx;

        /* Step 1: Find */
        igt_require(igt_multi_output_find(&display, fd,
                                           specs, 2, &ctx) == 0);
        igt_info("Step 1 - Find: %s + %s\n",
                 specs[0].output->name, specs[1].output->name);

        /* Step 2: Select modes */
        igt_require(igt_multi_output_select_modes(&ctx) == 0);
        igt_info("Step 2 - Modes: %dx%d + %dx%d\n",
                 specs[0].mode.hdisplay, specs[0].mode.vdisplay,
                 specs[1].mode.hdisplay, specs[1].mode.vdisplay);
        igt_assert(specs[0].mode.hdisplay == 3840);

        /* Step 3: Allocate pipes */
        igt_require(igt_multi_output_allocate_pipes(&ctx) == 0);
        igt_info("Step 3 - Pipes: %s→%d, %s→%d\n",
                 specs[0].output->name, specs[0].output->pipe,
                 specs[1].output->name, specs[1].output->pipe);

        /* Step 4: Create FBs */
        igt_multi_output_create_fbs(&ctx);
        igt_assert(specs[0].fb.valid);
        igt_assert(specs[0].fb.format == DRM_FORMAT_XRGB2101010);
        igt_info("Step 4 - FBs: %dx%d fmt=0x%x\n",
                 specs[0].fb.width, specs[0].fb.height, specs[0].fb.format);

        /* Step 5: Validate BW */
        igt_require(igt_multi_output_validate_bw(&ctx) == 0);
        igt_info("Step 5 - BW validated\n");

        igt_multi_output_commit(&ctx);
        igt_multi_output_teardown(&ctx);
    }

    /* ── Manual output override ──────────────────────────────── */

    igt_subtest("multi-output-manual-override") {
        igt_output_spec_t specs[] = {
            { .predicate = any_connected,
              .output = &display.outputs[2] }, /* Force eDP-1 */
            { .predicate = any_connected },
        };
        igt_multi_output_ctx_t ctx;

        igt_require(igt_multi_output_find(&display, fd,
                                           specs, 2, &ctx) == 0);
        /* Spec[0] should be eDP-1 (manually set) */
        igt_assert(specs[0].output == &display.outputs[2]);
        igt_info("Manual override: spec[0] = %s\n", specs[0].output->name);

        igt_multi_output_teardown(&ctx);
    }

    /* ── try_setup failure case ───────────────────────────────── */

    igt_subtest("multi-output-impossible") {
        /* Ask for 3 DSC outputs but only 2 exist */
        igt_output_spec_t specs[] = {
            { .predicate = dsc_predicate },
            { .predicate = dsc_predicate },
            { .predicate = dsc_predicate },
        };
        igt_multi_output_ctx_t ctx;
        int ret = igt_multi_output_try_setup(&display, fd, specs, 3, &ctx);
        igt_info("Impossible setup: ret=%d (expect -1)\n", ret);
        igt_assert(ret < 0);
    }

    /* ── BW-safe commit ──────────────────────────────────────── */

    igt_subtest("bw-safe-commit") {
        igt_fb_t fb;
        igt_output_set_crtc(&display.outputs[0], PIPE_A);
        igt_output_setup_fb(fd, &display.outputs[0],
                            DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb);

        igt_assert(igt_bw_safe_commit(&display));
        igt_info("BW-safe commit succeeded\n");

        igt_remove_fb(fd, &fb);
    }

    igt_fixture {
        sandbox_display_fini(&display);
    }

    _sandbox_exit();
}
