/*
 * test_full_examples.c — Full End-to-End Test Examples
 *
 * Covers:
 *   - Layer 6: Output classifier
 *   - Layer 8: Convenience helpers (setup_fb, mode finders)
 *   - Full example: DSC + Big Joiner
 *   - Full example: Dual output (DSC + Normal)
 *   - Full example: Triple feature (HDR + DSC + Big Joiner)
 *   - Full example: Ultra Joiner
 *   - Full example: VRR + Async Flip (dual)
 */

#include "igt_sandbox.h"

IGT_TEST_DESCRIPTION("Full end-to-end examples showcasing all layers");

static bool dsc_capable(int fd, igt_output_t *output)
{
    return igt_output_has_dsc(fd, output);
}

static bool any_connected(int fd, igt_output_t *output)
{
    (void)fd; (void)output;
    return true;
}

static bool hdr_dsc_big_joiner(int fd, igt_output_t *output)
{
    return igt_output_has_hdr(fd, output) &&
           igt_output_has_dsc(fd, output) &&
           igt_output_get_max_joiner(fd, output) >= JOINED_PIPES_BIG_JOINER;
}

static bool vrr_capable(int fd, igt_output_t *output)
{
    return igt_output_has_vrr(fd, output);
}

static bool psr_capable(int fd, igt_output_t *output)
{
    return igt_output_has_psr(fd, output, PSR_MODE_1);
}

/*
 * Rich config: 6 pipes, 5 outputs, multiple features per output
 *
 *   DP-1:    DSC, HDR, VRR, Big Joiner — the "everything" output
 *   DP-2:    DSC, Big Joiner
 *   HDMI-A-1: HDR only
 *   eDP-1:   DSC, PSR, FBC — laptop panel
 *   DP-3:    Ultra Joiner capable, DSC
 */
static const sandbox_display_config_t full_config = {
    .n_pipes = 6,
    .max_dotclock = 594000,
    .max_pipe_width = 5120,
    .n_outputs = 5,
    .outputs = {
        { .name = "DP-1", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = { .dsc_source = true, .dsc_sink = true, .fec = true,
                    .hdr_panel = true, .hdr_prop = true,
                    .vrr_capable = true, .vrr_min_hz = 48, .vrr_max_hz = 144,
                    .max_joiner_level = 1, .force_joiner = true },
          .n_modes = 3,
          .modes = { { 5120, 2880, 742500 },
                     { 3840, 2160, 594000 },
                     { 1920, 1080, 148500 } } },

        { .name = "DP-2", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = { .dsc_source = true, .dsc_sink = true, .fec = true,
                    .max_joiner_level = 1 },
          .n_modes = 2,
          .modes = { { 5120, 2880, 742500 },
                     { 1920, 1080, 148500 } } },

        { .name = "HDMI-A-1", .connector_type = DRM_MODE_CONNECTOR_HDMIA,
          .connected = true,
          .caps = { .hdr_panel = true, .hdr_prop = true },
          .n_modes = 1,
          .modes = { { 1920, 1080, 148500 } } },

        { .name = "eDP-1", .connector_type = DRM_MODE_CONNECTOR_eDP,
          .connected = true, .is_internal = true,
          .caps = { .dsc_source = true, .dsc_sink = true,
                    .psr = true, .fbc = true, .drrs = true },
          .n_modes = 1,
          .modes = { { 2560, 1440, 241500 } } },

        { .name = "DP-3", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = { .dsc_source = true, .dsc_sink = true, .fec = true,
                    .max_joiner_level = 2 },
          .n_modes = 2,
          .modes = { { 7680, 4320, 1188000 },
                     { 3840, 2160, 594000 } } },
    },
};

igt_main
{
    igt_display_t display;
    int fd = SANDBOX_FD;

    _sandbox_init("test_full_examples");

    igt_fixture {
        sandbox_display_init(&display, &full_config);
    }

    /* ═══════════════════════════════════════════════════════════
     * Layer 6: Output Classifier
     * ═══════════════════════════════════════════════════════════ */

    igt_subtest("classifier-dsc") {
        igt_output_t *match[IGT_MAX_OUTPUTS], *no_match[IGT_MAX_OUTPUTS];
        int m_count, nm_count;

        igt_classify_outputs(&display, fd, dsc_capable,
                             match, &m_count, no_match, &nm_count);

        igt_info("DSC capable: %d, non-DSC: %d\n", m_count, nm_count);
        igt_assert(m_count == 4); /* DP-1, DP-2, eDP-1, DP-3 */
        igt_assert(nm_count == 1); /* HDMI-A-1 */
    }

    igt_subtest("find-output-with") {
        igt_output_t *output = igt_find_output_with(&display, fd, vrr_capable);
        igt_require(output != NULL);
        igt_info("First VRR output: %s\n", output->name);
        igt_assert(strcmp(output->name, "DP-1") == 0);
    }

    igt_subtest("count-outputs-with") {
        int count = igt_count_outputs_with(&display, fd, dsc_capable);
        igt_info("DSC output count: %d (expect 4)\n", count);
        igt_assert(count == 4);
    }

    /* ═══════════════════════════════════════════════════════════
     * Layer 8: Convenience Helpers
     * ═══════════════════════════════════════════════════════════ */

    igt_subtest("setup-fb-convenience") {
        igt_fb_t fb;
        igt_plane_t *primary;

        igt_output_set_crtc(&display.outputs[0], PIPE_A);

        primary = igt_output_setup_fb(fd, &display.outputs[0],
                                       DRM_FORMAT_XRGB8888,
                                       DRM_FORMAT_MOD_LINEAR, &fb);
        igt_assert(fb.valid);
        igt_assert(primary->has_fb);
        igt_info("FB created: %dx%d\n", fb.width, fb.height);

        igt_remove_fb(fd, &fb);
    }

    igt_subtest("find-joiner-mode") {
        drmModeModeInfo mode;

        /* DP-1 should have a mode triggering big joiner */
        igt_assert(igt_find_joiner_mode(fd, &display.outputs[0],
                   JOINED_PIPES_BIG_JOINER, &mode));
        igt_info("Big joiner mode: %dx%d@%dkHz\n",
                 mode.hdisplay, mode.vdisplay, mode.clock);
        igt_assert(mode.hdisplay >= 5120 || (int)mode.clock > 594000);
    }

    igt_subtest("find-non-joiner-mode") {
        drmModeModeInfo mode;

        igt_assert(igt_find_non_joiner_mode(fd, &display.outputs[0], &mode));
        igt_info("Non-joiner mode: %dx%d@%dkHz\n",
                 mode.hdisplay, mode.vdisplay, mode.clock);
        igt_assert(mode.hdisplay <= 5120 && (int)mode.clock <= 594000);
    }

    /* ═══════════════════════════════════════════════════════════
     * Full Example 1: DSC + Big Joiner
     * ═══════════════════════════════════════════════════════════ */

    igt_subtest_with_dynamic("dsc-with-big-joiner") {
        igt_output_t *output;

        igt_require(igt_source_has_dsc(fd));
        igt_require(igt_source_has_joiner(fd));

        for_each_connected_output_where(&display, output,
                igt_output_has_dsc(fd, output) &&
                igt_output_get_max_joiner(fd, output)
                    >= JOINED_PIPES_BIG_JOINER) {

            igt_dynamic_f("%s", output->name) {
                igt_fb_t fb;
                drmModeModeInfo mode;
                igt_debugfs_guard_t dsc_guard;

                igt_require(igt_find_joiner_mode(fd, output,
                            JOINED_PIPES_BIG_JOINER, &mode));
                igt_output_override_mode(output, &mode);

                igt_require(igt_allocate_pipes(&display,
                            &output, 1, NULL) == 0);

                igt_intel_dsc_guard_begin(fd, output, &dsc_guard);
                force_dsc_enable(fd, output);

                igt_output_setup_fb(fd, output,
                    DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb);

                igt_assert(igt_bw_safe_commit(&display));
                igt_assert(igt_is_dsc_enabled(fd, output->name));

                igt_remove_fb(fd, &fb);
                igt_intel_dsc_guard_end(&dsc_guard);
            }
        }
    }

    /* ═══════════════════════════════════════════════════════════
     * Full Example 2: Dual-Output Combo (DSC + Normal)
     * ═══════════════════════════════════════════════════════════ */

    igt_subtest_with_dynamic("dsc-plus-normal-dual") {
        bool (*preds[])(int, igt_output_t *) = {
            dsc_capable,
            any_connected,
        };
        igt_output_t *outs[2];
        igt_combo_iter_t iter;

        for_each_output_combo(&display, &iter, outs, 2, preds) {
            igt_dynamic_f("%s-%s", outs[0]->name, outs[1]->name) {
                igt_debugfs_guard_t dsc_guard;
                igt_fb_t fb[2];

                igt_intel_dsc_guard_begin(fd, outs[0], &dsc_guard);
                force_dsc_enable(fd, outs[0]);

                igt_output_setup_fb(fd, outs[0],
                    DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb[0]);
                igt_output_setup_fb(fd, outs[1],
                    DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb[1]);

                igt_assert(igt_bw_safe_commit(&display));
                igt_assert(igt_is_dsc_enabled(fd, outs[0]->name));

                igt_remove_fb(fd, &fb[0]);
                igt_remove_fb(fd, &fb[1]);
                igt_intel_dsc_guard_end(&dsc_guard);
            }
        }
    }

    /* ═══════════════════════════════════════════════════════════
     * Full Example 3: HDR + DSC + Big Joiner (Triple Feature)
     * ═══════════════════════════════════════════════════════════ */

    igt_subtest_with_dynamic("hdr-dsc-big-joiner") {
        igt_output_t *output;

        for_each_connected_output_where(&display, output,
                hdr_dsc_big_joiner(fd, output)) {

            igt_dynamic_f("%s", output->name) {
                igt_fb_t fb;
                drmModeModeInfo mode;
                igt_debugfs_guard_t dsc_guard;

                igt_require(igt_find_joiner_mode(fd, output,
                            JOINED_PIPES_BIG_JOINER, &mode));
                igt_output_override_mode(output, &mode);
                igt_require(igt_allocate_pipes(&display,
                            &output, 1, NULL) == 0);

                igt_intel_dsc_guard_begin(fd, output, &dsc_guard);
                force_dsc_enable(fd, output);

                igt_output_set_prop_value(output,
                    IGT_CONNECTOR_HDR_OUTPUT_METADATA, 42);
                igt_output_set_prop_value(output,
                    IGT_CONNECTOR_MAX_BPC, 10);

                igt_output_setup_fb(fd, output,
                    DRM_FORMAT_XRGB2101010, DRM_FORMAT_MOD_LINEAR, &fb);

                igt_assert(igt_bw_safe_commit(&display));
                igt_assert(igt_is_dsc_enabled(fd, output->name));

                igt_remove_fb(fd, &fb);
                igt_intel_dsc_guard_end(&dsc_guard);
            }
        }
    }

    /* ═══════════════════════════════════════════════════════════
     * Full Example 4: Ultra Joiner + DSC
     * ═══════════════════════════════════════════════════════════ */

    igt_subtest_with_dynamic("ultra-joiner-dsc") {
        igt_output_t *output;

        for_each_connected_output_where(&display, output,
                igt_output_has_dsc(fd, output) &&
                igt_output_get_max_joiner(fd, output)
                    >= JOINED_PIPES_ULTRA_JOINER) {

            igt_dynamic_f("%s", output->name) {
                igt_fb_t fb;
                drmModeModeInfo mode;

                igt_require(igt_find_joiner_mode(fd, output,
                            JOINED_PIPES_ULTRA_JOINER, &mode));
                igt_output_override_mode(output, &mode);

                int need = igt_output_get_required_pipes(fd, output);
                igt_info("Ultra joiner: %d pipes needed\n", need);
                igt_assert(need == 4);

                igt_require(igt_allocate_pipes(&display,
                            &output, 1, NULL) == 0);

                igt_output_setup_fb(fd, output,
                    DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb);
                igt_assert(igt_bw_safe_commit(&display));

                igt_remove_fb(fd, &fb);
            }
        }
    }

    /* ═══════════════════════════════════════════════════════════
     * Full Example 5: VRR Dual-Output
     * ═══════════════════════════════════════════════════════════ */

    igt_subtest_with_dynamic("vrr-dual-output") {
        bool (*preds[])(int, igt_output_t *) = {
            vrr_capable, any_connected,
        };
        igt_output_t *outs[2];
        igt_combo_iter_t iter;

        for_each_output_combo(&display, &iter, outs, 2, preds) {
            igt_dynamic_f("%s-%s", outs[0]->name, outs[1]->name) {
                int min_hz, max_hz;
                igt_fb_t fb[2];

                igt_assert(igt_output_get_vrr_range(fd, outs[0],
                           &min_hz, &max_hz));
                igt_info("VRR range: %d-%d Hz on %s\n",
                         min_hz, max_hz, outs[0]->name);

                igt_output_setup_fb(fd, outs[0],
                    DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb[0]);
                igt_output_setup_fb(fd, outs[1],
                    DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb[1]);

                igt_assert(igt_bw_safe_commit(&display));

                igt_remove_fb(fd, &fb[0]);
                igt_remove_fb(fd, &fb[1]);
            }
        }
    }

    /* ═══════════════════════════════════════════════════════════
     * Full Example 6: Multi-Output Builder for PSR + FBC
     * ═══════════════════════════════════════════════════════════ */

    igt_subtest("psr-fbc-multi-output") {
        igt_output_spec_t specs[] = {
            { .predicate = psr_capable },
            { .predicate = any_connected },
        };
        igt_multi_output_ctx_t ctx;

        int ret = igt_multi_output_try_setup(&display, fd, specs, 2, &ctx);
        if (ret == 0) {
            igt_info("PSR+other: %s (PSR) + %s\n",
                     specs[0].output->name, specs[1].output->name);
            igt_multi_output_commit(&ctx);
            igt_multi_output_teardown(&ctx);
        } else {
            igt_info("PSR+other: not enough matching outputs\n");
        }
    }

    igt_fixture {
        sandbox_display_fini(&display);
    }

    _sandbox_exit();
}
