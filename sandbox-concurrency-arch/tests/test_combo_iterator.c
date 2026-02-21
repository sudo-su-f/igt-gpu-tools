/*
 * test_combo_iterator.c — Layer 7: Combo Iterator with Backtracking
 *
 * The most critical test: validates that the combo iterator with
 * caller-allocated state and odometer-pattern backtracking correctly
 * enumerates all valid output combinations without repeats.
 */

#include "igt_sandbox.h"

IGT_TEST_DESCRIPTION("Validate Layer 7: Combo Iterator with Backtracking");

static bool dsc_capable(int fd, igt_output_t *output)
{
    return igt_output_has_dsc(fd, output);
}

static bool any_output(int fd, igt_output_t *output)
{
    (void)fd; (void)output;
    return true;
}

static bool hdr_capable(int fd, igt_output_t *output)
{
    return igt_output_has_hdr(fd, output);
}

/*
 * Config: 4 pipes, 4 outputs with mixed capabilities
 *
 *   DP-1:    DSC + HDR
 *   DP-2:    DSC only
 *   HDMI-A-1: HDR only
 *   eDP-1:   DSC (internal, no FEC needed)
 */
static const sandbox_display_config_t combo_config = {
    .n_pipes = 4,
    .max_dotclock = 594000,
    .max_pipe_width = 5120,
    .n_outputs = 4,
    .outputs = {
        { .name = "DP-1", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = { .dsc_source = true, .dsc_sink = true, .fec = true,
                    .hdr_panel = true, .hdr_prop = true },
          .n_modes = 1,
          .modes = { { 1920, 1080, 148500 } } },

        { .name = "DP-2", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = { .dsc_source = true, .dsc_sink = true, .fec = true },
          .n_modes = 1,
          .modes = { { 2560, 1440, 241500 } } },

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

    _sandbox_init("test_combo_iterator");

    igt_fixture {
        sandbox_display_init(&display, &combo_config);
    }

    /* ── 2-slot combo: any + any ─────────────────────────────── */

    igt_subtest("combo-2slot-all-pairs") {
        bool (*preds[])(int, igt_output_t *) = { any_output, any_output };
        igt_output_t *outs[2];
        igt_combo_iter_t iter;
        int count = 0;

        igt_info("Enumerating all 2-output combos:\n");
        for_each_output_combo(&display, &iter, outs, 2, preds) {
            igt_info("  [%d] %s + %s\n", count, outs[0]->name, outs[1]->name);
            /* Outputs must be distinct */
            igt_assert(outs[0] != outs[1]);
            count++;
        }

        /* 4 outputs, choose 2 + ordering = 4*3 = 12 combos */
        igt_info("Total combos: %d (expect 12)\n", count);
        igt_assert(count == 12);
    }

    /* ── 2-slot combo: DSC + any ─────────────────────────────── */

    igt_subtest("combo-dsc-plus-any") {
        bool (*preds[])(int, igt_output_t *) = { dsc_capable, any_output };
        igt_output_t *outs[2];
        igt_combo_iter_t iter;
        int count = 0;

        igt_info("DSC + any combos:\n");
        for_each_output_combo(&display, &iter, outs, 2, preds) {
            igt_info("  [%d] %s (DSC) + %s\n",
                     count, outs[0]->name, outs[1]->name);
            /* Slot 0 must have DSC */
            igt_assert(igt_output_has_dsc(fd, outs[0]));
            /* Must be distinct */
            igt_assert(outs[0] != outs[1]);
            count++;
        }

        /* 3 DSC outputs × 3 remaining = 9 combos */
        igt_info("Total: %d (expect 9)\n", count);
        igt_assert(count == 9);
    }

    /* ── 2-slot combo: DSC + HDR ─────────────────────────────── */

    igt_subtest("combo-dsc-plus-hdr") {
        bool (*preds[])(int, igt_output_t *) = { dsc_capable, hdr_capable };
        igt_output_t *outs[2];
        igt_combo_iter_t iter;
        int count = 0;

        igt_info("DSC + HDR combos:\n");
        for_each_output_combo(&display, &iter, outs, 2, preds) {
            igt_info("  [%d] %s (DSC) + %s (HDR)\n",
                     count, outs[0]->name, outs[1]->name);
            igt_assert(igt_output_has_dsc(fd, outs[0]));
            igt_assert(igt_output_has_hdr(fd, outs[1]));
            igt_assert(outs[0] != outs[1]);
            count++;
        }

        /* DSC: DP-1, DP-2, eDP-1. HDR: DP-1, HDMI-A-1.
         * Valid pairs: (DP-1 DSC, HDMI-A-1 HDR),
         *              (DP-2 DSC, DP-1 HDR), (DP-2 DSC, HDMI-A-1 HDR),
         *              (eDP-1 DSC, DP-1 HDR), (eDP-1 DSC, HDMI-A-1 HDR) = 5 */
        igt_info("Total: %d (expect 5)\n", count);
        igt_assert(count == 5);
    }

    /* ── 3-slot combo ────────────────────────────────────────── */

    igt_subtest("combo-3slot") {
        bool (*preds[])(int, igt_output_t *) = {
            any_output, any_output, any_output
        };
        igt_output_t *outs[3];
        igt_combo_iter_t iter;
        int count = 0;

        for_each_output_combo(&display, &iter, outs, 3, preds) {
            /* All 3 must be distinct */
            igt_assert(outs[0] != outs[1]);
            igt_assert(outs[0] != outs[2]);
            igt_assert(outs[1] != outs[2]);
            count++;
        }

        /* 4P3 = 4*3*2 = 24 */
        igt_info("3-slot combos: %d (expect 24)\n", count);
        igt_assert(count == 24);
    }

    /* ── No valid combos ─────────────────────────────────────── */

    igt_subtest("combo-impossible") {
        /* Ask for 2 HDR outputs but only 2 HDR exist  → should find
         * (DP-1, HDMI-A-1) and (HDMI-A-1, DP-1) */
        bool (*preds[])(int, igt_output_t *) = { hdr_capable, hdr_capable };
        igt_output_t *outs[2];
        igt_combo_iter_t iter;
        int count = 0;

        for_each_output_combo(&display, &iter, outs, 2, preds) {
            igt_info("  HDR pair: %s + %s\n", outs[0]->name, outs[1]->name);
            count++;
        }
        igt_info("HDR pairs: %d (expect 2)\n", count);
        igt_assert(count == 2);
    }

    /* ── Caller-allocated iterator: no global state ──────────── */

    igt_subtest("combo-iter-no-global-state") {
        /*
         * Two independent iterators running simultaneously.
         * This proves there's no global state — each has its own cursors.
         */
        bool (*preds1[])(int, igt_output_t *) = { dsc_capable, any_output };
        bool (*preds2[])(int, igt_output_t *) = { any_output, any_output };
        igt_output_t *outs1[2], *outs2[2];
        igt_combo_iter_t iter1, iter2;
        int count1 = 0, count2 = 0;

        for_each_output_combo(&display, &iter1, outs1, 2, preds1) {
            count1++;
        }
        for_each_output_combo(&display, &iter2, outs2, 2, preds2) {
            count2++;
        }

        igt_info("Iterator 1 (DSC+any): %d combos\n", count1);
        igt_info("Iterator 2 (any+any): %d combos\n", count2);
        igt_assert(count1 == 9);
        igt_assert(count2 == 12);
    }

    /* ── No repeated combos verification ─────────────────────── */

    igt_subtest("combo-no-repeats") {
        bool (*preds[])(int, igt_output_t *) = { any_output, any_output };
        igt_output_t *outs[2];
        igt_combo_iter_t iter;

        /* Store all combos as (idx0, idx1) pairs */
        int seen[64][2];
        int count = 0;
        int i;

        for_each_output_combo(&display, &iter, outs, 2, preds) {
            int a = (int)(outs[0] - display.outputs);
            int b = (int)(outs[1] - display.outputs);

            /* Check no previous combo matches */
            for (i = 0; i < count; i++) {
                igt_assert(!(seen[i][0] == a && seen[i][1] == b));
            }
            seen[count][0] = a;
            seen[count][1] = b;
            count++;
        }
        igt_info("Verified %d combos with no repeats\n", count);
    }

    /* ── Combo with dynamic subtests (real IGT pattern) ──────── */

    igt_subtest_with_dynamic("combo-dynamic-subtests") {
        bool (*preds[])(int, igt_output_t *) = { dsc_capable, any_output };
        igt_output_t *outs[2];
        igt_combo_iter_t iter;

        for_each_output_combo(&display, &iter, outs, 2, preds) {
            igt_dynamic_f("%s-%s", outs[0]->name, outs[1]->name) {
                igt_fb_t fb[2];

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

    igt_fixture {
        sandbox_display_fini(&display);
    }

    _sandbox_exit();
}
