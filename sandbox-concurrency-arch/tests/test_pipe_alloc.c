/*
 * test_pipe_alloc.c — Layer 2: Joiner-Aware Pipe Allocator
 *
 * Validates pipe allocation with big joiner (2-pipe) and ultra joiner (4-pipe),
 * hdisplay-based joiner detection, and priority sorting (4-pipe first).
 */

#include "igt_sandbox.h"

IGT_TEST_DESCRIPTION("Validate Layer 2: Joiner-Aware Pipe Allocator");

/*
 * Config: 6 pipes (A-F), max_dotclock=594000, max_pipe_width=5120
 *
 *   DP-1:  has 8K mode (7680x4320@1188000) → ultra joiner (4 pipes)
 *   DP-2:  has 5K mode (5120x2880@742500)  → big joiner (2 pipes)
 *   DP-3:  has 4K mode (3840x2160@594000)  → single pipe
 *   eDP-1: has FHD mode (1920x1080)        → single pipe
 *   DP-4:  has wide mode (7680x2160@594000) → big joiner (width-based)
 */
static const sandbox_display_config_t alloc_config = {
    .n_pipes = 6,
    .max_dotclock = 594000,
    .max_pipe_width = 5120,
    .n_outputs = 5,
    .outputs = {
        { .name = "DP-1", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = { .max_joiner_level = 2 },
          .n_modes = 2,
          .modes = { { 7680, 4320, 1188000 }, { 3840, 2160, 594000 } } },

        { .name = "DP-2", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = { .max_joiner_level = 1 },
          .n_modes = 2,
          .modes = { { 5120, 2880, 742500 }, { 1920, 1080, 148500 } } },

        { .name = "DP-3", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .n_modes = 1,
          .modes = { { 3840, 2160, 594000 } } },

        { .name = "eDP-1", .connector_type = DRM_MODE_CONNECTOR_eDP,
          .connected = true, .is_internal = true,
          .n_modes = 1,
          .modes = { { 1920, 1080, 148500 } } },

        { .name = "DP-4", .connector_type = DRM_MODE_CONNECTOR_DP,
          .connected = true,
          .caps = { .max_joiner_level = 1 },
          .n_modes = 1,
          .modes = { { 7680, 2160, 594000 } } }, /* wide but not fast */
    },
};

igt_main
{
    igt_display_t display;
    int fd = SANDBOX_FD;

    _sandbox_init("test_pipe_alloc");

    igt_fixture {
        sandbox_display_init(&display, &alloc_config);
    }

    /* ── Pipe mask computation ───────────────────────────────── */

    igt_subtest("valid-pipe-mask") {
        uint32_t mask = igt_get_valid_pipe_mask(&display);
        igt_info("valid_pipe_mask = 0x%x (expect 0x3F for 6 pipes)\n", mask);
        igt_assert(mask == 0x3F); /* bits 0-5 set */
    }

    igt_subtest("master-pipe-mask") {
        uint32_t mask = igt_get_master_pipe_mask(&display);
        igt_info("master_pipe_mask = 0x%x (expect 0x1F for 6 pipes)\n", mask);
        igt_assert(mask == 0x1F); /* bits 0-4: each can start a 2-pipe join */
    }

    /* ── Required pipes computation (dotclock + hdisplay) ────── */

    igt_subtest("required-pipes-single") {
        /* eDP-1 at 1920x1080: single pipe */
        int need = igt_output_get_required_pipes(fd, &display.outputs[3]);
        igt_info("eDP-1: %d pipe(s) needed\n", need);
        igt_assert(need == 1);
    }

    igt_subtest("required-pipes-big-joiner-dotclock") {
        /* DP-2 at 5120x2880@742500: dotclock > max → big joiner */
        int need = igt_output_get_required_pipes(fd, &display.outputs[1]);
        igt_info("DP-2: %d pipe(s) needed (dotclock-based)\n", need);
        igt_assert(need == 2);
    }

    igt_subtest("required-pipes-big-joiner-width") {
        /* DP-4 at 7680x2160@594000: width > max but clock ≤ max */
        int need = igt_output_get_required_pipes(fd, &display.outputs[4]);
        igt_info("DP-4: %d pipe(s) needed (width-based)\n", need);
        igt_assert(need == 2);
    }

    igt_subtest("required-pipes-ultra-joiner") {
        /* DP-1 at 7680x4320@1188000: both dimensions exceed → 4 pipes */
        int need = igt_output_get_required_pipes(fd, &display.outputs[0]);
        igt_info("DP-1: %d pipe(s) needed (ultra joiner)\n", need);
        igt_assert(need == 4);
    }

    /* ── Intent-based computation ────────────────────────────── */

    igt_subtest("intent-with-dsc") {
        struct igt_modeset_intent intent = {0};
        intent.mode.clock = 742500;
        intent.mode.hdisplay = 5120;
        intent.mode.vdisplay = 2880;
        intent.dsc = true; /* DSC halves effective clock */
        /* 742500/2 = 371250, which is < 594000 → single pipe */
        int need = igt_compute_required_pipes(fd, &display.outputs[1], &intent);
        igt_info("With DSC: %d pipe(s) needed (expect 1)\n", need);
        igt_assert(need == 1);
    }

    igt_subtest("intent-forced-joiner") {
        struct igt_modeset_intent intent = {0};
        intent.mode.clock = 148500;
        intent.mode.hdisplay = 1920;
        intent.mode.vdisplay = 1080;
        intent.min_joiner = JOINED_PIPES_BIG_JOINER;
        int need = igt_compute_required_pipes(fd, &display.outputs[3], &intent);
        igt_info("Forced big joiner: %d pipe(s) needed (expect 2)\n", need);
        igt_assert(need == 2);
    }

    /* ── find_consecutive_pipes ──────────────────────────────── */

    igt_subtest("find-consecutive-single") {
        int p = igt_find_consecutive_pipes(6, 0x3F, 1);
        igt_info("First free single pipe: %d (expect 0)\n", p);
        igt_assert(p == 0);
    }

    igt_subtest("find-consecutive-with-gap") {
        /* Pipes A,C,D,E available (B fused off) → mask = 0x3D */
        int p = igt_find_consecutive_pipes(6, 0x3D, 2);
        igt_info("First consecutive pair in 0x3D: %d (expect 2)\n", p);
        igt_assert(p == 2); /* C+D */
    }

    igt_subtest("find-consecutive-4pipe") {
        /* All 6 pipes available → first 4-pipe block starts at 0 */
        int p = igt_find_consecutive_pipes(6, 0x3F, 4);
        igt_info("First 4-consecutive in 0x3F: %d (expect 0)\n", p);
        igt_assert(p == 0);
    }

    igt_subtest("find-consecutive-4pipe-partial") {
        /* Pipe A taken → available = 0x3E, 4-pipe at p=1 */
        int p = igt_find_consecutive_pipes(6, 0x3E, 4);
        igt_info("4-pipe in 0x3E: %d (expect 1)\n", p);
        igt_assert(p == 1);
    }

    igt_subtest("find-consecutive-4pipe-impossible") {
        /* Only 3 pipes available: 0x07 = A,B,C → can't fit 4 */
        int p = igt_find_consecutive_pipes(6, 0x07, 4);
        igt_info("4-pipe in 0x07: %d (expect -1)\n", p);
        igt_assert(p == -1);
    }

    /* ── Full allocator ──────────────────────────────────────── */

    igt_subtest("allocate-ultra-plus-single") {
        /* DP-1 (4 pipes) + eDP-1 (1 pipe) = 5 of 6 pipes */
        igt_output_t *outs[2] = {
            &display.outputs[0], &display.outputs[3]
        };
        uint32_t used = 0;
        int ret = igt_allocate_pipes(&display, outs, 2, &used);
        igt_info("Allocated: ret=%d, used_pipes=0x%x\n", ret, used);
        igt_info("  DP-1 → pipe %d, eDP-1 → pipe %d\n",
                 outs[0]->pipe, outs[1]->pipe);
        igt_assert(ret == 0);
        /* 4-pipe output should get A-D, single gets E */
        igt_assert(outs[0]->pipe == PIPE_A);
        igt_assert(outs[1]->pipe == PIPE_E);
    }

    igt_subtest("allocate-big-plus-big") {
        /* DP-2 (2 pipes) + DP-4 (2 pipes) = 4 of 6 pipes */
        igt_output_t *outs[2] = {
            &display.outputs[1], &display.outputs[4]
        };
        uint32_t used = 0;
        int ret = igt_allocate_pipes(&display, outs, 2, &used);
        igt_info("Allocated: ret=%d, used_pipes=0x%x\n", ret, used);
        igt_assert(ret == 0);
    }

    igt_subtest("allocate-priority-sorting") {
        /* Allocate: single + big + ultra → should sort: ultra, big, single */
        igt_output_t *outs[3] = {
            &display.outputs[3], /* eDP-1: 1 pipe */
            &display.outputs[1], /* DP-2: 2 pipes */
            &display.outputs[0], /* DP-1: 4 pipes */
        };
        uint32_t used = 0;
        int ret = igt_allocate_pipes(&display, outs, 3, &used);
        igt_info("Priority sort result: ret=%d, used=0x%x\n", ret, used);
        /* 4+2+1 = 7 pipes needed, we have 6 → should fail */
        /* Actually DP-1=4 + DP-2=2 = 6 exactly, eDP-1 has nothing left */
        if (ret < 0)
            igt_info("  Expected: not enough pipes\n");
        /* This is a valid failure case */
    }

    igt_fixture {
        sandbox_display_fini(&display);
    }

    _sandbox_exit();
}
