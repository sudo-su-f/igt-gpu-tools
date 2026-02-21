## Complete Examples

### Example 1 — DSC + Big Joiner Test

```c
#include "igt.h"
#include "igt_kms_feature.h"

IGT_TEST_DESCRIPTION("Verify DSC with big joiner modeset");

typedef struct {
    int drm_fd;
    igt_display_t display;
} data_t;

igt_main
{
    data_t data = {};

    igt_fixture {
        data.drm_fd = drm_open_driver_master(DRIVER_INTEL | DRIVER_XE);
        igt_display_require(&data.display, data.drm_fd);

        igt_require(igt_source_has_dsc(data.drm_fd));
        igt_require(igt_source_has_joiner(data.drm_fd));
    }

    igt_subtest_with_dynamic("dsc-with-big-joiner") {
        igt_output_t *output;

        for_each_connected_output_where(&data.display, output,
                igt_output_has_dsc(data.drm_fd, output) &&
                igt_output_get_max_joiner(data.drm_fd, output)
                    >= JOINED_PIPES_BIG_JOINER) {

            igt_dynamic_f("%s", output->name) {
                igt_fb_t fb;
                drmModeModeInfo mode;
                igt_debugfs_guard_t dsc_guard;

                igt_require(igt_find_joiner_mode(data.drm_fd, output,
                            JOINED_PIPES_BIG_JOINER, &mode));
                igt_output_override_mode(output, &mode);

                igt_require(igt_allocate_pipes(&data.display,
                            &output, 1, NULL) == 0);

                /* Explicit begin/end — no RAII dependency */
                igt_intel_dsc_guard_begin(data.drm_fd, output, &dsc_guard);
                force_dsc_enable(data.drm_fd, output);

                igt_output_setup_fb(data.drm_fd, output,
                    DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb);

                igt_assert(igt_bw_safe_commit(&data.display));
                igt_assert(igt_is_dsc_enabled(data.drm_fd, output->name));

                igt_remove_fb(data.drm_fd, &fb);
                igt_intel_dsc_guard_end(&dsc_guard);
            }
        }
    }

    igt_fixture {
        igt_display_fini(&data.display);
        drm_close_driver(data.drm_fd);
    }
}
```

---

### Example 2 — HDR + DSC + Big Joiner (Triple Feature)

```c
static bool hdr_dsc_big_joiner(int fd, igt_output_t *output)
{
    return igt_output_has_hdr(fd, output) &&
           igt_output_has_dsc(fd, output) &&
           igt_output_get_max_joiner(fd, output)
               >= JOINED_PIPES_BIG_JOINER;
}

igt_subtest_with_dynamic("hdr-dsc-big-joiner") {
    igt_output_t *output;

    for_each_connected_output_where(&data.display, output,
            hdr_dsc_big_joiner(data.drm_fd, output)) {

        igt_dynamic_f("%s", output->name) {
            igt_fb_t fb;
            drmModeModeInfo mode;
            igt_debugfs_guard_t dsc_guard;

            igt_require(igt_find_joiner_mode(data.drm_fd, output,
                        JOINED_PIPES_BIG_JOINER, &mode));
            igt_output_override_mode(output, &mode);
            igt_require(igt_allocate_pipes(&data.display,
                        &output, 1, NULL) == 0);

            igt_intel_dsc_guard_begin(data.drm_fd, output, &dsc_guard);
            force_dsc_enable(data.drm_fd, output);

            igt_output_set_prop_value(output,
                IGT_CONNECTOR_HDR_OUTPUT_METADATA, hdr_blob);
            igt_output_set_prop_value(output,
                IGT_CONNECTOR_MAX_BPC, 10);

            igt_output_setup_fb(data.drm_fd, output,
                DRM_FORMAT_XRGB2101010, DRM_FORMAT_MOD_LINEAR, &fb);

            igt_assert(igt_bw_safe_commit(&data.display));
            igt_assert(igt_is_dsc_enabled(data.drm_fd, output->name));

            igt_remove_fb(data.drm_fd, &fb);
            igt_intel_dsc_guard_end(&dsc_guard);
        }
    }
}
```

---

### Example 3 — Dual-Output Combo with for_each_output_combo

```c
static bool dsc_capable(int fd, igt_output_t *output)
{
    return igt_output_has_dsc(fd, output);
}

static bool any_connected(int fd, igt_output_t *output)
{
    (void)fd;
    (void)output;
    return true;
}

igt_subtest_with_dynamic("dsc-plus-normal-dual") {
    bool (*preds[])(int, igt_output_t *) = {
        dsc_capable,
        any_connected,
    };
    igt_output_t *outs[2];
    igt_combo_iter_t iter;

    for_each_output_combo(&data.display, &iter, outs, 2, preds) {
        igt_dynamic_f("%s-%s", outs[0]->name, outs[1]->name) {
            igt_debugfs_guard_t dsc_guard;
            igt_fb_t fb[2];

            igt_intel_dsc_guard_begin(data.drm_fd, outs[0], &dsc_guard);
            force_dsc_enable(data.drm_fd, outs[0]);

            igt_output_setup_fb(data.drm_fd, outs[0],
                DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb[0]);
            igt_output_setup_fb(data.drm_fd, outs[1],
                DRM_FORMAT_XRGB8888, DRM_FORMAT_MOD_LINEAR, &fb[1]);

            igt_assert(igt_bw_safe_commit(&data.display));
            igt_assert(igt_is_dsc_enabled(data.drm_fd, outs[0]->name));

            igt_remove_fb(data.drm_fd, &fb[0]);
            igt_remove_fb(data.drm_fd, &fb[1]);
            igt_intel_dsc_guard_end(&dsc_guard);
        }
    }
}
```

---

### What New Tests Become Possible

| Test | Outputs | Features | Key API Used |
|------|---------|----------|-------------|
| DSC + Big Joiner | 1 | DSC, Joiner | `for_each_connected_output_where` + `igt_allocate_pipes` |
| HDR + DSC + Joiner | 1 | HDR, DSC, Joiner | Composed predicates |
| Dual-output DSC Joiner + Normal | 2 | DSC, Joiner | `igt_multi_output_setup()` |
| Dual-output VRR + AsyncFlip | 2 | VRR | `for_each_output_combo()` |
| PSR + FBC Dual-Pipe | 2 | PSR, FBC | `igt_multi_output_setup()` |
| Ultra Joiner + DSC | 1 | DSC, Ultra Joiner | `igt_find_joiner_mode(ULTRA_JOINER)` |
| DSC BPC sweep + Joiner | 1 | DSC, Joiner | Predicate + existing BPC API |
