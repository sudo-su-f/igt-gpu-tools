/*
 * igt_sandbox.c — Implementation of the KMS test architecture sandbox
 *
 * Self-contained: no real DRM/KMS/IGT dependencies.
 * All hardware is simulated via sandbox_display_config_t.
 */

#include "igt_sandbox.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * Global State
 * ═══════════════════════════════════════════════════════════════════════════ */

_sandbox_harness_t _harness;

/* Global display reference for fd-based lookups */
static igt_display_t *_global_display = NULL;

/* Exit handlers */
#define MAX_EXIT_HANDLERS 8
static sandbox_exit_handler_t _exit_handlers[MAX_EXIT_HANDLERS];
static int _n_exit_handlers = 0;

/* Debugfs guard safety net */
#define MAX_ACTIVE_GUARDS 16
static igt_debugfs_guard_t *_active_guards[MAX_ACTIVE_GUARDS];
static int _n_active_guards = 0;
static bool _guard_exit_handler_installed = false;


/* ═══════════════════════════════════════════════════════════════════════════
 * Display Simulation
 * ═══════════════════════════════════════════════════════════════════════════ */

void sandbox_display_init(igt_display_t *display,
                          const sandbox_display_config_t *config)
{
    memset(display, 0, sizeof(*display));
    display->drm_fd = SANDBOX_FD;
    display->n_pipes = config->n_pipes;
    display->n_outputs = config->n_outputs;
    display->sim_config = (sandbox_display_config_t *)config;
    _global_display = display;

    for (int i = 0; i < config->n_outputs; i++) {
        igt_output_t *out = &display->outputs[i];
        const sandbox_output_config_t *cfg = &config->outputs[i];

        snprintf(out->name, sizeof(out->name), "%s", cfg->name);
        out->connector_type = cfg->connector_type;
        out->connected = cfg->connected;
        out->is_internal = cfg->is_internal;
        out->sim_config = (sandbox_output_config_t *)cfg;
        out->pipe = PIPE_NONE;
        out->pipe_assigned = false;
        out->has_override = false;

        /* Copy modes */
        out->n_modes = cfg->n_modes;
        for (int m = 0; m < cfg->n_modes; m++) {
            out->modes[m].hdisplay = cfg->modes[m].hdisplay;
            out->modes[m].vdisplay = cfg->modes[m].vdisplay;
            out->modes[m].clock = cfg->modes[m].clock;
            out->modes[m].htotal = cfg->modes[m].hdisplay + 160;
            out->modes[m].vtotal = cfg->modes[m].vdisplay + 50;
            out->modes[m].vrefresh = cfg->modes[m].clock * 1000 /
                ((cfg->modes[m].hdisplay + 160) *
                 (cfg->modes[m].vdisplay + 50));
            snprintf(out->modes[m].name, sizeof(out->modes[m].name),
                     "%dx%d", cfg->modes[m].hdisplay, cfg->modes[m].vdisplay);
        }
        if (out->n_modes > 0)
            out->current_mode = &out->modes[0];

        /* Init debugfs simulation state */
        snprintf(out->debugfs_dsc_state, sizeof(out->debugfs_dsc_state), "0");
        snprintf(out->debugfs_joiner_state,
                 sizeof(out->debugfs_joiner_state), "0");
    }

    /* Compute pipe masks (init ordering: after pipe enumeration) */
    display->valid_pipe_mask = 0;
    for (int p = 0; p < config->n_pipes; p++)
        if (!config->pipe_fused_off[p])
            display->valid_pipe_mask |= BIT(p);

    display->master_pipe_mask = 0;
    for (int p = 0; p < config->n_pipes - 1; p++)
        if ((display->valid_pipe_mask & BIT(p)) &&
            (display->valid_pipe_mask & BIT(p + 1)))
            display->master_pipe_mask |= BIT(p);
}

void sandbox_display_fini(igt_display_t *display)
{
    _global_display = NULL;
    memset(display, 0, sizeof(*display));
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Test Harness
 * ═══════════════════════════════════════════════════════════════════════════ */

void _sandbox_init(const char *test_name)
{
    memset(&_harness, 0, sizeof(_harness));
    _harness.test_name = test_name;
    printf("IGT-Version: sandbox-1.0\n");
    printf("Starting test: %s\n", test_name);
}

void _sandbox_exit(void)
{
    printf("\n=== Results for %s ===\n", _harness.test_name);
    printf("  Passed: %d\n", _harness.total_pass);
    printf("  Skipped: %d\n", _harness.total_skip);
    printf("  Failed: %d\n", _harness.total_fail);
    printf("  Total:  %d\n",
           _harness.total_pass + _harness.total_skip + _harness.total_fail);

    /* Run exit handlers */
    for (int i = _n_exit_handlers - 1; i >= 0; i--)
        if (_exit_handlers[i])
            _exit_handlers[i](0);

    if (_harness.total_fail > 0)
        exit(1);
}

int _sandbox_begin_subtest(const char *name)
{
    _harness.current_subtest = name;
    _harness.subtest_result = _TEST_RUNNING;
    _harness.in_subtest = true;
    _harness.skip_reason[0] = '\0';
    printf("\n  Starting subtest: %s\n", name);
    return 1;
}

void _sandbox_end_subtest(void)
{
    if (!_harness.in_subtest)
        return;

    if (_harness.subtest_result == _TEST_RUNNING)
        _harness.subtest_result = _TEST_PASS;

    switch (_harness.subtest_result) {
    case _TEST_PASS:
        printf("  Subtest %s: SUCCESS\n", _harness.current_subtest);
        _harness.total_pass++;
        break;
    case _TEST_SKIP:
        printf("  Subtest %s: SKIP (%s)\n", _harness.current_subtest,
               _harness.skip_reason[0] ? _harness.skip_reason : "skipped");
        _harness.total_skip++;
        break;
    case _TEST_FAIL:
        printf("  Subtest %s: FAIL\n", _harness.current_subtest);
        _harness.total_fail++;
        break;
    }
    _harness.in_subtest = false;
}

int _sandbox_begin_subtest_dynamic(const char *name)
{
    _harness.current_subtest = name;
    _harness.in_subtest = true;
    _harness.dyn_pass = _harness.dyn_skip = _harness.dyn_fail = 0;
    printf("\n  Starting subtest: %s\n", name);
    return 1;
}

void _sandbox_end_subtest_dynamic(void)
{
    if (_harness.dyn_pass > 0 || _harness.dyn_fail > 0) {
        printf("  Subtest %s: %s (%d passed, %d skipped, %d failed)\n",
               _harness.current_subtest,
               _harness.dyn_fail ? "FAIL" : "SUCCESS",
               _harness.dyn_pass, _harness.dyn_skip, _harness.dyn_fail);
        if (_harness.dyn_fail)
            _harness.total_fail++;
        else
            _harness.total_pass++;
    } else if (_harness.dyn_skip > 0) {
        printf("  Subtest %s: SKIP (all dynamic subtests skipped)\n",
               _harness.current_subtest);
        _harness.total_skip++;
    } else {
        printf("  Subtest %s: SKIP (no dynamic subtests ran)\n",
               _harness.current_subtest);
        _harness.total_skip++;
    }
    _harness.in_subtest = false;
}

int _sandbox_begin_dynamic(const char *name)
{
    _harness.dynamic_result = _TEST_RUNNING;
    _harness.in_dynamic = true;
    _harness.skip_reason[0] = '\0';
    printf("    Starting dynamic subtest: %s\n", name);
    return 1;
}

void _sandbox_end_dynamic(void)
{
    if (!_harness.in_dynamic)
        return;

    if (_harness.dynamic_result == _TEST_RUNNING)
        _harness.dynamic_result = _TEST_PASS;

    switch (_harness.dynamic_result) {
    case _TEST_PASS:
        printf("    Dynamic subtest: SUCCESS\n");
        _harness.dyn_pass++;
        break;
    case _TEST_SKIP:
        printf("    Dynamic subtest: SKIP (%s)\n",
               _harness.skip_reason[0] ? _harness.skip_reason : "skipped");
        _harness.dyn_skip++;
        break;
    case _TEST_FAIL:
        printf("    Dynamic subtest: FAIL\n");
        _harness.dyn_fail++;
        break;
    }
    _harness.in_dynamic = false;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Simulated DRM Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

drmModeModeInfo *igt_output_get_mode(igt_output_t *output)
{
    if (output->has_override)
        return &output->override_mode;
    return output->current_mode;
}

void igt_output_override_mode(igt_output_t *output, drmModeModeInfo *mode)
{
    memcpy(&output->override_mode, mode, sizeof(*mode));
    output->has_override = true;
}

void igt_output_set_crtc(igt_output_t *output, enum pipe pipe)
{
    output->pipe = pipe;
    output->pipe_assigned = true;
}

void igt_output_set_prop_value(igt_output_t *output, int prop, uint64_t val)
{
    (void)output; (void)prop; (void)val;
    /* Simulation: just accept it */
}

bool igt_output_has_prop(igt_output_t *output, int prop)
{
    switch (prop) {
    case IGT_CONNECTOR_HDR_OUTPUT_METADATA:
        return output->sim_config->caps.hdr_prop;
    case IGT_CONNECTOR_VRR_CAPABLE:
        return output->sim_config->caps.vrr_capable;
    case IGT_CONNECTOR_CONTENT_PROTECTION:
        return output->sim_config->caps.hdcp;
    default:
        return true;
    }
}

igt_plane_t *igt_output_get_plane_type(igt_output_t *output, int type)
{
    (void)type;
    output->primary_plane.plane_type = DRM_PLANE_TYPE_PRIMARY;
    return &output->primary_plane;
}

void igt_plane_set_fb(igt_plane_t *plane, igt_fb_t *fb)
{
    plane->fb = fb;
    plane->has_fb = true;
}

void igt_create_fb(int fd, uint32_t w, uint32_t h,
                   uint32_t format, uint64_t modifier, igt_fb_t *fb)
{
    static uint32_t fb_id_counter = 100;
    (void)fd;
    memset(fb, 0, sizeof(*fb));
    fb->fb_id = fb_id_counter++;
    fb->width = w;
    fb->height = h;
    fb->format = format;
    fb->modifier = modifier;
    fb->valid = true;
}

void igt_create_pattern_fb(int fd, uint32_t w, uint32_t h,
                           uint32_t format, uint64_t modifier, igt_fb_t *fb)
{
    igt_create_fb(fd, w, h, format, modifier, fb);
}

void igt_remove_fb(int fd, igt_fb_t *fb)
{
    (void)fd;
    fb->valid = false;
}

int igt_display_commit2(igt_display_t *display, int flags)
{
    (void)display; (void)flags;
    igt_info("Commit: atomic commit simulated (SUCCESS)\n");
    return 0;
}

int igt_display_try_commit2(igt_display_t *display, int flags)
{
    (void)display; (void)flags;
    return 0; /* success */
}

void igt_display_require(igt_display_t *display, int fd)
{
    (void)fd;
    /* In sandbox, display is already initialized via sandbox_display_init */
    igt_require(display->n_outputs > 0);
}

void igt_display_fini(igt_display_t *display)
{
    for (int i = 0; i < display->n_outputs; i++) {
        display->outputs[i].pipe = PIPE_NONE;
        display->outputs[i].pipe_assigned = false;
        display->outputs[i].has_override = false;
    }
}

int igt_get_max_dotclock(int fd)
{
    (void)fd;
    if (_global_display && _global_display->sim_config)
        return _global_display->sim_config->max_dotclock;
    return 594000; /* default */
}

int igt_get_max_pipe_width(int fd)
{
    (void)fd;
    if (_global_display && _global_display->sim_config)
        return _global_display->sim_config->max_pipe_width;
    return 5120; /* default */
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Layer 1 — Feature Detection Predicates
 * ═══════════════════════════════════════════════════════════════════════════ */

bool igt_source_has_dsc(int fd)
{
    (void)fd;
    if (!_global_display) return false;
    /* Source supports DSC if any output config says so */
    for (int i = 0; i < _global_display->n_outputs; i++)
        if (_global_display->outputs[i].sim_config->caps.dsc_source)
            return true;
    return false;
}

bool igt_source_has_joiner(int fd)
{
    (void)fd;
    if (!_global_display) return false;
    for (int i = 0; i < _global_display->n_outputs; i++)
        if (_global_display->outputs[i].sim_config->caps.max_joiner_level > 0)
            return true;
    return false;
}

bool igt_output_has_dsc(int fd, igt_output_t *output)
{
    (void)fd;
    if (!output->sim_config->caps.dsc_source)
        return false;
    if (!output->sim_config->caps.dsc_sink)
        return false;
    if (!output->is_internal && !output->sim_config->caps.fec)
        return false;
    return true;
}

igt_feature_status_t igt_output_check_dsc(int fd, igt_output_t *output)
{
    (void)fd;
    if (!output->sim_config->caps.dsc_source)
        return IGT_FEATURE_NO_SOURCE;
    if (!output->sim_config->caps.dsc_sink)
        return IGT_FEATURE_NO_SINK;
    if (!output->is_internal && !output->sim_config->caps.fec)
        return IGT_FEATURE_NO_FEC;
    return IGT_FEATURE_OK;
}

void igt_output_require_dsc(int fd, igt_output_t *output)
{
    igt_feature_status_t st = igt_output_check_dsc(fd, output);
    switch (st) {
    case IGT_FEATURE_OK: return;
    case IGT_FEATURE_NO_SOURCE:
        igt_skip("DSC: GPU does not have DSC encoder\n");
    case IGT_FEATURE_NO_SINK:
        igt_skip("DSC: sink %s does not support DSC\n", output->name);
    case IGT_FEATURE_NO_FEC:
        igt_skip("DSC: external %s requires FEC\n", output->name);
    default:
        igt_skip("DSC: not supported on %s\n", output->name);
    }
}

bool igt_output_has_hdr(int fd, igt_output_t *output)
{
    (void)fd;
    if (!output->sim_config->caps.hdr_prop)
        return false;
    if (!output->sim_config->caps.hdr_panel)
        return false;
    return true;
}

void igt_output_require_hdr(int fd, igt_output_t *output)
{
    igt_require_f(igt_output_has_hdr(fd, output),
                  "HDR not supported on %s\n", output->name);
}

bool igt_output_has_vrr(int fd, igt_output_t *output)
{
    (void)fd;
    return output->sim_config->caps.vrr_capable;
}

bool igt_output_get_vrr_range(int fd, igt_output_t *output,
                              int *min_hz, int *max_hz)
{
    (void)fd;
    if (!output->sim_config->caps.vrr_capable)
        return false;
    if (min_hz) *min_hz = output->sim_config->caps.vrr_min_hz;
    if (max_hz) *max_hz = output->sim_config->caps.vrr_max_hz;
    return true;
}

void igt_output_require_vrr(int fd, igt_output_t *output)
{
    igt_require_f(igt_output_has_vrr(fd, output),
                  "VRR not supported on %s\n", output->name);
}

bool igt_output_has_psr(int fd, igt_output_t *output, enum psr_mode mode)
{
    (void)fd; (void)mode;
    return output->sim_config->caps.psr;
}

void igt_output_require_psr(int fd, igt_output_t *output, enum psr_mode mode)
{
    igt_require_f(igt_output_has_psr(fd, output, mode),
                  "PSR mode %d not supported on %s\n", mode, output->name);
}

bool igt_pipe_has_fbc(int fd, enum pipe pipe)
{
    (void)fd;
    if (!_global_display) return false;
    /* Check any output assigned to this pipe */
    for (int i = 0; i < _global_display->n_outputs; i++)
        if (_global_display->outputs[i].pipe == pipe)
            return _global_display->outputs[i].sim_config->caps.fbc;
    return false;
}

bool igt_output_has_content_protection(int fd, igt_output_t *output)
{
    (void)fd;
    return output->sim_config->caps.hdcp;
}

bool igt_output_has_drrs(int fd, igt_output_t *output)
{
    (void)fd;
    return output->sim_config->caps.drrs;
}

bool igt_output_has_force_joiner(int fd, igt_output_t *output)
{
    (void)fd;
    return output->sim_config->caps.force_joiner;
}

enum joined_pipes igt_output_get_max_joiner(int fd, igt_output_t *output)
{
    (void)fd;
    return (enum joined_pipes)output->sim_config->caps.max_joiner_level;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Layer 2 — Joiner-Aware Pipe Allocator
 * ═══════════════════════════════════════════════════════════════════════════ */

uint32_t igt_get_valid_pipe_mask(igt_display_t *display)
{
    return display->valid_pipe_mask;
}

uint32_t igt_get_master_pipe_mask(igt_display_t *display)
{
    return display->master_pipe_mask;
}

int igt_compute_required_pipes(int fd, igt_output_t *output,
                               const struct igt_modeset_intent *intent)
{
    int max_dotclock = igt_get_max_dotclock(fd);
    int max_pipe_width = igt_get_max_pipe_width(fd);
    int effective_clock;
    int hdisplay;

    (void)output;

    /* Forced minimum joiner always wins */
    if (intent->min_joiner >= JOINED_PIPES_ULTRA_JOINER)
        return 4;
    if (intent->min_joiner >= JOINED_PIPES_BIG_JOINER)
        return 2;

    hdisplay = intent->mode.hdisplay;

    /* Width-based joiner requirement */
    if (max_pipe_width > 0) {
        if (hdisplay > 2 * max_pipe_width)
            return 4;
        if (hdisplay > max_pipe_width)
            return 2;
    }

    /* Dotclock-based joiner requirement */
    if (max_dotclock <= 0)
        return 1;

    effective_clock = intent->mode.clock;
    if (intent->dsc)
        effective_clock = effective_clock / 2;
    if (intent->bpc > 8)
        effective_clock = effective_clock * intent->bpc / 8;

    if (effective_clock > 2 * max_dotclock)
        return 4;
    if (effective_clock > max_dotclock)
        return 2;

    return 1;
}

int igt_output_get_required_pipes(int fd, igt_output_t *output)
{
    struct igt_modeset_intent intent;
    drmModeModeInfo *mode = igt_output_get_mode(output);

    if (!mode)
        return 1;

    memset(&intent, 0, sizeof(intent));
    memcpy(&intent.mode, mode, sizeof(intent.mode));
    return igt_compute_required_pipes(fd, output, &intent);
}

int igt_find_consecutive_pipes(int n_crtcs, uint32_t available_mask,
                               int need)
{
    int p, k;
    bool all_free;

    if (need == 1) {
        for (p = 0; p < n_crtcs; p++)
            if (available_mask & BIT(p))
                return p;
        return -1;
    }

    /* For need >= 2: check full [p, p+need) range is available */
    for (p = 0; p <= n_crtcs - need; p++) {
        all_free = true;
        for (k = 0; k < need; k++) {
            if (!(available_mask & BIT(p + k))) {
                all_free = false;
                break;
            }
        }
        if (all_free)
            return p;
    }
    return -1;
}

int igt_allocate_pipes(igt_display_t *display,
                       igt_output_t **outputs, int n_outputs,
                       uint32_t *used_pipes)
{
    uint32_t avail = display->valid_pipe_mask;
    int fd = display->drm_fd;
    int requirements[IGT_MAX_OUTPUTS];
    int order[IGT_MAX_OUTPUTS];
    int i, j, idx, need, master, tmp;

    if (used_pipes)
        avail &= ~(*used_pipes);

    for (i = 0; i < n_outputs; i++) {
        requirements[i] = igt_output_get_required_pipes(fd, outputs[i]);
        order[i] = i;
    }

    /* Sort descending (4-pipe first, then 2, then 1) */
    for (i = 0; i < n_outputs - 1; i++)
        for (j = i + 1; j < n_outputs; j++)
            if (requirements[order[i]] < requirements[order[j]]) {
                tmp = order[i];
                order[i] = order[j];
                order[j] = tmp;
            }

    for (i = 0; i < n_outputs; i++) {
        idx = order[i];
        need = requirements[idx];
        master = igt_find_consecutive_pipes(display->n_pipes, avail, need);
        if (master < 0)
            return -1;

        igt_output_set_crtc(outputs[idx], (enum pipe)master);
        for (j = master; j < master + need; j++)
            avail &= ~BIT(j);
    }

    if (used_pipes)
        *used_pipes = display->valid_pipe_mask & ~avail;
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Layer 3 — Multi-Output Setup Builder
 * ═══════════════════════════════════════════════════════════════════════════ */

int igt_multi_output_find(igt_display_t *display, int fd,
                          igt_output_spec_t *specs, int n_specs,
                          igt_multi_output_ctx_t *ctx)
{
    int i;
    igt_output_t *output;
    bool claimed[IGT_MAX_OUTPUTS];

    memset(ctx, 0, sizeof(*ctx));
    ctx->display = display;
    ctx->fd = fd;
    ctx->n_specs = n_specs;
    ctx->specs = specs;

    memset(claimed, 0, sizeof(claimed));

    for (i = 0; i < n_specs; i++) {
        if (specs[i].output)
            continue; /* already set by test author */

        bool found = false;
        for_each_connected_output(display, output) {
            int idx = (int)(output - display->outputs);
            if (claimed[idx])
                continue;
            if (specs[i].predicate && !specs[i].predicate(fd, output))
                continue;
            specs[i].output = output;
            claimed[idx] = true;
            found = true;
            break;
        }
        if (!found)
            return -1;
    }
    return 0;
}

int igt_multi_output_select_modes(igt_multi_output_ctx_t *ctx)
{
    int i;
    for (i = 0; i < ctx->n_specs; i++) {
        if (ctx->specs[i].find_mode) {
            if (!ctx->specs[i].find_mode(ctx->fd, ctx->specs[i].output,
                                          &ctx->specs[i].mode))
                return -1;
            igt_output_override_mode(ctx->specs[i].output,
                                     &ctx->specs[i].mode);
        } else {
            drmModeModeInfo *m = igt_output_get_mode(ctx->specs[i].output);
            if (m)
                memcpy(&ctx->specs[i].mode, m, sizeof(ctx->specs[i].mode));
        }
    }
    return 0;
}

int igt_multi_output_allocate_pipes(igt_multi_output_ctx_t *ctx)
{
    igt_output_t *outputs[IGT_MAX_OUTPUTS];
    int i;
    for (i = 0; i < ctx->n_specs; i++)
        outputs[i] = ctx->specs[i].output;
    return igt_allocate_pipes(ctx->display, outputs, ctx->n_specs,
                              &ctx->used_pipes);
}

void igt_multi_output_create_fbs(igt_multi_output_ctx_t *ctx)
{
    int i;
    for (i = 0; i < ctx->n_specs; i++) {
        uint32_t fmt = ctx->specs[i].format ?
                       ctx->specs[i].format : DRM_FORMAT_XRGB8888;
        uint64_t mod = ctx->specs[i].modifier;
        drmModeModeInfo *m = igt_output_get_mode(ctx->specs[i].output);

        igt_create_fb(ctx->fd, m->hdisplay, m->vdisplay,
                      fmt, mod, &ctx->specs[i].fb);

        igt_plane_t *primary = igt_output_get_plane_type(
            ctx->specs[i].output, DRM_PLANE_TYPE_PRIMARY);
        igt_plane_set_fb(primary, &ctx->specs[i].fb);
    }
}

int igt_multi_output_validate_bw(igt_multi_output_ctx_t *ctx)
{
    return igt_display_try_commit2(ctx->display, COMMIT_ATOMIC);
}

int igt_multi_output_try_setup(igt_display_t *display, int fd,
                               igt_output_spec_t *specs, int n_specs,
                               igt_multi_output_ctx_t *ctx)
{
    int ret;
    ret = igt_multi_output_find(display, fd, specs, n_specs, ctx);
    if (ret < 0) return ret;
    ret = igt_multi_output_select_modes(ctx);
    if (ret < 0) return ret;
    ret = igt_multi_output_allocate_pipes(ctx);
    if (ret < 0) return ret;
    igt_multi_output_create_fbs(ctx);
    ret = igt_multi_output_validate_bw(ctx);
    if (ret < 0) {
        igt_multi_output_teardown(ctx);
        return ret;
    }
    return 0;
}

void igt_multi_output_setup(igt_display_t *display, int fd,
                            igt_output_spec_t *specs, int n_specs,
                            igt_multi_output_ctx_t *ctx)
{
    int ret = igt_multi_output_try_setup(display, fd, specs, n_specs, ctx);
    igt_require_f(ret == 0,
                  "Multi-output setup failed: not enough matching "
                  "outputs or pipes\n");
}

void igt_multi_output_commit(igt_multi_output_ctx_t *ctx)
{
    igt_display_commit2(ctx->display, COMMIT_ATOMIC);
    ctx->committed = true;
}

int igt_multi_output_try_commit(igt_multi_output_ctx_t *ctx)
{
    int ret = igt_display_try_commit2(ctx->display, COMMIT_ATOMIC);
    if (ret == 0) ctx->committed = true;
    return ret;
}

void igt_multi_output_teardown(igt_multi_output_ctx_t *ctx)
{
    int i;
    for (i = 0; i < ctx->n_specs; i++) {
        if (ctx->specs[i].fb.valid)
            igt_remove_fb(ctx->fd, &ctx->specs[i].fb);
        if (ctx->specs[i].output) {
            ctx->specs[i].output->has_override = false;
            ctx->specs[i].output->pipe_assigned = false;
        }
    }
    ctx->used_pipes = 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Layer 4 — Bandwidth-Safe Commit
 * ═══════════════════════════════════════════════════════════════════════════ */

bool igt_bw_safe_commit(igt_display_t *display)
{
    int ret = igt_display_try_commit2(display, COMMIT_ATOMIC);
    if (ret != 0)
        return false;
    igt_display_commit2(display, COMMIT_ATOMIC);
    return true;
}

int igt_try_bw_commit(igt_display_t *display)
{
    return igt_display_try_commit2(display, COMMIT_ATOMIC);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Layer 5 — Debugfs State Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

void igt_install_exit_handler(sandbox_exit_handler_t handler)
{
    if (_n_exit_handlers < MAX_EXIT_HANDLERS)
        _exit_handlers[_n_exit_handlers++] = handler;
}

static void _guard_exit_handler(int sig)
{
    int i;
    (void)sig;
    for (i = 0; i < _n_active_guards; i++) {
        if (_active_guards[i] && _active_guards[i]->active) {
            igt_info("EXIT HANDLER: Restoring %s on %s\n",
                     _active_guards[i]->attr_name,
                     _active_guards[i]->output ?
                         _active_guards[i]->output->name : "?");
            _active_guards[i]->active = false;
        }
    }
    _n_active_guards = 0;
}

void igt_debugfs_guard_begin(int fd, igt_output_t *output,
                             const char *debugfs_attr,
                             igt_debugfs_guard_t *guard)
{
    (void)fd;
    memset(guard, 0, sizeof(*guard));
    guard->dir_fd = 42; /* simulated */
    guard->attr_name = debugfs_attr;
    guard->output = output;
    guard->active = true;

    /* Simulated read of current debugfs value */
    if (strcmp(debugfs_attr, "i915_dsc_fec_support") == 0)
        snprintf(guard->original_value, sizeof(guard->original_value),
                 "%s", output->debugfs_dsc_state);
    else if (strcmp(debugfs_attr, "i915_bigjoiner_force_enable") == 0)
        snprintf(guard->original_value, sizeof(guard->original_value),
                 "%s", output->debugfs_joiner_state);
    else
        snprintf(guard->original_value, sizeof(guard->original_value), "0");

    guard->original_len = (int)strlen(guard->original_value);

    /* Register in global list */
    if (_n_active_guards < MAX_ACTIVE_GUARDS)
        _active_guards[_n_active_guards++] = guard;

    /* Install exit handler ONCE */
    if (!_guard_exit_handler_installed) {
        igt_install_exit_handler(_guard_exit_handler);
        _guard_exit_handler_installed = true;
    }

    igt_info("Guard BEGIN: saved %s = \"%s\" on %s\n",
             debugfs_attr, guard->original_value, output->name);
}

void igt_debugfs_guard_end(igt_debugfs_guard_t *guard)
{
    int i;
    if (!guard->active)
        return;

    igt_info("Guard END: restoring %s = \"%s\" on %s\n",
             guard->attr_name, guard->original_value,
             guard->output ? guard->output->name : "?");

    /* Simulated write restore */
    if (guard->output) {
        if (strcmp(guard->attr_name, "i915_dsc_fec_support") == 0)
            snprintf(guard->output->debugfs_dsc_state,
                     sizeof(guard->output->debugfs_dsc_state),
                     "%s", guard->original_value);
        else if (strcmp(guard->attr_name, "i915_bigjoiner_force_enable") == 0)
            snprintf(guard->output->debugfs_joiner_state,
                     sizeof(guard->output->debugfs_joiner_state),
                     "%s", guard->original_value);
    }

    guard->active = false;

    for (i = 0; i < _n_active_guards; i++) {
        if (_active_guards[i] == guard) {
            _active_guards[i] = _active_guards[--_n_active_guards];
            break;
        }
    }
}

void igt_intel_dsc_guard_begin(int fd, igt_output_t *output,
                               igt_debugfs_guard_t *guard)
{
    igt_debugfs_guard_begin(fd, output, "i915_dsc_fec_support", guard);
}

void igt_intel_dsc_guard_end(igt_debugfs_guard_t *guard)
{
    igt_debugfs_guard_end(guard);
}

void igt_intel_joiner_guard_begin(int fd, igt_output_t *output,
                                  igt_debugfs_guard_t *guard)
{
    igt_debugfs_guard_begin(fd, output,
                           "i915_bigjoiner_force_enable", guard);
}

void igt_intel_joiner_guard_end(igt_debugfs_guard_t *guard)
{
    igt_debugfs_guard_end(guard);
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Layer 6 — Output Classifier
 * ═══════════════════════════════════════════════════════════════════════════ */

void igt_classify_outputs(igt_display_t *display, int fd,
                          bool (*predicate)(int fd, igt_output_t *),
                          igt_output_t **match, int *match_count,
                          igt_output_t **no_match, int *no_match_count)
{
    igt_output_t *output;
    int m = 0, n = 0;

    for_each_connected_output(display, output) {
        if (predicate(fd, output)) {
            if (match) match[m] = output;
            m++;
        } else {
            if (no_match) no_match[n] = output;
            n++;
        }
    }
    if (match_count) *match_count = m;
    if (no_match_count) *no_match_count = n;
}

igt_output_t *igt_find_output_with(igt_display_t *display, int fd,
                                   bool (*pred)(int fd, igt_output_t *))
{
    igt_output_t *output;
    for_each_connected_output(display, output)
        if (pred(fd, output))
            return output;
    return NULL;
}

int igt_count_outputs_with(igt_display_t *display, int fd,
                           bool (*pred)(int fd, igt_output_t *))
{
    igt_output_t *output;
    int count = 0;
    for_each_connected_output(display, output)
        if (pred(fd, output))
            count++;
    return count;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Layer 7 — Composition Macros (Combo Iterator)
 * ═══════════════════════════════════════════════════════════════════════════ */

static bool _try_assign_slot(igt_combo_iter_t *iter,
                             igt_output_t **outputs, int slot)
{
    int c, j;
    for (c = iter->cursor[slot]; c < iter->n_connected; c++) {
        igt_output_t *candidate = iter->connected[c];
        bool claimed = false;

        for (j = 0; j < slot; j++) {
            if (outputs[j] == candidate) {
                claimed = true;
                break;
            }
        }
        if (claimed) continue;

        if (!iter->preds[slot](iter->fd, candidate))
            continue;

        iter->cursor[slot] = c;
        outputs[slot] = candidate;
        return true;
    }
    return false;
}

static bool _find_combo_from_slot(igt_combo_iter_t *iter,
                                  igt_output_t **outputs,
                                  int start_slot)
{
    int slot, d;
    uint32_t dummy = 0;

    for (slot = start_slot; slot < iter->n_slots; slot++) {
        if (!_try_assign_slot(iter, outputs, slot))
            return false;
        for (d = slot + 1; d < iter->n_slots; d++)
            iter->cursor[d] = 0;
    }

    return igt_allocate_pipes(iter->display, outputs,
                              iter->n_slots, &dummy) == 0;
}

static bool _backtrack(igt_combo_iter_t *iter, igt_output_t **outputs)
{
    int slot, d;
    for (slot = iter->n_slots - 1; slot >= 0; slot--) {
        outputs[slot] = NULL;
        iter->cursor[slot]++;

        if (iter->cursor[slot] < iter->n_connected) {
            for (d = slot + 1; d < iter->n_slots; d++)
                iter->cursor[d] = 0;
            return true;
        }
        iter->cursor[slot] = 0;
    }
    iter->exhausted = true;
    return false;
}

int _first_output_combo(igt_display_t *display, igt_combo_iter_t *iter,
                        igt_output_t **outputs, int n,
                        bool (**preds)(int, igt_output_t *))
{
    igt_output_t *output;
    int s;

    memset(iter, 0, sizeof(*iter));
    iter->display = display;
    iter->fd = display->drm_fd;
    iter->preds = preds;
    iter->n_slots = n;

    iter->n_connected = 0;
    for_each_connected_output(display, output)
        iter->connected[iter->n_connected++] = output;

    for (s = 0; s < n; s++) {
        iter->cursor[s] = 0;
        outputs[s] = NULL;
    }
    iter->initialized = true;

    /* Find first valid combo */
    while (!iter->exhausted) {
        if (_find_combo_from_slot(iter, outputs, 0))
            return 1;
        if (!_backtrack(iter, outputs))
            return 0;
    }
    return 0;
}

int _next_output_combo(igt_combo_iter_t *iter, igt_output_t **outputs)
{
    int slot;
    if (iter->exhausted)
        return 0;

    while (true) {
        if (!_backtrack(iter, outputs))
            return 0;

        /* Find which slot was advanced */
        for (slot = iter->n_slots - 1; slot >= 0; slot--) {
            if (outputs[slot] == NULL) {
                break;
            }
        }
        if (slot < 0) slot = 0;

        if (_find_combo_from_slot(iter, outputs, slot))
            return 1;
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Layer 8 — Convenience Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

igt_plane_t *igt_output_setup_fb(int fd, igt_output_t *output,
                                 uint32_t format, uint64_t modifier,
                                 igt_fb_t *fb)
{
    drmModeModeInfo *mode = igt_output_get_mode(output);
    igt_plane_t *primary;

    igt_create_fb(fd, mode->hdisplay, mode->vdisplay,
                  format, modifier, fb);

    primary = igt_output_get_plane_type(output, DRM_PLANE_TYPE_PRIMARY);
    igt_plane_set_fb(primary, fb);
    return primary;
}

bool igt_find_joiner_mode(int fd, igt_output_t *output,
                          enum joined_pipes level, drmModeModeInfo *mode)
{
    int max_dotclock = igt_get_max_dotclock(fd);
    int max_pipe_width = igt_get_max_pipe_width(fd);
    int clock_threshold, width_threshold;
    int i;
    bool needs_joiner;

    switch (level) {
    case JOINED_PIPES_BIG_JOINER:
        clock_threshold = max_dotclock;
        width_threshold = max_pipe_width;
        break;
    case JOINED_PIPES_ULTRA_JOINER:
        clock_threshold = 2 * max_dotclock;
        width_threshold = 2 * max_pipe_width;
        break;
    default:
        return false;
    }

    for (i = 0; i < output->n_modes; i++) {
        needs_joiner = false;
        if (max_dotclock > 0 && (int)output->modes[i].clock > clock_threshold)
            needs_joiner = true;
        if (max_pipe_width > 0 &&
            output->modes[i].hdisplay > width_threshold)
            needs_joiner = true;

        if (needs_joiner) {
            memcpy(mode, &output->modes[i], sizeof(*mode));
            return true;
        }
    }
    return false;
}

bool igt_find_non_joiner_mode(int fd, igt_output_t *output,
                              drmModeModeInfo *mode)
{
    int max_dotclock = igt_get_max_dotclock(fd);
    int max_pipe_width = igt_get_max_pipe_width(fd);
    int i;

    for (i = 0; i < output->n_modes; i++) {
        if ((max_dotclock <= 0 ||
             (int)output->modes[i].clock <= max_dotclock) &&
            (max_pipe_width <= 0 ||
             output->modes[i].hdisplay <= max_pipe_width)) {
            memcpy(mode, &output->modes[i], sizeof(*mode));
            return true;
        }
    }
    return false;
}

/* Simulated DSC enable/check */
void force_dsc_enable(int fd, igt_output_t *output)
{
    (void)fd;
    snprintf(output->debugfs_dsc_state,
             sizeof(output->debugfs_dsc_state), "1");
    output->dsc_enabled = true;
    igt_info("Simulated: DSC enabled on %s\n", output->name);
}

bool igt_is_dsc_enabled(int fd, const char *output_name)
{
    int i;
    (void)fd;
    if (!_global_display) return false;
    for (i = 0; i < _global_display->n_outputs; i++)
        if (strcmp(_global_display->outputs[i].name, output_name) == 0)
            return _global_display->outputs[i].dsc_enabled;
    return false;
}
