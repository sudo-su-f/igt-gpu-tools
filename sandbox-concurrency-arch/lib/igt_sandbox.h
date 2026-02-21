/*
 * igt_sandbox.h — Self-contained sandbox for KMS Test Architecture validation
 *
 * This header provides:
 *   1. Simulated DRM/KMS types (drmModeModeInfo, connectors, pipes, etc.)
 *   2. A configurable display simulator (number of outputs, pipes, features)
 *   3. IGT-compatible test harness (igt_main, igt_subtest, setjmp/longjmp)
 *   4. All 8 layers of the proposed KMS test infrastructure
 *
 * No real GPU or DRM device required. All hardware is simulated.
 */

#ifndef IGT_SANDBOX_H
#define IGT_SANDBOX_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Section 1: Constants & Basic Types
 * ═══════════════════════════════════════════════════════════════════════════ */

#define IGT_MAX_PIPES       8
#define IGT_MAX_OUTPUTS     16
#define IGT_MAX_MODES       16
#define SANDBOX_FD          3       /* Fake DRM file descriptor */

#ifndef BIT
#define BIT(x) (1U << (x))
#endif

/* Simulated DRM connector types */
#define DRM_MODE_CONNECTOR_DP       10
#define DRM_MODE_CONNECTOR_eDP      14
#define DRM_MODE_CONNECTOR_HDMIA    11
#define DRM_MODE_CONNECTOR_HDMIB    12
#define DRM_MODE_CONNECTOR_VGA      1

/* Simulated DRM formats */
#define DRM_FORMAT_XRGB8888         0x34325258
#define DRM_FORMAT_XRGB2101010      0x30335258
#define DRM_FORMAT_MOD_LINEAR       0ULL

/* Simulated plane types */
#define DRM_PLANE_TYPE_PRIMARY      1
#define DRM_PLANE_TYPE_OVERLAY      2
#define DRM_PLANE_TYPE_CURSOR       3

/* Simulated DRM properties */
#define COMMIT_ATOMIC               1

/* Simulated DRM mode info — only the fields we actually use */
typedef struct {
    uint32_t clock;         /* pixel clock in kHz */
    uint16_t hdisplay;
    uint16_t vdisplay;
    uint16_t htotal;
    uint16_t vtotal;
    uint32_t vrefresh;
    char name[32];
} drmModeModeInfo;

/* Pipe enumeration */
enum pipe {
    PIPE_A = 0, PIPE_B, PIPE_C, PIPE_D,
    PIPE_E, PIPE_F, PIPE_G, PIPE_H,
    PIPE_NONE = -1
};

/* Joiner levels */
enum joined_pipes {
    JOINED_PIPES_NONE = 0,
    JOINED_PIPES_BIG_JOINER = 1,    /* 2 pipes */
    JOINED_PIPES_ULTRA_JOINER = 2,  /* 4 pipes */
};

/* PSR modes */
enum psr_mode {
    PSR_MODE_1 = 1,
    PSR_MODE_2 = 2,
};

/* Feature status (rich diagnostics) */
typedef enum {
    IGT_FEATURE_OK = 0,
    IGT_FEATURE_NO_SOURCE,
    IGT_FEATURE_NO_SINK,
    IGT_FEATURE_NO_FEC,
    IGT_FEATURE_NO_PROPERTY,
    IGT_FEATURE_NO_EDID_DATA,
    IGT_FEATURE_WRONG_CONNECTOR,
} igt_feature_status_t;

/* Connector property IDs */
enum igt_connector_prop {
    IGT_CONNECTOR_HDR_OUTPUT_METADATA = 100,
    IGT_CONNECTOR_MAX_BPC = 101,
    IGT_CONNECTOR_SCALING_MODE = 102,
    IGT_CONNECTOR_VRR_CAPABLE = 103,
    IGT_CONNECTOR_CONTENT_PROTECTION = 104,
};

enum igt_crtc_prop {
    IGT_CRTC_DEGAMMA_LUT = 200,
    IGT_CRTC_GAMMA_LUT = 201,
    IGT_CRTC_CTM = 202,
};


/* ═══════════════════════════════════════════════════════════════════════════
 * Section 2: Simulation Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * sandbox_output_config_t — Configure a simulated output
 *
 * Tests fill this in to describe the simulated hardware topology.
 */
typedef struct {
    const char *name;           /* "DP-1", "eDP-1", "HDMI-A-1" etc. */
    int connector_type;         /* DRM_MODE_CONNECTOR_* */
    bool connected;
    bool is_internal;           /* eDP panel */

    /* Feature capabilities */
    struct {
        bool dsc_source;        /* GPU has DSC encoder */
        bool dsc_sink;          /* Monitor supports DSC */
        bool fec;               /* FEC available */
        bool hdr_panel;         /* HDR metadata in EDID */
        bool hdr_prop;          /* HDR_OUTPUT_METADATA prop exists */
        bool vrr_capable;
        int vrr_min_hz, vrr_max_hz;
        bool psr;
        bool fbc;               /* Per-pipe FBC */
        bool hdcp;
        bool drrs;
        bool force_joiner;
        int max_joiner_level;   /* 0=none, 1=big, 2=ultra */
    } caps;

    /* Available modes */
    struct {
        uint16_t hdisplay, vdisplay;
        uint32_t clock;         /* kHz */
    } modes[IGT_MAX_MODES];
    int n_modes;
} sandbox_output_config_t;

/**
 * sandbox_display_config_t — Configure the entire simulated display
 */
typedef struct {
    int n_pipes;
    bool pipe_fused_off[IGT_MAX_PIPES];
    int max_dotclock;           /* kHz — single pipe limit */
    int max_pipe_width;         /* pixels — single pipe width limit */

    sandbox_output_config_t outputs[IGT_MAX_OUTPUTS];
    int n_outputs;
} sandbox_display_config_t;


/* ═══════════════════════════════════════════════════════════════════════════
 * Section 3: Core IGT Types (Simulated)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct igt_output igt_output_t;
typedef struct igt_display igt_display_t;
typedef struct igt_plane igt_plane_t;
typedef struct igt_fb igt_fb_t;

struct igt_fb {
    uint32_t fb_id;
    uint32_t width, height;
    uint32_t format;
    uint64_t modifier;
    bool valid;
};

struct igt_plane {
    int plane_type;
    igt_fb_t *fb;
    bool has_fb;
};

struct igt_output {
    char name[64];
    int connector_type;
    bool connected;
    bool is_internal;

    /* Simulated feature caps */
    sandbox_output_config_t *sim_config;

    /* Modes */
    drmModeModeInfo modes[IGT_MAX_MODES];
    int n_modes;
    drmModeModeInfo *current_mode;
    drmModeModeInfo override_mode;
    bool has_override;

    /* Pipe assignment */
    enum pipe pipe;
    bool pipe_assigned;

    /* Primary plane (simplified) */
    igt_plane_t primary_plane;

    /* Simulated debugfs state */
    char debugfs_dsc_state[64];
    char debugfs_joiner_state[64];
    bool dsc_enabled;
};

struct igt_display {
    int drm_fd;             /* always SANDBOX_FD */
    int n_pipes;
    int n_outputs;
    igt_output_t outputs[IGT_MAX_OUTPUTS];

    /* Cached pipe masks (Layer 2 / Layer 9) */
    uint32_t valid_pipe_mask;
    uint32_t master_pipe_mask;

    /* Simulation config reference */
    sandbox_display_config_t *sim_config;
};


/* ═══════════════════════════════════════════════════════════════════════════
 * Section 4: Test Harness
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Mimics IGT's test runner using setjmp/longjmp for skip/fail.
 * Output format matches IGT's stdout format.
 */

/* Result codes (internal) */
#define _TEST_RUNNING       0
#define _TEST_PASS          1
#define _TEST_SKIP          2
#define _TEST_FAIL          3

/* Global test harness state */
typedef struct {
    jmp_buf subtest_jmp;
    jmp_buf dynamic_jmp;
    int subtest_result;
    int dynamic_result;
    int total_pass, total_skip, total_fail;
    int dyn_pass, dyn_skip, dyn_fail;
    const char *current_subtest;
    const char *test_name;
    bool in_subtest;
    bool in_dynamic;
    char skip_reason[256];
} _sandbox_harness_t;

extern _sandbox_harness_t _harness;

/* Initialization */
void sandbox_display_init(igt_display_t *display,
                          const sandbox_display_config_t *config);
void sandbox_display_fini(igt_display_t *display);

/* Test harness functions */
void _sandbox_init(const char *test_name);
void _sandbox_exit(void);
int  _sandbox_begin_subtest(const char *name);
void _sandbox_end_subtest(void);
int  _sandbox_begin_subtest_dynamic(const char *name);
void _sandbox_end_subtest_dynamic(void);
int  _sandbox_begin_dynamic(const char *name);
void _sandbox_end_dynamic(void);

/* ── Macros matching IGT API ─────────────────────────────────────────── */

#define igt_main \
    static void _real_main(void); \
    int main(int argc, char **argv) { \
        (void)argc; (void)argv; \
        _real_main(); \
        return 0; \
    } \
    static void _real_main(void)

#define IGT_TEST_DESCRIPTION(desc) \
    static const char *_test_description = desc

#define igt_fixture \
    for (int __fix = 0; __fix < 1; __fix++)

#define igt_subtest(name) \
    for (int __st = _sandbox_begin_subtest(name); \
         __st && (setjmp(_harness.subtest_jmp) == 0 || \
                  (_sandbox_end_subtest(), 0)); \
         __st = 0, _sandbox_end_subtest())

#define igt_subtest_with_dynamic(name) \
    for (int __st = _sandbox_begin_subtest_dynamic(name); \
         __st; \
         __st = 0, _sandbox_end_subtest_dynamic())

#define igt_dynamic_f(fmt, ...) \
    for (char __dyn_name[256] = {0}; \
         (snprintf(__dyn_name, sizeof(__dyn_name), fmt, ##__VA_ARGS__), \
          _sandbox_begin_dynamic(__dyn_name)) && \
         (setjmp(_harness.dynamic_jmp) == 0 || \
          (_sandbox_end_dynamic(), 0)); \
         _sandbox_end_dynamic())

/* ── Assertions & Requirements ───────────────────────────────────────── */

#define igt_assert(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "  ASSERT FAILED: %s [%s:%d]\n", \
                #expr, __FILE__, __LINE__); \
        if (_harness.in_dynamic) { \
            _harness.dynamic_result = _TEST_FAIL; \
            longjmp(_harness.dynamic_jmp, 1); \
        } else if (_harness.in_subtest) { \
            _harness.subtest_result = _TEST_FAIL; \
            longjmp(_harness.subtest_jmp, 1); \
        } else { \
            exit(1); \
        } \
    } \
} while(0)

#define igt_require(expr) do { \
    if (!(expr)) { \
        snprintf(_harness.skip_reason, sizeof(_harness.skip_reason), \
                 "%s", #expr); \
        if (_harness.in_dynamic) { \
            _harness.dynamic_result = _TEST_SKIP; \
            longjmp(_harness.dynamic_jmp, 1); \
        } else if (_harness.in_subtest) { \
            _harness.subtest_result = _TEST_SKIP; \
            longjmp(_harness.subtest_jmp, 1); \
        } \
    } \
} while(0)

#define igt_require_f(expr, fmt, ...) do { \
    if (!(expr)) { \
        snprintf(_harness.skip_reason, sizeof(_harness.skip_reason), \
                 fmt, ##__VA_ARGS__); \
        if (_harness.in_dynamic) { \
            _harness.dynamic_result = _TEST_SKIP; \
            longjmp(_harness.dynamic_jmp, 1); \
        } else if (_harness.in_subtest) { \
            _harness.subtest_result = _TEST_SKIP; \
            longjmp(_harness.subtest_jmp, 1); \
        } \
    } \
} while(0)

#define igt_skip(fmt, ...) do { \
    snprintf(_harness.skip_reason, sizeof(_harness.skip_reason), \
             fmt, ##__VA_ARGS__); \
    if (_harness.in_dynamic) { \
        _harness.dynamic_result = _TEST_SKIP; \
        longjmp(_harness.dynamic_jmp, 1); \
    } else if (_harness.in_subtest) { \
        _harness.subtest_result = _TEST_SKIP; \
        longjmp(_harness.subtest_jmp, 1); \
    } \
} while(0)

#define igt_info(fmt, ...)  printf("  " fmt, ##__VA_ARGS__)
#define igt_debug(fmt, ...) /* silent in sandbox */


/* ═══════════════════════════════════════════════════════════════════════════
 * Section 5: Simulated DRM Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

drmModeModeInfo *igt_output_get_mode(igt_output_t *output);
void igt_output_override_mode(igt_output_t *output, drmModeModeInfo *mode);
void igt_output_set_crtc(igt_output_t *output, enum pipe pipe);
void igt_output_set_prop_value(igt_output_t *output, int prop, uint64_t val);
bool igt_output_has_prop(igt_output_t *output, int prop);

igt_plane_t *igt_output_get_plane_type(igt_output_t *output, int type);
void igt_plane_set_fb(igt_plane_t *plane, igt_fb_t *fb);

void igt_create_fb(int fd, uint32_t w, uint32_t h,
                   uint32_t format, uint64_t modifier, igt_fb_t *fb);
void igt_create_pattern_fb(int fd, uint32_t w, uint32_t h,
                           uint32_t format, uint64_t modifier, igt_fb_t *fb);
void igt_remove_fb(int fd, igt_fb_t *fb);

int igt_display_commit2(igt_display_t *display, int flags);
int igt_display_try_commit2(igt_display_t *display, int flags);
void igt_display_require(igt_display_t *display, int fd);
void igt_display_fini(igt_display_t *display);

int igt_get_max_dotclock(int fd);
int igt_get_max_pipe_width(int fd);

/* Iteration macros */
#define for_each_connected_output(display, output) \
    for (int __co_i = 0; \
         __co_i < (display)->n_outputs && \
         ((output) = &(display)->outputs[__co_i], 1); \
         __co_i++) \
        for_each_if((output)->connected)

#define for_each_if(expr) if (!(expr)) {} else


/* ═══════════════════════════════════════════════════════════════════════════
 * Section 6: Layer 1 — Feature Detection Predicates
 * ═══════════════════════════════════════════════════════════════════════════ */

bool igt_output_has_dsc(int fd, igt_output_t *output);
bool igt_output_has_hdr(int fd, igt_output_t *output);
bool igt_output_has_vrr(int fd, igt_output_t *output);
bool igt_output_get_vrr_range(int fd, igt_output_t *output,
                              int *min_hz, int *max_hz);
bool igt_output_has_psr(int fd, igt_output_t *output, enum psr_mode mode);
bool igt_pipe_has_fbc(int fd, enum pipe pipe);
bool igt_output_has_content_protection(int fd, igt_output_t *output);
bool igt_output_has_drrs(int fd, igt_output_t *output);
bool igt_output_has_force_joiner(int fd, igt_output_t *output);
enum joined_pipes igt_output_get_max_joiner(int fd, igt_output_t *output);
bool igt_source_has_dsc(int fd);
bool igt_source_has_joiner(int fd);

/* Rich status */
igt_feature_status_t igt_output_check_dsc(int fd, igt_output_t *output);

/* Require variants (FUNCTIONS, not macros — avoids naming collisions) */
void igt_output_require_dsc(int fd, igt_output_t *output);
void igt_output_require_hdr(int fd, igt_output_t *output);
void igt_output_require_vrr(int fd, igt_output_t *output);
void igt_output_require_psr(int fd, igt_output_t *output, enum psr_mode mode);


/* ═══════════════════════════════════════════════════════════════════════════
 * Section 7: Layer 2 — Joiner-Aware Pipe Allocator
 * ═══════════════════════════════════════════════════════════════════════════ */

struct igt_modeset_intent {
    drmModeModeInfo mode;
    uint32_t format;
    uint64_t modifier;
    int bpc;
    bool dsc;
    enum joined_pipes min_joiner;
};

int igt_compute_required_pipes(int fd, igt_output_t *output,
                               const struct igt_modeset_intent *intent);
int igt_output_get_required_pipes(int fd, igt_output_t *output);

uint32_t igt_get_valid_pipe_mask(igt_display_t *display);
uint32_t igt_get_master_pipe_mask(igt_display_t *display);

int igt_find_consecutive_pipes(int n_crtcs, uint32_t available_mask,
                               int need);

int igt_allocate_pipes(igt_display_t *display,
                       igt_output_t **outputs, int n_outputs,
                       uint32_t *used_pipes);


/* ═══════════════════════════════════════════════════════════════════════════
 * Section 8: Layer 3 — Multi-Output Setup Builder
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    /* Filled by test author */
    bool (*predicate)(int fd, igt_output_t *output);
    bool (*find_mode)(int fd, igt_output_t *output, drmModeModeInfo *mode);
    uint32_t format;
    uint64_t modifier;

    /* Filled by builder */
    igt_output_t *output;
    drmModeModeInfo mode;
    enum pipe master_pipe;
    igt_fb_t fb;
} igt_output_spec_t;

typedef struct {
    igt_display_t *display;
    int fd;
    int n_specs;
    igt_output_spec_t *specs;
    uint32_t used_pipes;
    bool committed;
} igt_multi_output_ctx_t;

int  igt_multi_output_find(igt_display_t *display, int fd,
                           igt_output_spec_t *specs, int n_specs,
                           igt_multi_output_ctx_t *ctx);
int  igt_multi_output_select_modes(igt_multi_output_ctx_t *ctx);
int  igt_multi_output_allocate_pipes(igt_multi_output_ctx_t *ctx);
void igt_multi_output_create_fbs(igt_multi_output_ctx_t *ctx);
int  igt_multi_output_validate_bw(igt_multi_output_ctx_t *ctx);

void igt_multi_output_setup(igt_display_t *display, int fd,
                            igt_output_spec_t *specs, int n_specs,
                            igt_multi_output_ctx_t *ctx);
int  igt_multi_output_try_setup(igt_display_t *display, int fd,
                                igt_output_spec_t *specs, int n_specs,
                                igt_multi_output_ctx_t *ctx);

void igt_multi_output_commit(igt_multi_output_ctx_t *ctx);
int  igt_multi_output_try_commit(igt_multi_output_ctx_t *ctx);
void igt_multi_output_teardown(igt_multi_output_ctx_t *ctx);


/* ═══════════════════════════════════════════════════════════════════════════
 * Section 9: Layer 4 — Bandwidth-Safe Commit
 * ═══════════════════════════════════════════════════════════════════════════ */

bool igt_bw_safe_commit(igt_display_t *display);
int  igt_try_bw_commit(igt_display_t *display);


/* ═══════════════════════════════════════════════════════════════════════════
 * Section 10: Layer 5 — Debugfs State Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    int dir_fd;
    const char *attr_name;
    char original_value[64];
    int original_len;
    bool active;
    igt_output_t *output;       /* for simulation restore */
} igt_debugfs_guard_t;

void igt_debugfs_guard_begin(int fd, igt_output_t *output,
                             const char *debugfs_attr,
                             igt_debugfs_guard_t *guard);
void igt_debugfs_guard_end(igt_debugfs_guard_t *guard);

void igt_intel_dsc_guard_begin(int fd, igt_output_t *output,
                               igt_debugfs_guard_t *guard);
void igt_intel_dsc_guard_end(igt_debugfs_guard_t *guard);
void igt_intel_joiner_guard_begin(int fd, igt_output_t *output,
                                  igt_debugfs_guard_t *guard);
void igt_intel_joiner_guard_end(igt_debugfs_guard_t *guard);

/* Exit handler (installed once) */
typedef void (*sandbox_exit_handler_t)(int sig);
void igt_install_exit_handler(sandbox_exit_handler_t handler);


/* ═══════════════════════════════════════════════════════════════════════════
 * Section 11: Layer 6 — Output Classifier
 * ═══════════════════════════════════════════════════════════════════════════ */

void igt_classify_outputs(igt_display_t *display, int fd,
                          bool (*predicate)(int fd, igt_output_t *),
                          igt_output_t **match, int *match_count,
                          igt_output_t **no_match, int *no_match_count);

igt_output_t *igt_find_output_with(igt_display_t *display, int fd,
                                   bool (*pred)(int fd, igt_output_t *));

int igt_count_outputs_with(igt_display_t *display, int fd,
                           bool (*pred)(int fd, igt_output_t *));


/* ═══════════════════════════════════════════════════════════════════════════
 * Section 12: Layer 7 — Composition Macros
 * ═══════════════════════════════════════════════════════════════════════════ */

#define for_each_connected_output_where(display, output, pred) \
    for_each_connected_output(display, output) \
        for_each_if(pred)

typedef struct {
    igt_display_t *display;
    int fd;
    bool (**preds)(int, igt_output_t *);
    int n_slots;

    igt_output_t *connected[IGT_MAX_OUTPUTS];
    int n_connected;

    int cursor[IGT_MAX_PIPES];
    bool exhausted;
    bool initialized;
} igt_combo_iter_t;

int _first_output_combo(igt_display_t *display, igt_combo_iter_t *iter,
                        igt_output_t **outputs, int n,
                        bool (**preds)(int, igt_output_t *));
int _next_output_combo(igt_combo_iter_t *iter, igt_output_t **outputs);

#define for_each_output_combo(display, iter, outputs, n, preds) \
    for (int __combo_ok__ = \
             _first_output_combo(display, iter, outputs, n, preds); \
         __combo_ok__; \
         __combo_ok__ = _next_output_combo(iter, outputs))


/* ═══════════════════════════════════════════════════════════════════════════
 * Section 13: Layer 8 — Convenience Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

igt_plane_t *igt_output_setup_fb(int fd, igt_output_t *output,
                                 uint32_t format, uint64_t modifier,
                                 igt_fb_t *fb);

bool igt_find_joiner_mode(int fd, igt_output_t *output,
                          enum joined_pipes level, drmModeModeInfo *mode);
bool igt_find_non_joiner_mode(int fd, igt_output_t *output,
                              drmModeModeInfo *mode);

/* Simulated DSC enable/disable for testing */
void force_dsc_enable(int fd, igt_output_t *output);
bool igt_is_dsc_enabled(int fd, const char *output_name);


#ifdef __cplusplus
}
#endif

#endif /* IGT_SANDBOX_H */
