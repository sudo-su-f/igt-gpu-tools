## Layer 1 — Feature Detection Predicates

### What this is

A set of boolean functions in a new `lib/igt_kms_feature.h` that answer
"does this output support feature X?" by checking the full prerequisite chain
(source capability, sink capability, connector type requirements).

### Design: Silent predicates + Require variants

Predicates are **pure boolean checks** — they never print anything. This is
critical because predicates are typically evaluated inside loops (e.g.,
`for_each_connected_output_where`), and printing on every false evaluation
would spam logs.

Diagnostic output is provided by separate **require** functions, which print
once and skip the subtest. These are implemented as **functions** (not macros)
to enable richer status handling via the `igt_feature_status_t` enum, and to
avoid name collisions between macro and function definitions.

For structured diagnostics beyond simple bool, a status enum is available:

```c
/**
 * igt_feature_status - Rich reason code for feature detection
 *
 * Returned by igt_output_check_dsc() etc. for cases where the
 * caller wants to know *why* a feature isn't available.
 */
typedef enum {
    IGT_FEATURE_OK = 0,
    IGT_FEATURE_NO_SOURCE,       /* GPU/driver doesn't support it */
    IGT_FEATURE_NO_SINK,         /* Panel/monitor doesn't support it */
    IGT_FEATURE_NO_FEC,          /* External DP needs FEC for DSC */
    IGT_FEATURE_NO_PROPERTY,     /* DRM property missing */
    IGT_FEATURE_NO_EDID_DATA,    /* EDID lacks required metadata */
    IGT_FEATURE_WRONG_CONNECTOR, /* Wrong connector type */
} igt_feature_status_t;
```

### Full API

```c
/* ── lib/igt_kms_feature.h ──────────────────────────────────────── */

/*
 * Silent boolean predicates — pure checks, never print.
 * Safe to call inside loops without log spam.
 */

/* DSC: source support + sink support + FEC (for external DP) */
bool igt_output_has_dsc(int fd, igt_output_t *output);

/* HDR: HDR_OUTPUT_METADATA property + EDID CTA HDR metadata */
bool igt_output_has_hdr(int fd, igt_output_t *output);

/* VRR: VRR_CAPABLE property exists and reads true */
bool igt_output_has_vrr(int fd, igt_output_t *output);

/* VRR range: parses debugfs vrr_range file, returns min/max Hz */
bool igt_output_get_vrr_range(int fd, igt_output_t *output,
                              int *min_hz, int *max_hz);

/* PSR: preserves mode parameter (PSR_MODE_1, PSR_MODE_2, etc.) */
bool igt_output_has_psr(int fd, igt_output_t *output,
                        enum psr_mode mode);

/* Joiner: returns JOINED_PIPES_NONE / BIG_JOINER / ULTRA_JOINER */
enum joined_pipes igt_output_get_max_joiner(int fd, igt_output_t *output);

/* FBC: per-pipe check (named igt_pipe_* because it's a pipe property) */
bool igt_pipe_has_fbc(int fd, enum pipe pipe);

/* HDCP */
bool igt_output_has_content_protection(int fd, igt_output_t *output);

/* DRRS */
bool igt_output_has_drrs(int fd, igt_output_t *output);

/* Force joiner: can debugfs force joiner be used on this output? */
bool igt_output_has_force_joiner(int fd, igt_output_t *output);

/* Source-only checks (no output needed) */
bool igt_source_has_dsc(int fd);
bool igt_source_has_joiner(int fd);

/*
 * Require variants — print diagnostic and skip if not supported.
 * Use at the "decision boundary" (once per subtest), not in loops.
 *
 * These are FUNCTIONS, not macros, to enable richer diagnostics
 * via igt_feature_status_t and to avoid name collisions.
 */
void igt_output_require_dsc(int fd, igt_output_t *output);
void igt_output_require_hdr(int fd, igt_output_t *output);
void igt_output_require_vrr(int fd, igt_output_t *output);
void igt_output_require_psr(int fd, igt_output_t *output,
                            enum psr_mode mode);

/*
 * Rich status check — returns structured reason code.
 * Use when the caller needs to distinguish failure reasons.
 */
igt_feature_status_t igt_output_check_dsc(int fd, igt_output_t *output);
```

### Implementation — `igt_output_has_dsc()`

> **Note:** The predicate checks the full chain silently. No `igt_info()` calls.

```c
bool igt_output_has_dsc(int fd, igt_output_t *output)
{
    if (!igt_is_dsc_supported_by_source(fd))
        return false;

    if (!igt_is_dsc_supported_by_sink(fd, output->name))
        return false;

    if (!output_is_internal_panel(output) &&
        !igt_is_fec_supported(fd, output->name))
        return false;

    return true;
}
```

### Implementation — `igt_output_check_dsc()` (Rich Status)

```c
igt_feature_status_t igt_output_check_dsc(int fd, igt_output_t *output)
{
    if (!igt_is_dsc_supported_by_source(fd))
        return IGT_FEATURE_NO_SOURCE;

    if (!igt_is_dsc_supported_by_sink(fd, output->name))
        return IGT_FEATURE_NO_SINK;

    if (!output_is_internal_panel(output) &&
        !igt_is_fec_supported(fd, output->name))
        return IGT_FEATURE_NO_FEC;

    return IGT_FEATURE_OK;
}
```

### Implementation — `igt_output_require_dsc()` (Function, not macro)

> **Note:** Prints once-and-skips at the decision boundary, not inside loops.

```c
void igt_output_require_dsc(int fd, igt_output_t *output)
{
    igt_feature_status_t st = igt_output_check_dsc(fd, output);

    switch (st) {
    case IGT_FEATURE_OK:
        return;
    case IGT_FEATURE_NO_SOURCE:
        igt_skip("DSC: GPU does not have DSC encoder\n");
        break;  /* igt_skip is noreturn; break silences -Wimplicit-fallthrough */
    case IGT_FEATURE_NO_SINK:
        igt_skip("DSC: sink %s does not support DSC\n", output->name);
        break;
    case IGT_FEATURE_NO_FEC:
        igt_skip("DSC: external %s requires FEC\n", output->name);
        break;
    default:
        igt_skip("DSC: not supported on %s\n", output->name);
        break;
    }
}
```

### Implementation — Other require variants

```c
void igt_output_require_hdr(int fd, igt_output_t *output)
{
    igt_require_f(igt_output_has_hdr(fd, output),
                  "HDR not supported on %s\n", output->name);
}

void igt_output_require_vrr(int fd, igt_output_t *output)
{
    igt_require_f(igt_output_has_vrr(fd, output),
                  "VRR not supported on %s\n", output->name);
}

void igt_output_require_psr(int fd, igt_output_t *output,
                            enum psr_mode mode)
{
    igt_require_f(igt_output_has_psr(fd, output, mode),
                  "PSR mode %d not supported on %s\n",
                  mode, output->name);
}
```

### Implementation — `igt_output_has_hdr()`

```c
bool igt_output_has_hdr(int fd, igt_output_t *output)
{
    if (!igt_output_has_prop(output, IGT_CONNECTOR_HDR_OUTPUT_METADATA))
        return false;
    if (!igt_is_hdr_panel(fd, output))
        return false;
    return true;
}
```

### Functions promoted from test files to library

| Function | Currently in | Becomes |
|----------|-------------|---------|
| `is_panel_hdr()` | `tests/kms_hdr.c` | `igt_is_hdr_panel()` in `lib/igt_kms_feature.c` |
| `get_vrr_range()` | `tests/kms_vrr.c` | `igt_output_get_vrr_range()` in `lib/igt_kms_feature.c` |

### What we DON'T wrap

Single-property checks remain as-is — they're already the right abstraction:

```c
igt_output_has_prop(output, IGT_CONNECTOR_SCALING_MODE);
igt_crtc_has_prop(crtc, IGT_CRTC_DEGAMMA_LUT);
igt_crtc_has_prop(crtc, IGT_CRTC_GAMMA_LUT);
igt_crtc_has_prop(crtc, IGT_CRTC_CTM);
```
