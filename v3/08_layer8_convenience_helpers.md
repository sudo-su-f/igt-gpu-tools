## Layer 8 — Convenience Helpers

### `igt_output_setup_fb()` — Create FB and set on primary plane

```c
igt_plane_t *igt_output_setup_fb(int fd, igt_output_t *output,
                                 uint32_t format, uint64_t modifier,
                                 igt_fb_t *fb)
{
    drmModeModeInfo *mode = igt_output_get_mode(output);

    igt_create_fb(fd, mode->hdisplay, mode->vdisplay,
                  format, modifier, fb);

    igt_plane_t *primary = igt_output_get_plane_type(
        output, DRM_PLANE_TYPE_PRIMARY);
    igt_plane_set_fb(primary, fb);

    return primary;
}
```

### Mode finder functions

```c
bool igt_find_joiner_mode(int fd, igt_output_t *output,
                          enum joined_pipes level,
                          drmModeModeInfo *mode);

bool igt_find_non_joiner_mode(int fd, igt_output_t *output,
                              drmModeModeInfo *mode);

bool igt_find_hdr_mode(int fd, igt_output_t *output,
                       drmModeModeInfo *mode);

bool igt_find_vrr_mode(int fd, igt_output_t *output,
                       drmModeModeInfo *mode);
```

### Implementation — `igt_find_joiner_mode()`

Checks both dotclock and hdisplay thresholds to find a mode that triggers
joiner at the requested level. Uses **deterministic selection**: among all
qualifying modes, picks the one with the largest resolution
(`hdisplay × vdisplay`), breaking ties by highest dotclock. This avoids
dependence on the kernel's mode list ordering and ensures reproducible results.

```c
bool igt_find_joiner_mode(int fd, igt_output_t *output,
                          enum joined_pipes level,
                          drmModeModeInfo *mode)
{
    drmModeConnector *conn = output->config.connector;
    int max_dotclock = igt_get_max_dotclock(fd);
    int max_pipe_width = igt_get_max_pipe_width(fd);
    int clock_threshold, width_threshold;

    if (max_dotclock <= 0 && max_pipe_width <= 0)
        return false;

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

    /* Deterministic selection: pick the mode with the largest
     * resolution (hdisplay × vdisplay), then highest clock.
     * This avoids depending on the kernel's mode list ordering. */
    drmModeModeInfo *best = NULL;
    for (int i = 0; i < conn->count_modes; i++) {
        bool needs_joiner = false;

        if (max_dotclock > 0 && conn->modes[i].clock > clock_threshold)
            needs_joiner = true;
        if (max_pipe_width > 0 &&
            conn->modes[i].hdisplay > width_threshold)
            needs_joiner = true;

        if (!needs_joiner)
            continue;

        /* Deterministic: largest resolution, then highest clock */
        if (!best ||
            conn->modes[i].hdisplay * conn->modes[i].vdisplay >
                best->hdisplay * best->vdisplay ||
            (conn->modes[i].hdisplay * conn->modes[i].vdisplay ==
                 best->hdisplay * best->vdisplay &&
             conn->modes[i].clock > best->clock))
            best = &conn->modes[i];
    }
    if (best) {
        memcpy(mode, best, sizeof(*mode));
        return true;
    }
    return false;
}

/**
 * igt_find_non_joiner_mode - Find the best mode that does NOT need joiner
 *
 * Deterministic selection: picks the largest single-pipe mode by
 * resolution (hdisplay × vdisplay), breaking ties by highest clock.
 */
bool igt_find_non_joiner_mode(int fd, igt_output_t *output,
                              drmModeModeInfo *mode)
{
    drmModeConnector *conn = output->config.connector;
    int max_dotclock = igt_get_max_dotclock(fd);
    int max_pipe_width = igt_get_max_pipe_width(fd);
    drmModeModeInfo *best = NULL;

    for (int i = 0; i < conn->count_modes; i++) {
        bool needs_joiner = false;

        if (max_dotclock > 0 && conn->modes[i].clock > max_dotclock)
            needs_joiner = true;
        if (max_pipe_width > 0 &&
            conn->modes[i].hdisplay > max_pipe_width)
            needs_joiner = true;

        if (needs_joiner)
            continue;

        if (!best ||
            conn->modes[i].hdisplay * conn->modes[i].vdisplay >
                best->hdisplay * best->vdisplay ||
            (conn->modes[i].hdisplay * conn->modes[i].vdisplay ==
                 best->hdisplay * best->vdisplay &&
             conn->modes[i].clock > best->clock))
            best = &conn->modes[i];
    }
    if (best) {
        memcpy(mode, best, sizeof(*mode));
        return true;
    }
    return false;
}
```
