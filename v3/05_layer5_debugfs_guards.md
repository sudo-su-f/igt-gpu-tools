## Layer 5 — Debugfs State Helpers

### What this is

Explicit `begin`/`end` functions that save a debugfs attribute's value and
restore it when the test is done. These are **not RAII or scope-based** — IGT
uses `setjmp`/`longjmp` for failure/skip control flow, which means automatic
(stack) variables are unspecified after `longjmp` and `__attribute__((cleanup))`
does not reliably fire.

Instead, cleanup is handled through two complementary mechanisms:

1. **Explicit `begin`/`end` pairs** that the test calls directly
2. **`igt_install_exit_handler()`** as a safety net for process-level cleanup.
   This fires via `atexit()` on normal exit, and via signal handler on
   SIGTERM/SIGINT/etc. IGT already performs filesystem I/O in both contexts
   (e.g., `igt_cleanup_aperture_trashers`, connector state reset), so our
   exit handler follows the same established pattern.

### Namespacing: Intel-specific

All debugfs state helpers that depend on i915/xe debugfs node names are
namespaced under `igt_intel_*`, not generic `igt_*`. This makes it clear
that these helpers are Intel-specific and prevents confusion when used
alongside vendor-neutral KMS library code.

### API

```c
/* ── lib/igt_kms_feature.h ──────────────────────────────────────── */

typedef struct {
    int dir_fd;                /* fd to connector debugfs dir */
    const char *attr_name;     /* debugfs attribute name */
    char original_value[64];   /* saved content */
    int original_len;          /* length of saved content */
    bool active;               /* guard is holding state */
    pid_t owner_pid;           /* PID that created the guard */
} igt_debugfs_guard_t;

/*
 * Generic debugfs guard: save any debugfs attribute.
 * Caller is responsible for calling _end() in all exit paths.
 * An exit handler is also registered as a safety net.
 */
void igt_debugfs_guard_begin(int fd, igt_output_t *output,
                             const char *debugfs_attr,
                             igt_debugfs_guard_t *guard);
void igt_debugfs_guard_end(igt_debugfs_guard_t *guard);

/*
 * Intel-specific DSC guard: saves/restores "i915_dsc_fec_support".
 * Namespaced under igt_intel_* because it depends on i915 debugfs.
 */
void igt_intel_dsc_guard_begin(int fd, igt_output_t *output,
                               igt_debugfs_guard_t *guard);
void igt_intel_dsc_guard_end(igt_debugfs_guard_t *guard);

/*
 * Intel-specific joiner guard: saves/restores
 * "i915_bigjoiner_force_enable".
 */
void igt_intel_joiner_guard_begin(int fd, igt_output_t *output,
                                  igt_debugfs_guard_t *guard);
void igt_intel_joiner_guard_end(igt_debugfs_guard_t *guard);
```

### Usage Pattern

```c
igt_dynamic_f("%s", output->name) {
    igt_debugfs_guard_t dsc_guard;

    /* Save DSC state */
    igt_intel_dsc_guard_begin(fd, output, &dsc_guard);

    /* Modify debugfs state */
    force_dsc_enable(fd, output);

    /* ... test code ... */

    /* Restore DSC state.
     * If igt_assert() above fails, the exit handler
     * registered by _begin() will restore at process exit. */
    igt_intel_dsc_guard_end(&dsc_guard);
}
```

### Implementation

Uses `igt_debugfs_simple_read()` / `igt_debugfs_simple_write()` which are
the correct upstream IGT helpers for directory-fd-based debugfs access.
The exit handler is installed exactly once via a static guard.

> **Note on `O_RDONLY` for the directory fd:** `igt_debugfs_connector_dir()`
> opens the connector's debugfs directory. The `igt_debugfs_simple_write()`
> helper opens the individual attribute file by name relative to this
> directory fd using `openat(dir_fd, attr, O_WRONLY)`. So the directory fd
> itself only needs `O_RDONLY` for `openat()` lookups — write permission
> is requested on the attribute file, not the directory.

```c
/*
 * Global list of active guards for exit handler safety net.
 * Limited to a reasonable max — tests rarely need more than a few.
 */
#define MAX_ACTIVE_GUARDS 16
static igt_debugfs_guard_t *active_guards[MAX_ACTIVE_GUARDS];
static int n_active_guards;
static bool exit_handler_installed;

static void _guard_exit_handler(int sig)
{
    /*
     * Consistent with established IGT practice: existing exit handlers
     * (e.g. igt_cleanup_aperture_trashers, connector state reset)
     * perform filesystem I/O from the same context. We follow the
     * same pattern here rather than introducing different behavior.
     *
     * Fork safety: only restore guards owned by this process.
     * After fork(), parent and child share initial state but diverge.
     * Without this check, both processes would attempt to restore
     * the same debugfs attributes, causing race conditions.
     */
    pid_t my_pid = getpid();
    for (int i = 0; i < n_active_guards; i++) {
        if (active_guards[i] && active_guards[i]->active &&
            active_guards[i]->owner_pid == my_pid) {
            /*
             * Write back exactly original_len bytes, not strlen().
             * Uses openat() + write() for exact-length restoration.
             */
            int wfd = openat(active_guards[i]->dir_fd,
                             active_guards[i]->attr_name, O_WRONLY);
            if (wfd >= 0) {
                write(wfd, active_guards[i]->original_value,
                      active_guards[i]->original_len);
                close(wfd);
            }
            active_guards[i]->active = false;
        }
    }
    n_active_guards = 0;
}

void igt_debugfs_guard_begin(int fd, igt_output_t *output,
                             const char *debugfs_attr,
                             igt_debugfs_guard_t *guard)
{
    memset(guard, 0, sizeof(*guard));

    guard->dir_fd = igt_debugfs_connector_dir(fd, output->name, O_RDONLY);
    igt_assert(guard->dir_fd >= 0);

    guard->attr_name = debugfs_attr;
    guard->original_len = igt_debugfs_simple_read(guard->dir_fd,
                                                   debugfs_attr,
                                                   guard->original_value,
                                                   sizeof(guard->original_value));
    if (guard->original_len < 0) {
        /*
         * Read failed (attribute missing, permission denied, etc.).
         * Mark the guard inactive — we have no value to restore.
         * Close the dir_fd since we won't need it.
         */
        close(guard->dir_fd);
        guard->active = false;
        igt_warn("debugfs guard: failed to read '%s', guard inactive\n",
                 debugfs_attr);
        return;
    }
    /* Null-terminate for logging/debugging; use original_len for exact restore */
    guard->original_value[guard->original_len] = '\0';
    guard->active = true;
    guard->owner_pid = getpid();

    /* Register in global list */
    igt_assert(n_active_guards < MAX_ACTIVE_GUARDS);
    active_guards[n_active_guards++] = guard;

    /* Install exit handler exactly once */
    if (!exit_handler_installed) {
        igt_install_exit_handler(_guard_exit_handler);
        exit_handler_installed = true;
    }
}

void igt_debugfs_guard_end(igt_debugfs_guard_t *guard)
{
    if (!guard->active)
        return;

    /* Write back exactly original_len bytes, not strlen() */
    int wfd = openat(guard->dir_fd, guard->attr_name, O_WRONLY);
    igt_assert(wfd >= 0);
    igt_assert(write(wfd, guard->original_value,
                     guard->original_len) == guard->original_len);
    close(wfd);
    close(guard->dir_fd);
    guard->active = false;

    /* Remove from global list */
    for (int i = 0; i < n_active_guards; i++) {
        if (active_guards[i] == guard) {
            active_guards[i] = active_guards[--n_active_guards];
            break;
        }
    }
}

/* Intel-specific thin wrappers */
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
```

### Why not `__attribute__((cleanup))`?

IGT's control flow model uses `setjmp`/`longjmp`:

- `igt_assert()` failure → `longjmp` to subtest boundary
- `igt_require()` skip → `longjmp` to subtest boundary

After `longjmp`, automatic (stack) variables have **unspecified values**
per the C standard. There is **no stack unwinding**, so `cleanup` attributes
do not fire. This means:

- `__attribute__((cleanup(fn)))` is **not guaranteed to run** on test failure
- The guard variable itself may have corrupted values after `longjmp`

The explicit `begin`/`end` pattern combined with `igt_install_exit_handler()`
provides reliable cleanup:

- Normal path: `_end()` is called explicitly
- Failure path: exit handler restores all active guards at process exit
- Skip path: same as failure — exit handler fires
