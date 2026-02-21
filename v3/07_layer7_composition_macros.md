## Layer 7 — Composition Macros

### What this is

Three new `for_each_*` macros added to `lib/igt_kms.h`. These extend the
existing family of 11 iteration macros. The first two build on the existing
`for_each_if()` mechanism. The third uses a **caller-allocated iterator**
with proper backtracking to enumerate all valid output combinations.

### Macro 1: `for_each_connected_output_where`

```c
#define for_each_connected_output_where(display, output, pred) \
    for_each_connected_output(display, output) \
        for_each_if(pred)
```

Usage:

```c
for_each_connected_output_where(&display, output,
        igt_output_has_dsc(fd, output) &&
        igt_output_has_hdr(fd, output)) {
    igt_dynamic_f("%s", output->name) { /* ... */ }
}
```

### Macro 2: `for_each_pipe_output_combo`

```c
#define for_each_pipe_output_combo(display, crtc, output) \
    for_each_crtc_with_valid_output(display, crtc, output) \
        for_each_if(__igt_pipe_has_room_for_output(display, crtc, output))
```

### Macro 3: `for_each_output_combo` — Caller-allocated iterator

This macro uses a **caller-allocated iterator** with proper backtracking
cursors. It is safe for nesting, forking, re-entrancy, and dynamic subtests.

**How iteration works:**

1. On first call, `__igt_first_output_combo()` builds a `connected[]` snapshot
   (stable ordering) and initializes all cursors to 0.
2. For each combo attempt, the iterator walks slots left-to-right, advancing
   each slot's cursor through `connected[]` until it finds an output that
   matches the predicate and hasn't been claimed by an earlier slot.
3. On `__igt_next_output_combo()`, the iterator backtracks: it advances the
   **deepest** (rightmost) slot's cursor. If that slot overflows, it resets
   that cursor and advances the next-deeper slot (standard odometer pattern).
4. When all slots overflow (slot 0 exhausts its candidates), `exhausted`
   is set to true and iteration terminates.

```c
/**
 * igt_combo_iter_t - Iterator state for output combo enumeration
 *
 * Allocated by the caller (on stack or heap). Passed to the macro.
 * No global state, so safe for:
 *   - Nested combo loops
 *   - Forked child processes (IGT sometimes forks)
 *   - Re-entrancy from dynamic subtests
 *   - Future refactors that reorder control flow
 */
typedef struct {
    igt_display_t *display;
    int fd;
    bool (**preds)(int, igt_output_t *);
    int n_slots;

    /*
     * Snapshot of connected outputs (stable ordering).
     * Sized to IGT_MAX_CONNECTORS — the number of connected outputs
     * can far exceed the pipe count (MST, docks, virtual outputs).
     */
    igt_output_t *connected[IGT_MAX_CONNECTORS];
    int n_connected;

    /* Per-slot cursor into connected[]: the index of the output
     * currently assigned to this slot. Advanced during backtracking.
     * Sized to IGT_MAX_PIPES since slot count <= pipe count. */
    int cursor[IGT_MAX_PIPES];

    bool exhausted;
    bool initialized;
} igt_combo_iter_t;

#define for_each_output_combo(display, iter, outputs, n, preds) \
    for (int __combo_ok__ = \
             __igt_first_output_combo(display, iter, outputs, n, preds); \
         __combo_ok__; \
         __combo_ok__ = \
             __igt_next_output_combo(iter, outputs))
```

Usage:

```c
bool (*preds[])(int, igt_output_t *) = {
    dsc_capable,       /* output 0 must support DSC */
    any_connected,     /* output 1 can be anything */
};
igt_output_t *outs[2];
igt_combo_iter_t iter;   /* ← caller-allocated, no global state */

for_each_output_combo(&display, &iter, outs, 2, preds) {
    igt_dynamic_f("%s-%s", outs[0]->name, outs[1]->name) {
        /* outs[0] supports DSC, outs[1] is any other.
         * Pipes are pre-allocated and non-conflicting. */
    }
}
```

### Implementation — Combo iteration with backtracking

```c
/**
 * __igt_try_assign_slot - Try to find a valid output for the given slot
 * starting from cursor[slot]. Skips outputs claimed by earlier slots.
 *
 * Returns true if a valid assignment was found (cursor[slot] updated).
 */
static bool __igt_try_assign_slot(igt_combo_iter_t *iter,
                                  igt_output_t **outputs, int slot)
{
    for (int c = iter->cursor[slot]; c < iter->n_connected; c++) {
        igt_output_t *candidate = iter->connected[c];

        /* Skip if already assigned to an earlier slot */
        bool claimed = false;
        for (int j = 0; j < slot; j++) {
            if (outputs[j] == candidate) {
                claimed = true;
                break;
            }
        }
        if (claimed)
            continue;

        /* Check predicate */
        if (!iter->preds[slot](iter->fd, candidate))
            continue;

        /* Valid assignment found */
        iter->cursor[slot] = c;
        outputs[slot] = candidate;
        return true;
    }

    /* No valid candidate from cursor[slot] onward */
    return false;
}

/**
 * __igt_find_combo_from_slot - Fill slots [start_slot .. n_slots) with valid
 * outputs. For each slot, start searching from cursor[slot].
 *
 * Returns true if a complete combo is found. On failure, returns false
 * and the caller should backtrack.
 */
static bool __igt_find_combo_from_slot(igt_combo_iter_t *iter,
                                       igt_output_t **outputs,
                                       int start_slot)
{
    for (int slot = start_slot; slot < iter->n_slots; slot++) {
        if (!__igt_try_assign_slot(iter, outputs, slot)) {
            /* This slot failed: need to backtrack */
            return false;
        }
        /* Reset deeper slots to search from beginning */
        for (int d = slot + 1; d < iter->n_slots; d++)
            iter->cursor[d] = 0;
    }

    /*
     * All slots filled. Verify pipe allocation feasibility.
     * Uses igt_check_pipe_assignment() which is a pure feasibility
     * check — it only returns whether a valid assignment exists
     * and fills master_pipes[] with the result. It does NOT call
     * igt_output_set_crtc() or mutate any display state.
     * This keeps the iterator side-effect-free during enumeration.
     */
    int masters[IGT_MAX_PIPES];
    return igt_check_pipe_assignment(iter->display, outputs,
                                     iter->n_slots, masters) == 0;
}

static int __igt_first_output_combo(igt_display_t *display,
                                    igt_combo_iter_t *iter,
                                    igt_output_t **outputs, int n,
                                    bool (**preds)(int, igt_output_t *))
{
    igt_output_t *output;

    memset(iter, 0, sizeof(*iter));
    iter->display = display;
    iter->fd = display->drm_fd;
    iter->preds = preds;
    iter->n_slots = n;

    igt_assert_f(n > 0 && n <= IGT_MAX_PIPES,
                 "n_slots %d out of range [1, IGT_MAX_PIPES]\n", n);

    /* Build connected[] snapshot (stable ordering) */
    iter->n_connected = 0;
    for_each_connected_output(display, output)
        iter->connected[iter->n_connected++] = output;

    igt_assert_f(iter->n_connected <= IGT_MAX_CONNECTORS,
                 "n_connected %d exceeds IGT_MAX_CONNECTORS\n",
                 iter->n_connected);

    /* Initialize all cursors to 0 */
    for (int s = 0; s < n; s++)
        iter->cursor[s] = 0;

    iter->initialized = true;

    /* Try to find the first valid combo starting from slot 0 */
    while (!iter->exhausted) {
        if (__igt_find_combo_from_slot(iter, outputs, 0))
            return 1;

        /* Combo failed (predicate, uniqueness, or pipe allocation).
         * Backtrack: advance the deepest possible slot. */
        int advanced = __igt_backtrack(iter, outputs);
        if (advanced < 0)
            return 0;
    }
    return 0;
}

/**
 * __igt_backtrack - Advance the deepest slot that has remaining candidates.
 *
 * Standard odometer pattern: advance the rightmost digit. If it
 * overflows, reset it and advance the next digit to the left.
 * When slot 0 overflows, iteration is exhausted.
 *
 * Returns the slot index that was advanced (>= 0), so the caller
 * can resume __igt_find_combo_from_slot() from exactly that slot.
 * Returns -1 if all combos are exhausted.
 */
static int __igt_backtrack(igt_combo_iter_t *iter, igt_output_t **outputs)
{
    for (int slot = iter->n_slots - 1; slot >= 0; slot--) {
        /* Clear this slot's assignment */
        outputs[slot] = NULL;
        /* Advance cursor past the current position */
        iter->cursor[slot]++;

        if (iter->cursor[slot] < iter->n_connected) {
            /* Reset all deeper slots */
            for (int d = slot + 1; d < iter->n_slots; d++)
                iter->cursor[d] = 0;
            return slot;
        }
        /* This slot overflowed — reset and try the next shallower */
        iter->cursor[slot] = 0;
    }

    /* All slots overflowed */
    iter->exhausted = true;
    return -1;
}

static int __igt_next_output_combo(igt_combo_iter_t *iter,
                                   igt_output_t **outputs)
{
    if (iter->exhausted)
        return 0;

    /* Backtrack from the deepest slot to find the next combo */
    while (true) {
        int advanced_slot = __igt_backtrack(iter, outputs);
        if (advanced_slot < 0)
            return 0;  /* exhausted */

        if (__igt_find_combo_from_slot(iter, outputs, advanced_slot))
            return 1;
        /* Combo invalid — backtrack again */
    }
}
```

### Why this works correctly

1. **No repeated combos:** `cursor[slot]` is strictly advanced past the
   current position before searching. Deeper slots are reset to 0 only
   after a shallower slot advances, ensuring no combo is revisited.

2. **Complete enumeration:** The odometer pattern guarantees every valid
   combination of cursor positions is visited exactly once.

3. **Uniqueness:** `__igt_try_assign_slot()` checks that no earlier slot already
   claims the candidate output.

4. **Pipe feasibility:** Each complete combo is validated through
   `igt_check_pipe_assignment()` — a pure feasibility check that does NOT
   mutate display state (no `igt_output_set_crtc` calls). Only after the
   macro body runs does the caller apply assignments via
   `igt_apply_pipe_assignment()`. If feasibility fails, the iterator
   backtracks to try the next combo.

5. **No side effects during iteration:** The feasibility check uses a fully
   local `masters[]` array and never modifies `used_pipes`, output CRTC
   assignments, or any other display state. This prevents surprising
   interactions with outer loops, nested combos, and dynamic subtests.

### Implementation — `__igt_pipe_has_room_for_output()`

```c
static inline bool __igt_pipe_has_room_for_output(igt_display_t *display,
                                                   igt_crtc_t *crtc,
                                                   igt_output_t *output)
{
    enum pipe p = crtc->pipe;
    int need = igt_output_get_required_pipes(display->drm_fd, output);

    if (need <= 1)
        return true;

    /* Bounds check: p + need must stay within valid pipe range
     * to prevent BIT(p + k) from shifting past bit 31. */
    if (p + need > display->n_pipes)
        return false;

    /* Check that all pipes [p, p+need) are valid */
    for (int k = 0; k < need; k++)
        if (!(display->valid_pipe_mask & BIT(p + k)))
            return false;

    return true;
}
```
