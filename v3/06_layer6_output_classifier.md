## Layer 6 — Output Classifier

### What this is

A utility function that partitions connected outputs into "match" and
"no match" arrays based on a predicate.

### API

```c
void igt_classify_outputs(igt_display_t *display, int fd,
                          bool (*predicate)(int fd, igt_output_t *),
                          igt_output_t **match, int *match_count,
                          igt_output_t **no_match, int *no_match_count);

igt_output_t *igt_find_output_with(igt_display_t *display, int fd,
                                   bool (*pred)(int fd, igt_output_t *));

int igt_count_outputs_with(igt_display_t *display, int fd,
                           bool (*pred)(int fd, igt_output_t *));
```

### Implementation

```c
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
```
