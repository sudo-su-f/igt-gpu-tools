/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef IGT_JOINER_H
#define IGT_JOINER_H

#include "igt_fb.h"
#include "igt_kms.h"

bool igt_check_bigjoiner_support(igt_display_t *display);
bool igt_is_joiner_enabled_for_pipe(int drmfd, enum pipe pipe);

#endif /* IGT_JOINER_H */
