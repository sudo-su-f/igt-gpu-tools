/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef IGT_MST_H
#define IGT_MST_H

#include "igt_kms.h"

bool igt_check_output_is_dp_mst(igt_output_t *output);
int igt_get_dp_mst_connector_id(igt_output_t *output);

#endif /* IGT_MST_H */
