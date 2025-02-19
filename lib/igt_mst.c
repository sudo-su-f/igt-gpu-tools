/*
 * Copyright © 2023 Intel Corporation
 */

#include "igt_mst.h"
#include "igt_kms.h"

/**
 * igt_check_output_is_dp_mst:
 * @output: igt_output_t structure
 *
 * Returns: True if the output is a DP MST output, false otherwise.
 */
bool igt_check_output_is_dp_mst(igt_output_t *output)
{
    return output->config.connector->connector_type == DRM_MODE_CONNECTOR_DisplayPort &&
           output->config.connector->connector_type_id == DRM_MODE_CONNECTOR_ID_DP_MST;
}

/**
 * igt_get_dp_mst_connector_id:
 * @output: igt_output_t structure
 *
 * Returns: The connector ID of the DP MST output.
 */
int igt_get_dp_mst_connector_id(igt_output_t *output)
{
    return output->config.connector->connector_id;
}
