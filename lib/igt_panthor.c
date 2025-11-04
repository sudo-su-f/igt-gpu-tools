// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (C) 2025 Collabora Ltd.

#include "drmtest.h"
#include "igt_panthor.h"
#include "ioctl_wrappers.h"
#include "panthor_drm.h"

/**
 * SECTION:igt_panthor
 * @short_description: Panthor support library
 * @title: Panthor
 * @include: igt.h
 *
 * This library provides various auxiliary helper functions for writing Panthor
 * tests.
 */

/**
 * igt_panthor_query:
 * @fd: device file descriptor
 * @type: query type (e.g., DRM_PANTHOR_DEV_QUERY_GPU_INFO)
 * @data: pointer to a struct to store the query result
 * @size: size of the result struct
 * @err: expected error code, or 0 for success
 *
 * Query GPU information.
 */
void igt_panthor_query(int fd, int32_t type, void *data, size_t size, int err)
{
	struct drm_panthor_dev_query query = {
		.type = type,
		.pointer = (uintptr_t)data,
		.size = size,
	};

	if (err)
		do_ioctl_err(fd, DRM_IOCTL_PANTHOR_DEV_QUERY, &query, err);
	else
		do_ioctl(fd, DRM_IOCTL_PANTHOR_DEV_QUERY, &query);
}
