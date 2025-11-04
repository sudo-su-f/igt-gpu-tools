// SPDX-License-Identifier: MIT
/*
 * Copyright © 2025 Intel Corporation
 */
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>

#include "igt.h"
#include "igt_configfs.h"
#include "igt_device.h"
#include "igt_fs.h"
#include "igt_kmod.h"
#include "igt_sriov_device.h"
#include "igt_sysfs.h"
#include "xe/xe_query.h"

/**
 * TEST: Comprehensive survivability mode testing
 * Category: Core
 * Mega feature: General Core features
 * Sub-category: Telemetry
 * Functionality: survivability mode
 * Description: Validate survivability mode functionality
 * Test category: Functional tests
 *
 * SUBTEST: i2c-functionality
 * Description: Validate i2c adapter functionality in survivability mode
 */

static char bus_addr[NAME_MAX];

static bool check_survivability_mode_sysfs(void)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, PATH_MAX, "/sys/bus/pci/devices/%s/survivability_mode", bus_addr);
	fd = open(path, O_RDONLY);
	igt_assert_f(fd >= 0, "Survivability mode not set\n");
	close(fd);
	return true;
}

static int find_i2c_adapter(struct pci_device *pci_xe)
{
	char device_path[PATH_MAX];
	struct dirent *dirent;
	int i2c_adapter = -1;
	DIR *device_dir;
	int ret;

	igt_require(igt_kmod_load("i2c-dev", NULL) == 0);

	snprintf(device_path, sizeof(device_path), "/sys/bus/pci/devices/%s/%s.%hu", bus_addr,
		 "i2c_designware", (pci_xe->bus << 8) | (pci_xe->dev));
	device_dir = opendir(device_path);

	if (!device_dir)
		return -1;

	while ((dirent = readdir(device_dir))) {
		if (strncmp(dirent->d_name, "i2c-", 4) == 0) {
			ret = sscanf(dirent->d_name, "i2c-%d", &i2c_adapter);
			igt_assert_f(ret == 1, "Failed to parse i2c adapter number");
			closedir(device_dir);
			return i2c_adapter;
		}
	}

	closedir(device_dir);
	return i2c_adapter;
}

static void restore(int sig)
{
	int configfs_fd;

	igt_kmod_unbind("xe", bus_addr);

	configfs_fd = igt_configfs_open("xe");
	if (configfs_fd >= 0)
		igt_fs_remove_dir(configfs_fd, bus_addr);
	close(configfs_fd);

	igt_kmod_bind("xe", bus_addr);
}

static void set_survivability_mode(int configfs_device_fd, bool value)
{
	igt_kmod_unbind("xe", bus_addr);
	igt_sysfs_set_boolean(configfs_device_fd, "survivability_mode", value);
	igt_kmod_bind("xe", bus_addr);
}

static void test_i2c_functionality(int configfs_device_fd, struct pci_device *pci_xe)
{
	if (find_i2c_adapter(pci_xe) >= 0) {
		/* Enable survivability mode */
		set_survivability_mode(configfs_device_fd, true);

		/* check presence of survivability mode sysfs */
		check_survivability_mode_sysfs();

		/* Check i2c adapter after survivability mode */
		igt_assert_f(find_i2c_adapter(pci_xe) >= 0,
			     "i2c not initialized\n");

		set_survivability_mode(configfs_device_fd, false);
	}
}

static int create_device_configfs_group(int configfs_fd)
{
	mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	int configfs_device_fd;

	configfs_device_fd = igt_fs_create_dir(configfs_fd, bus_addr, mode);
	igt_assert(configfs_device_fd);

	return configfs_device_fd;
}

igt_main
{
	int fd, configfs_fd, configfs_device_fd;
	struct pci_device *pci_xe;
	bool vf_device;

	igt_fixture {
		fd = drm_open_driver(DRIVER_XE);
		igt_require(IS_BATTLEMAGE(intel_get_drm_devid(fd)));
		vf_device = intel_is_vf_device(fd);
		igt_require_f(!vf_device, "survivability mode not supported in VF\n");
		pci_xe = igt_device_get_pci_device(fd);
		igt_device_get_pci_slot_name(fd, bus_addr);
		configfs_fd = igt_configfs_open("xe");
		igt_require(configfs_fd != -1);
		configfs_device_fd = create_device_configfs_group(configfs_fd);
		igt_install_exit_handler(restore);
	}

	igt_describe("Validate i2c adapter functionality in survivability mode");
	igt_subtest("i2c-functionality") {
		test_i2c_functionality(configfs_device_fd, pci_xe);
		drm_close_driver(fd);
		fd = drm_open_driver(DRIVER_XE);
	}

	igt_fixture {
		igt_fs_remove_dir(configfs_fd, bus_addr);
		close(configfs_device_fd);
		close(configfs_fd);
		drm_close_driver(fd);
	}
}
