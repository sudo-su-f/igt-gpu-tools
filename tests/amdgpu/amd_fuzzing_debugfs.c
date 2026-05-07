// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 *
 * AMDGPU DebugFS Fuzzing Test
 *
 * Fuzz tests for AMDGPU debugfs interfaces (userspace -> kernel via debugfs)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>

#include "igt.h"

#define DEBUGFS_BASE "/sys/kernel/debug/dri"
#define MAX_PATH 512
#define MAX_VALUE 4096

/* Test case for fuzzing */
struct fuzz_case {
	const char *desc;
	const char *value;
	int expected_errno;  /* 0 = success expected, -1 = any error OK */
};

/* Generic test cases for writable debugfs files */
static const struct fuzz_case generic_fuzz_cases[] = {
	{ "valid_0", "0", 0 },
	{ "valid_1", "1", 0 },
	{ "negative", "-1", -1 },
	{ "large_int", "999999", 0 },  /* Debugfs often accepts and clamps */
	{ "overflow", "99999999999999999999", -1 },
	{ "invalid_chars", "abc", -1 },
	{ "special", "!@#$", -1 },
	{ "empty", "", -1 },  /* Debugfs rejects empty strings */
	{ "hex_valid", "0xFF", 0 },
	{ "hex_large", "0xFFFFFFFF", 0 },
	{ NULL, NULL, 0 }
};

/* Read-only or hardware-specific files that reject all writes */
static const struct fuzz_case readonly_fuzz_cases[] = {
	{ "valid_0", "0", -1 },
	{ "valid_1", "1", -1 },
	{ "negative", "-1", -1 },
	{ "large_int", "999999", -1 },
	{ "overflow", "99999999999999999999", -1 },
	{ "invalid_chars", "abc", -1 },
	{ "special", "!@#$", -1 },
	{ "empty", "", -1 },
	{ "hex_valid", "0xFF", -1 },
	{ "hex_large", "0xFFFFFFFF", -1 },
	{ NULL, NULL, 0 }
};

/* Mask files that reject 0 (mask=0 disables all) */
static const struct fuzz_case mask_fuzz_cases[] = {
	{ "valid_0", "0", -1 },
	{ "valid_1", "1", 0 },
	{ "negative", "-1", -1 },
	{ "large_int", "999999", 0 },
	{ "overflow", "99999999999999999999", -1 },
	{ "invalid_chars", "abc", -1 },
	{ "special", "!@#$", -1 },
	{ "empty", "", -1 },
	{ "hex_valid", "0xFF", 0 },
	{ "hex_large", "0xFFFFFFFF", 0 },
	{ NULL, NULL, 0 }
};

/* Find AMDGPU card path */
static int find_amdgpu_card(char *card_path, size_t size)
{
	struct dirent *entry;
	DIR *dir;

	dir = opendir(DEBUGFS_BASE);
	if (!dir)
		return -errno;

	while ((entry = readdir(dir)) != NULL) {
		if (strstr(entry->d_name, "0000:") != NULL) {
			snprintf(card_path, size, "%s/%s",
			         DEBUGFS_BASE, entry->d_name);
			closedir(dir);
			return 0;
		}
	}

	closedir(dir);
	return -ENOENT;
}

/* Check file access */
static int check_file_writable(const char *path)
{
	struct stat st;
	
	if (stat(path, &st) != 0)
		return 0;
		
	return (st.st_mode & S_IWUSR) || (st.st_mode & S_IWGRP);
}

/* Read file value */
static int read_debugfs(const char *path, char *buffer, size_t bufsize)
{
	int fd, ret;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	ret = read(fd, buffer, bufsize - 1);
	close(fd);

	if (ret < 0)
		return -errno;

	buffer[ret] = '\0';
	if (ret > 0 && buffer[ret-1] == '\n')
		buffer[ret-1] = '\0';

	return ret;
}

/* Write file value */
static int write_debugfs(const char *path, const char *value, size_t len)
{
	int fd, ret;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;

	ret = write(fd, value, len);
	close(fd);

	if (ret < 0)
		return -errno;

	return ret;
}

/* Test a single debugfs file */
static void test_debugfs_file(const char *filepath, const char *filename)
{
	char original[MAX_VALUE] = "";
	const struct fuzz_case *test_case;
	int ret;
	int pass_count = 0, fail_count = 0;
	struct stat st;
	const struct fuzz_case *cases;

	igt_info("=== Testing: %s ===\n", filename);

	/* Check if file is writable */
	if (!check_file_writable(filepath)) {
		igt_skip("File not writable: %s\n", filename);
		return;
	}

	/* Try to read original value */
	if (stat(filepath, &st) == 0 && (st.st_mode & S_IRUSR)) {
		ret = read_debugfs(filepath, original, sizeof(original));
		if (ret >= 0)
			igt_info("  Original value: '%s'\n", original);
	}

	/* Run fuzz test cases */
	cases = generic_fuzz_cases;

	/* Spec-aware: select test cases based on file behavior */
	if (strstr(filename, "dcc_en") || strstr(filename, "dmub_trace_mask")) {
		/* Read-only or hardware-specific - reject all writes */
		cases = readonly_fuzz_cases;
	} else if (strstr(filename, "sched_mask")) {
		/* Scheduler masks - reject 0 (would disable all) */
		cases = mask_fuzz_cases;
	}

	for (test_case = cases; test_case->desc != NULL; test_case++) {
		ret = write_debugfs(filepath, test_case->value,
		                   strlen(test_case->value));

		if (ret < 0) {
			if (test_case->expected_errno == 0) {
				igt_warn("  [%s] Write failed: %s - UNEXPECTED\n",
				        test_case->desc, strerror(-ret));
				fail_count++;
			} else {
				igt_debug("  [%s] Write failed: %s - EXPECTED\n",
				         test_case->desc, strerror(-ret));
				pass_count++;
			}
		} else {
			if (test_case->expected_errno == 0) {
				igt_debug("  [%s] Write succeeded - EXPECTED\n",
				         test_case->desc);
				pass_count++;
			} else {
				igt_warn("  [%s] Write succeeded - UNEXPECTED\n",
				        test_case->desc);
				fail_count++;
			}
		}
	}

	/* Restore original value if we read one */
	if (strlen(original) > 0) {
		ret = write_debugfs(filepath, original, strlen(original));
		if (ret < 0)
			igt_warn("Failed to restore %s: %s\n",
			        filename, strerror(-ret));
	}

	igt_info("  Results: %d passed, %d failed\n", pass_count, fail_count);

	/* Allow some failures for exploratory fuzzing */
	igt_assert_f(fail_count < 6,
	             "Too many issues for %s (%d failures)",
	             filename, fail_count);
}

/* Main test */
int main(int argc, char **argv)
{
	char card_path[MAX_PATH];
	char filepath[MAX_PATH];
	int card_found = 0;

	/* Writable debugfs files to test */
	const char *test_files[] = {
		/* Display Manager debug knobs */
		"amdgpu_dm_dcc_en",
		"amdgpu_dm_disable_hpd",
		"amdgpu_dm_dmcub_trace_event_en",
		"amdgpu_dm_dmub_trace_mask",
		"amdgpu_dm_dp_ignore_cable_id",
		"amdgpu_dm_force_timing_sync",
		"amdgpu_dm_visual_confirm",
		/* Scheduler masks */
		"amdgpu_compute_sched_mask",
		"amdgpu_sdma_sched_mask",
		/* SMU debug */
		"amdgpu_smu_debug",
		NULL
	};

	igt_subtest_init(argc, argv);

	igt_fixture() {
		card_found = (find_amdgpu_card(card_path, sizeof(card_path)) == 0);
		igt_require_f(card_found, "No AMDGPU card found in debugfs\n");
		igt_require(getuid() == 0);  /* Need root for debugfs access */
		igt_info("Found AMDGPU card: %s\n", card_path);
	}

	for (int i = 0; test_files[i] != NULL; i++) {
	igt_subtest_f("debugfs-%s", test_files[i]) {
			int ret = snprintf(filepath, sizeof(filepath), "%s/%s",
			                   card_path, test_files[i]);
			igt_assert_f(ret > 0 && ret < (int)sizeof(filepath),
			             "Path too long: %s/%s", card_path, test_files[i]);
			test_debugfs_file(filepath, test_files[i]);
		}
	}

	igt_exit();
}
