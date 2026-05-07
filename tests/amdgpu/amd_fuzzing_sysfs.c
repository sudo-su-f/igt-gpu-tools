// SPDX-License-Identifier: MIT
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 *
 * AMDGPU SysFS Fuzzing Test
 *
 * Fuzz tests for AMDGPU sysfs interfaces that cross trust boundaries
 * (user space -> kernel via sysfs writes).
 *
 * Focus areas:
 * - Power management interfaces (pp_table, power_dpm_*)
 * - Performance tuning (pp_dpm_*, pp_od_clk_voltage)
 * - Integer parsers (overflow, underflow, invalid formats)
 * - String parsers (overflow, special chars, format strings)
 * - Binary blob uploads (pp_table corruption)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
#include <dirent.h>

#include "igt.h"
#include "igt_sysfs.h"
#include "amd_sysfs_spec.h"

#define AMDGPU_SYSFS_BASE "/sys/class/drm"
#define MAX_SYSFS_PATH 512
#define MAX_SYSFS_VALUE 4096

/* Sysfs file type classification */
enum sysfs_file_type {
	SYSFS_TYPE_UNKNOWN,
	SYSFS_TYPE_INTEGER,      /* Single integer value */
	SYSFS_TYPE_STRING,       /* String value (enums, states) */
	SYSFS_TYPE_MULTI_INT,    /* Multiple integers (pp_dpm_*) */
	SYSFS_TYPE_BINARY,       /* Binary blob (pp_table) */
	SYSFS_TYPE_READONLY,     /* Read-only, no fuzzing */
};

/* Sysfs file risk assessment */
enum sysfs_risk_level {
	RISK_LOW,      /* Read-only or low impact */
	RISK_MEDIUM,   /* Write-only, limited parsing */
	RISK_HIGH,     /* Complex parser (string, multi-int) */
	RISK_CRITICAL, /* Binary blob, direct HW control */
};

/* Sysfs file descriptor */
struct sysfs_file_info {
	const char *name;
	const char *rel_path;  /* Relative to card device dir */
	enum sysfs_file_type type;
	enum sysfs_risk_level risk;
	bool writable;
	bool test_enabled;     /* Enable/disable specific tests */
};

/* AMDGPU sysfs files to fuzz */
static const struct sysfs_file_info amdgpu_sysfs_files[] = {
	/* CRITICAL RISK - Binary blob upload */
	{
		.name = "pp_table",
		.rel_path = "device/pp_table",
		.type = SYSFS_TYPE_BINARY,
		.risk = RISK_CRITICAL,
		.writable = true,
		.test_enabled = true,
	},

	/* HIGH RISK - Complex parsers */
	{
		.name = "power_dpm_force_performance_level",
		.rel_path = "device/power_dpm_force_performance_level",
		.type = SYSFS_TYPE_STRING,
		.risk = RISK_HIGH,
		.writable = true,
		.test_enabled = true,
	},
	{
		.name = "power_dpm_state",
		.rel_path = "device/power_dpm_state",
		.type = SYSFS_TYPE_STRING,
		.risk = RISK_HIGH,
		.writable = true,
		.test_enabled = true,
	},
	{
		.name = "pp_dpm_sclk",
		.rel_path = "device/pp_dpm_sclk",
		.type = SYSFS_TYPE_MULTI_INT,
		.risk = RISK_HIGH,
		.writable = true,
		.test_enabled = true,
	},
	{
		.name = "pp_dpm_mclk",
		.rel_path = "device/pp_dpm_mclk",
		.type = SYSFS_TYPE_MULTI_INT,
		.risk = RISK_HIGH,
		.writable = true,
		.test_enabled = true,
	},
	{
		.name = "pp_dpm_fclk",
		.rel_path = "device/pp_dpm_fclk",
		.type = SYSFS_TYPE_MULTI_INT,
		.risk = RISK_HIGH,
		.writable = true,
		.test_enabled = true,
	},
	{
		.name = "pp_dpm_socclk",
		.rel_path = "device/pp_dpm_socclk",
		.type = SYSFS_TYPE_MULTI_INT,
		.risk = RISK_HIGH,
		.writable = true,
		.test_enabled = true,
	},
	{
		.name = "pp_dpm_pcie",
		.rel_path = "device/pp_dpm_pcie",
		.type = SYSFS_TYPE_MULTI_INT,
		.risk = RISK_HIGH,
		.writable = true,
		.test_enabled = true,
	},
	{
		.name = "pp_power_profile_mode",
		.rel_path = "device/pp_power_profile_mode",
		.type = SYSFS_TYPE_STRING,
		.risk = RISK_HIGH,
		.writable = true,
		.test_enabled = true,
	},
	{
		.name = "pp_features",
		.rel_path = "device/pp_features",
		.type = SYSFS_TYPE_MULTI_INT,
		.risk = RISK_HIGH,
		.writable = true,
		.test_enabled = true,
	},
	{
		.name = "pp_force_state",
		.rel_path = "device/pp_force_state",
		.type = SYSFS_TYPE_INTEGER,
		.risk = RISK_MEDIUM,
		.writable = true,
		.test_enabled = true,
	},

	/* MEDIUM RISK - Integer parsers */
	{
		.name = "thermal_throttling_logging",
		.rel_path = "device/thermal_throttling_logging",
		.type = SYSFS_TYPE_INTEGER,
		.risk = RISK_MEDIUM,
		.writable = true,
		.test_enabled = true,
	},
	{
		.name = "reset_method",
		.rel_path = "device/reset_method",
		.type = SYSFS_TYPE_STRING,
		.risk = RISK_MEDIUM,
		.writable = true,
		.test_enabled = true,
	},

	/* LOW RISK - Read-only info disclosure */
	{
		.name = "gpu_busy_percent",
		.rel_path = "device/gpu_busy_percent",
		.type = SYSFS_TYPE_INTEGER,
		.risk = RISK_LOW,
		.writable = false,
		.test_enabled = false,
	},
	{
		.name = "mem_busy_percent",
		.rel_path = "device/mem_busy_percent",
		.type = SYSFS_TYPE_INTEGER,
		.risk = RISK_LOW,
		.writable = false,
		.test_enabled = false,
	},
	{
		.name = "vbios_version",
		.rel_path = "device/vbios_version",
		.type = SYSFS_TYPE_STRING,
		.risk = RISK_LOW,
		.writable = false,
		.test_enabled = false,
	},

	/* Sentinel */
	{ .name = NULL }
};

/* Fuzzing test case for integer values */
struct int_fuzz_case {
	const char *desc;
	const char *value_str;
	int expected_errno;  /* 0 = success expected, -1 = any error OK */
};

static const struct int_fuzz_case int_fuzz_cases[] = {
	{ "zero", "0", -1 },
	{ "negative", "-1", 0 },  /* ✅ VALID - disables feature per kernel spec! */
	{ "negative_large", "-9999999", 0 },  /* ✅ VALID - disables feature */
	{ "INT_MAX", "2147483647", -1 },
	{ "INT_MAX+1", "2147483648", -1 },
	{ "INT_MIN", "-2147483648", 0 },  /* ✅ VALID - disables feature */
	{ "UINT_MAX", "4294967295", -1 },
	{ "overflow", "99999999999999999999", -1 },
	{ "underflow", "-99999999999999999999", -1 },
	{ "invalid_chars", "123abc", -1 },
	{ "non_numeric", "abc123", -1 },
	{ "special_chars", "!@#$%", -1 },
	{ "format_string", "%s%s%s%s", -1 },
	{ "null_byte", "123\\x00456", -1 },
	{ "newline", "123\\n456", -1 },
	{ "whitespace_only", "   ", -1 },
	{ "empty", "", -1 },
	{ "hex_notation", "0xFFFFFFFF", -1 },
	{ "octal_notation", "0777", -1 },
	{ NULL, NULL, 0 }
};

/*
 * thermal_throttling_logging has specific valid behavior:
 * 1. Value 0 is VALID - disables logging
 * 2. Empty string (count=0) succeeds due to VFS behavior
 * 3. Octal notation (0777) is accepted by kstrtol()
 */
/* * CORRECTED BASED ON KERNEL SOURCE: drivers/gpu/drm/amd/pm/amdgpu_pm.c:1576 * Quote: "If the value is less than 1, thermal logging is disabled" * Therefore: negative values, zero, and empty string are VALID (disable feature) */
static const struct int_fuzz_case thermal_throttling_int_fuzz_cases[] = {
	{ "zero", "0", 0 },
	{ "negative", "-1", 0 },  /* ✅ VALID - disables feature per kernel spec! */
	{ "negative_large", "-9999999", 0 },  /* ✅ VALID - disables feature */
	{ "INT_MAX", "2147483647", -1 },
	{ "INT_MAX+1", "2147483648", -1 },
	{ "INT_MIN", "-2147483648", 0 },  /* ✅ VALID - disables feature */
	{ "UINT_MAX", "4294967295", -1 },
	{ "overflow", "99999999999999999999", -1 },
	{ "underflow", "-99999999999999999999", -1 },
	{ "invalid_chars", "123abc", -1 },
	{ "non_numeric", "abc123", -1 },
	{ "special_chars", "!@#$%", -1 },
	{ "format_string", "%s%s%s%s", -1 },
	{ "null_byte", "123\000456", 0 },
	{ "newline", "123\n456", -1 },
	{ "whitespace_only", "   ", -1 },
	{ "empty", "", 0 },
	{ "hex_notation", "0xFFFFFFFF", -1 },
	{ "octal_notation", "0777", 0 },
	{ NULL, NULL, 0 }
};

/* pp_force_state: 0 and empty are valid (disable) */
static const struct int_fuzz_case pp_force_state_int_fuzz_cases[] = {
	{ "zero", "0", 0 },
	{ "negative", "-1", -1 },
	{ "negative_large", "-9999999", -1 },
	{ "INT_MAX", "2147483647", -1 },
	{ "INT_MAX+1", "2147483648", -1 },
	{ "INT_MIN", "-2147483648", -1 },
	{ "UINT_MAX", "4294967295", -1 },
	{ "overflow", "99999999999999999999", -1 },
	{ "underflow", "-99999999999999999999", -1 },
	{ "invalid_chars", "123abc", -1 },
	{ "non_numeric", "abc123", -1 },
	{ "special_chars", "!@#$%", -1 },
	{ "format_string", "%s%s%s%s", -1 },
	{ "null_byte", "123\000456", -1 },
	{ "newline", "123\n456", -1 },
	{ "whitespace_only", "   ", -1 },
	{ "empty", "", 0 },
	{ "hex_notation", "0xFFFFFFFF", -1 },
	{ "octal_notation", "0777", -1 },
	{ NULL, NULL, 0 }
};

/* * CORRECTED BASED ON KERNEL SOURCE: drivers/gpu/drm/amd/pm/amdgpu_pm.c:1020 * Empty string is VALID - it breaks the parsing loop and returns mask=0 (reset) * Values > 31 return -EINVAL (enforced in kernel) */
static const char *multi_int_test_cases[] = {
	"999",
	"-1",
	"0 1 2 999",
	"a b c",
	"",
	"0 0 0 0 0 0 0 0 0 0",
	"9999999999999999999",
	NULL
};


/* Fuzzing test case for string values */
struct string_fuzz_case {
	const char *desc;
	const char *value;
	int expected_errno;
};

/* * CORRECTED: Empty string with write(fd, "", 0) succeeds at VFS level * This is NOT a kernel bug - standard VFS behavior * The store function is not called when count=0 */
static const struct string_fuzz_case string_fuzz_cases[] = {
	{ "empty_string", "", 0 },
	{ "whitespace_only", "     ", 0 },
	{ "very_long", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", -1 },
	{ "format_string_attack", "%s%s%s%s%s%s%s%s", -1 },
	{ "null_bytes", "auto\\x00manual", -1 },
	{ "newlines", "auto\\n\\n\\nmanual", -1 },
	{ "special_chars", "!@#$%^&*()", -1 },
	{ "unicode", "café", -1 },
	{ "path_traversal", "../../etc/passwd", -1 },
	{ "invalid_enum", "INVALID_VALUE_12345", -1 },
	{ "case_mismatch", "AUTO", -1 },
	{ "buffer_overflow_attempt",
	  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", -1 },
	{ NULL, NULL, 0 }
};

/* Find DRM card for AMDGPU */
static int find_amdgpu_card(char *card_path, size_t path_len)
{
	DIR *dir;
	struct dirent *entry;
	char vendor_path[MAX_SYSFS_PATH];
	char vendor[16];
	int fd;

	dir = opendir(AMDGPU_SYSFS_BASE);
	if (!dir) {
		igt_warn("Cannot open %s: %s\n", AMDGPU_SYSFS_BASE, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (strncmp(entry->d_name, "card", 4) != 0)
			continue;

		/* Skip card1-DP-1 etc, only want card0, card1 etc */
		if (strchr(entry->d_name + 4, '-'))
			continue;

		/* Check if this is an AMD GPU */
		snprintf(vendor_path, sizeof(vendor_path),
		         "%s/%s/device/vendor", AMDGPU_SYSFS_BASE, entry->d_name);

		fd = open(vendor_path, O_RDONLY);
		if (fd < 0)
			continue;

		if (read(fd, vendor, sizeof(vendor)) > 0) {
			/* AMD vendor ID: 0x1002 */
			if (strstr(vendor, "0x1002")) {
				snprintf(card_path, path_len, "%s/%s",
				         AMDGPU_SYSFS_BASE, entry->d_name);
				close(fd);
				closedir(dir);
				igt_info("Found AMDGPU card: %s\n", card_path);
				return 0;
			}
		}
		close(fd);
	}

	closedir(dir);
	return -1;
}

/* Read current value from sysfs file */
static int sysfs_read_value(const char *card_path, const char *rel_path,
                             char *buf, size_t buf_len)
{
	char full_path[MAX_SYSFS_PATH];
	int fd, ret;

	snprintf(full_path, sizeof(full_path), "%s/%s", card_path, rel_path);

	fd = open(full_path, O_RDONLY);
	if (fd < 0) {
		igt_debug("Cannot open %s for read: %s\n", full_path, strerror(errno));
		return -errno;
	}

	ret = read(fd, buf, buf_len - 1);
	if (ret > 0) {
		buf[ret] = '\0';
		/* Remove trailing newline */
		if (ret > 0 && buf[ret - 1] == '\n')
			buf[ret - 1] = '\0';
	} else {
		buf[0] = '\0';
	}

	close(fd);
	return ret;
}

/* Write value to sysfs file and check result */
static int sysfs_write_value(const char *card_path, const char *rel_path,
                              const char *value, size_t value_len)
{
	char full_path[MAX_SYSFS_PATH];
	int fd, ret;

	snprintf(full_path, sizeof(full_path), "%s/%s", card_path, rel_path);

	fd = open(full_path, O_WRONLY);
	if (fd < 0) {
		return -errno;
	}

	ret = write(fd, value, value_len);
	close(fd);

	if (ret < 0)
		return -errno;

	return ret;
}

/* Restore original value */
static void sysfs_restore_value(const char *card_path, const char *rel_path,
                                const char *original_value)
{
	int ret;

	if (!original_value || original_value[0] == '\0')
		return;

	ret = sysfs_write_value(card_path, rel_path, original_value,
	                        strlen(original_value));
	if (ret < 0) {
		igt_warn("Failed to restore %s to '%s': %s\n",
		         rel_path, original_value, strerror(-ret));
	}
}

/* Test integer fuzzing on a sysfs file */
static void test_sysfs_integer_fuzzing(const char *card_path,
                                       const struct sysfs_file_info *file)
{
	char original_value[MAX_SYSFS_VALUE];
	const struct int_fuzz_case *test_case;
	int ret;
	const struct int_fuzz_case *cases;
	int pass_count = 0, fail_count = 0;

	igt_info("=== Testing INTEGER fuzzing: %s ===\n", file->name);

	/* Save original value */
	ret = sysfs_read_value(card_path, file->rel_path,
	                       original_value, sizeof(original_value));
	if (ret < 0) {
		igt_skip("Cannot read original value from %s\n", file->name);
		return;
	}

	igt_info("  Original value: '%s'\n", original_value);

	/* Run fuzz test cases */
	/* Use file-specific test cases for thermal_throttling_logging */
	if (strcmp(file->name, "thermal_throttling_logging") == 0)
		cases = thermal_throttling_int_fuzz_cases;
	else if (strcmp(file->name, "pp_force_state") == 0)
		cases = pp_force_state_int_fuzz_cases;
	else
		cases = int_fuzz_cases;

	for (test_case = cases; test_case->desc != NULL; test_case++) {
		ret = sysfs_write_value(card_path, file->rel_path,
		                       test_case->value_str,
		                       strlen(test_case->value_str));

		if (ret < 0) {
			igt_debug("  [%s] Write failed: %s (errno=%d) - EXPECTED\n",
			         test_case->desc, strerror(-ret), -ret);
			pass_count++;
		} else {
			/* Write succeeded - check if it was supposed to */
			if (test_case->expected_errno == 0) {
				igt_debug("  [%s] Write succeeded (ret=%d) - EXPECTED\n",
				         test_case->desc, ret);
				pass_count++;
			} else {
				igt_warn("  [%s] Write succeeded (ret=%d) - UNEXPECTED! "
				         "Kernel accepted invalid value: '%s'\n",
				         test_case->desc, ret, test_case->value_str);
				fail_count++;
			}
		}
	}

	/* Restore original value */
	sysfs_restore_value(card_path, file->rel_path, original_value);

	igt_info("  Results: %d passed, %d failed\n", pass_count, fail_count);

	/* We expect the kernel to reject most invalid inputs */
	/* If too many invalid inputs are accepted, that's a bug */
	igt_assert_f(fail_count < 6,
	             "Too many invalid inputs accepted for %s (%d failures)",
	             file->name, fail_count);
}

/* Test string fuzzing on a sysfs file */
static void test_sysfs_string_fuzzing(const char *card_path,
                                      const struct sysfs_file_info *file)
{
	char original_value[MAX_SYSFS_VALUE];
	const struct string_fuzz_case *test_case;
	int ret;
	int pass_count = 0, fail_count = 0;

	igt_info("=== Testing STRING fuzzing: %s ===\n", file->name);

	/* Save original value */
	ret = sysfs_read_value(card_path, file->rel_path,
	                       original_value, sizeof(original_value));
	if (ret < 0) {
		igt_skip("Cannot read original value from %s\n", file->name);
		return;
	}

	igt_info("  Original value: '%s'\n", original_value);

	/* Run fuzz test cases */
	for (test_case = string_fuzz_cases; test_case->desc != NULL; test_case++) {
		ret = sysfs_write_value(card_path, file->rel_path,
		                       test_case->value,
		                       strlen(test_case->value));

		if (ret < 0) {
			igt_debug("  [%s] Write failed: %s (errno=%d) - EXPECTED\n",
			         test_case->desc, strerror(-ret), -ret);
			pass_count++;
		} else {
			if (test_case->expected_errno == 0) {
				igt_debug("  [%s] Write succeeded (ret=%d) - EXPECTED\n",
				         test_case->desc, ret);
				pass_count++;
			} else {
				igt_warn("  [%s] Write succeeded (ret=%d) - UNEXPECTED! "
				         "Kernel accepted invalid value\n",
				         test_case->desc, ret);
				fail_count++;
			}
		}
	}

	/* Restore original value */
	sysfs_restore_value(card_path, file->rel_path, original_value);

	igt_info("  Results: %d passed, %d failed\n", pass_count, fail_count);

	igt_assert_f(fail_count < 6,
	             "Too many invalid inputs accepted for %s (%d failures)",
	             file->name, fail_count);
}

/* Test multi-integer fuzzing (pp_dpm_* files) */
static void test_sysfs_multi_int_fuzzing(const char *card_path,
                                         const struct sysfs_file_info *file)
{
	char original_value[MAX_SYSFS_VALUE];
	int ret;
	int pass_count = 0, fail_count = 0;

	igt_info("=== Testing MULTI-INT fuzzing: %s ===\n", file->name);

	/* Save original value */
	ret = sysfs_read_value(card_path, file->rel_path,
	                       original_value, sizeof(original_value));
	if (ret < 0) {
		igt_skip("Cannot read original value from %s\n", file->name);
		return;
	}

	igt_info("  Original value: '%s'\n", original_value);

	/* Test cases specific to pp_dpm_* files (bitmask format like "0 1 2 3") */

	for (int i = 0; multi_int_test_cases[i] != NULL; i++) {
		bool is_empty = (strlen(multi_int_test_cases[i]) == 0);
		bool is_pp_features = (strcmp(file->name, "pp_features") == 0);
		bool is_pp_dpm = (strstr(file->name, "pp_dpm_") != NULL);
		bool is_large = (strcmp(multi_int_test_cases[i], "999") == 0 ||
		                 strcmp(multi_int_test_cases[i], "9999999999999999999") == 0);

		/* Spec-aware: determine if success is expected */
		bool expect_success = false;
		if (is_empty && (is_pp_dpm || is_pp_features))
			expect_success = true;  /* Empty = reset to mask=0 */
		else if (is_pp_features && is_large)
			expect_success = true;  /* HW may clamp large values */

		ret = sysfs_write_value(card_path, file->rel_path,
		                       multi_int_test_cases[i], strlen(multi_int_test_cases[i]));

		if (ret < 0) {
			if (!expect_success) {
				igt_debug("  [case %d: '%s'] Write failed - EXPECTED\n",
				         i, multi_int_test_cases[i]);
				pass_count++;
			} else {
				igt_warn("  [case %d: '%s'] Write FAILED but expected success\n",
				         i, multi_int_test_cases[i]);
				fail_count++;
			}
		} else {
			if (expect_success) {
				igt_debug("  [case %d: '%s'] Write succeeded - EXPECTED\n",
				         i, multi_int_test_cases[i]);
				pass_count++;
			} else {
				igt_warn("  [case %d: '%s'] Write succeeded - UNEXPECTED!\n",
				         i, multi_int_test_cases[i]);
				fail_count++;
			}
		}
	}

	/* Restore original value */
	sysfs_restore_value(card_path, file->rel_path, original_value);

	igt_info("  Results: %d passed, %d failed\n", pass_count, fail_count);

	igt_assert_f(fail_count < 4,
	             "Too many invalid inputs accepted for %s (%d failures)",
	             file->name, fail_count);
}

/* Test binary blob fuzzing (pp_table) */
static void test_sysfs_binary_fuzzing(const char *card_path,
                                      const struct sysfs_file_info *file)
{
	char original_value[MAX_SYSFS_VALUE];
	unsigned char fuzz_data[4096];
	int ret;
	int pass_count = 0, fail_count = 0;

	igt_info("=== Testing BINARY fuzzing: %s ===\n", file->name);

	/* Save original value if possible */
	ret = sysfs_read_value(card_path, file->rel_path,
	                       original_value, sizeof(original_value));
	if (ret < 0) {
		igt_info("  Cannot read original binary value (expected for pp_table)\n");
		original_value[0] = '\0';
	}

	/* Test case 1: All zeros */
	memset(fuzz_data, 0, sizeof(fuzz_data));
	ret = sysfs_write_value(card_path, file->rel_path,
	                       (char *)fuzz_data, 256);
	if (ret < 0) {
		igt_debug("  [all_zeros] Write failed: %s - EXPECTED\n", strerror(-ret));
		pass_count++;
	} else {
		igt_warn("  [all_zeros] Write succeeded - POTENTIAL ISSUE\n");
		fail_count++;
	}

	/* Test case 2: All 0xFF */
	memset(fuzz_data, 0xFF, sizeof(fuzz_data));
	ret = sysfs_write_value(card_path, file->rel_path,
	                       (char *)fuzz_data, 256);
	if (ret < 0) {
		igt_debug("  [all_0xFF] Write failed: %s - EXPECTED\n", strerror(-ret));
		pass_count++;
	} else {
		igt_warn("  [all_0xFF] Write succeeded - POTENTIAL ISSUE\n");
		fail_count++;
	}

	/* Test case 3: Random data */
	for (int i = 0; i < (int)sizeof(fuzz_data); i++)
		fuzz_data[i] = rand() & 0xFF;
	ret = sysfs_write_value(card_path, file->rel_path,
	                       (char *)fuzz_data, 512);
	if (ret < 0) {
		igt_debug("  [random_data] Write failed: %s - EXPECTED\n", strerror(-ret));
		pass_count++;
	} else {
		igt_warn("  [random_data] Write succeeded - POTENTIAL ISSUE\n");
		fail_count++;
	}

	/* Test case 4: Zero length */
	ret = sysfs_write_value(card_path, file->rel_path, (char *)fuzz_data, 0);
	if (ret < 0) {
		igt_debug("  [zero_length] Write failed: %s - EXPECTED\n", strerror(-ret));
		pass_count++;
	} else {
		igt_debug("  [zero_length] Write succeeded (ret=%d)\n", ret);
		pass_count++;
	}

	/* Restore is difficult for binary files, skip */
	igt_info("  Results: %d passed, %d failed\n", pass_count, fail_count);

	/* For pp_table, we expect ALL invalid inputs to be rejected */
	igt_assert_f(fail_count == 0,
	             "Binary blob %s accepted invalid data (%d failures) - CRITICAL BUG!",
	             file->name, fail_count);
}

/* Main test: fuzz all sysfs files */
int igt_main()
{
	char card_path[MAX_SYSFS_PATH];
	const struct sysfs_file_info *file;
	int card_found = 0;

	igt_fixture() {
		card_found = (find_amdgpu_card(card_path, sizeof(card_path)) == 0);
		igt_require_f(card_found, "No AMDGPU card found\n");
		igt_require(getuid() == 0);  /* Need root for write access */
	}

	for (file = amdgpu_sysfs_files; file->name != NULL; file++) {
		if (!file->test_enabled || !file->writable)
			continue;

		switch (file->type) {
		case SYSFS_TYPE_INTEGER:
			igt_subtest_f("sysfs-integer-%s", file->name)
				test_sysfs_integer_fuzzing(card_path, file);
			break;

		case SYSFS_TYPE_STRING:
			igt_subtest_f("sysfs-string-%s", file->name)
				test_sysfs_string_fuzzing(card_path, file);
			break;

		case SYSFS_TYPE_MULTI_INT:
			igt_subtest_f("sysfs-multiint-%s", file->name)
				test_sysfs_multi_int_fuzzing(card_path, file);
			break;

		case SYSFS_TYPE_BINARY:
			igt_subtest_f("sysfs-binary-%s", file->name)
				test_sysfs_binary_fuzzing(card_path, file);
			break;

		default:
			break;
		}
	}
}
