/* SPDX-License-Identifier: MIT */
/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 *
 * AMDGPU SysFS Attribute Specifications
 *
 * Based on kernel source: drivers/gpu/drm/amd/pm/amdgpu_pm.c
 * Verified: 2026-05-04, kernel 6.19.0+
 *
 * This file documents the ACTUAL behavior of AMDGPU sysfs attributes
 * as implemented in the kernel, NOT what we think they should do.
 */

#ifndef AMD_SYSFS_SPEC_H
#define AMD_SYSFS_SPEC_H

#include <stdbool.h>
#include <limits.h>

/* Validation specification for a sysfs attribute */
struct sysfs_validation_spec {
	const char *name;
	
	/* Integer attributes */
	bool accepts_negative;      /* e.g., -1 for disable */
	bool accepts_empty_string;  /* Reset/clear functionality */
	bool accepts_zero;          /* 0 is valid value */
	long min_value;             /* Minimum valid value */
	long max_value;             /* Maximum valid value (-1 = no limit) */
	
	/* String attributes */
	const char **valid_strings; /* NULL-terminated array of valid strings */
	
	/* Multi-int attributes */
	bool is_bitmask;            /* Uses bitmask format ("0 1 2 3") */
	int max_bit_index;          /* Maximum bit index for bitmask (-1 = no limit) */
	
	/* Documentation */
	const char *kernel_doc;     /* Reference to kernel documentation */
	const char *notes;          /* Additional notes */
};

/*
 * thermal_throttling_logging specification
 *
 * From kernel: drivers/gpu/drm/amd/pm/amdgpu_pm.c:1576-1642
 *
 * Quote from kernel doc:
 *   "Writing an integer to the file, sets a new logging interval, in seconds.
 *    The value should be between 1 and 3600. If the value is less than 1,
 *    thermal logging is disabled. Values greater than 3600 are ignored."
 *
 * Implementation (amdgpu_set_thermal_throttling_logging):
 *   - kstrtol(buf, 0, &throttling_logging_interval)
 *   - if (throttling_logging_interval > 3600) return -EINVAL;
 *   - if (throttling_logging_interval > 0) { enable with interval }
 *   - else { disable }
 *
 * CRITICAL: Negative values (< 1) are VALID and disable the feature!
 */
static const struct sysfs_validation_spec thermal_throttling_logging_spec = {
	.name = "thermal_throttling_logging",
	.accepts_negative = true,    /* -1, -999, INT_MIN all disable */
	.accepts_empty_string = true, /* kstrtol behavior with empty */
	.accepts_zero = true,         /* 0 also disables */
	.min_value = LONG_MIN,        /* kstrtol accepts any negative */
	.max_value = 3600,            /* Enforced: > 3600 returns -EINVAL */
	.valid_strings = NULL,
	.is_bitmask = false,
	.max_bit_index = -1,
	.kernel_doc = "drivers/gpu/drm/amd/pm/amdgpu_pm.c:1576 DOC: thermal_throttling_logging",
	.notes = "< 1 = disable, 1-3600 = enable with interval, > 3600 = -EINVAL"
};

/*
 * pp_dpm_sclk, pp_dpm_mclk, pp_dpm_fclk, pp_dpm_socclk, pp_dpm_pcie
 *
 * From kernel: drivers/gpu/drm/amd/pm/amdgpu_pm.c:946-1100
 *
 * Quote from kernel doc:
 *   "Secondly, enter a new value for each level by inputing a string that
 *    contains " echo xx xx xx > pp_dpm_sclk/mclk/pcie"
 *    E.g., echo "4 5 6" > pp_dpm_sclk will enable sclk levels 4, 5, and 6."
 *
 * Implementation (amdgpu_read_mask):
 *   - Parses space/newline delimited integers
 *   - kstrtoul(sub_str, 0, &level)
 *   - if (ret || level > 31) return -EINVAL;
 *   - *mask |= 1 << level;
 *   - Empty substring (from empty string or trailing spaces) breaks loop
 *
 * CRITICAL: Empty string is VALID (breaks loop immediately, mask=0)
 * CRITICAL: Values > 31 return -EINVAL (enforced bitmask limit)
 */
static const struct sysfs_validation_spec pp_dpm_clock_spec = {
	.name = "pp_dpm_sclk/mclk/fclk/socclk/pcie",
	.accepts_negative = false,   /* kstrtoul doesn't accept negative */
	.accepts_empty_string = true, /* Empty breaks loop, returns mask=0 */
	.accepts_zero = true,         /* Level 0 is valid */
	.min_value = 0,
	.max_value = 31,              /* Enforced: level > 31 returns -EINVAL */
	.valid_strings = NULL,
	.is_bitmask = true,           /* Format: "0 1 2" builds bitmask */
	.max_bit_index = 31,          /* Hardware limit in kernel */
	.kernel_doc = "drivers/gpu/drm/amd/pm/amdgpu_pm.c:946 DOC: pp_dpm_sclk ...",
	.notes = "Space-delimited bit indices 0-31. Empty string = reset (mask=0). > 31 = -EINVAL"
};

/*
 * power_dpm_force_performance_level
 *
 * From kernel: drivers/gpu/drm/amd/pm/amdgpu_pm.c:269-450
 *
 * Implementation (amdgpu_set_power_dpm_force_performance_level):
 *   - Uses sysfs_streq() to match against enum strings
 *   - sysfs_streq strips trailing whitespace/newlines
 *   - Does NOT explicitly handle empty string
 *   - Returns -EINVAL if no match
 *
 * OBSERVATION: sysfs_streq("", "auto") = false, returns -EINVAL
 * However, VFS write with count=0 returns 0 (success) WITHOUT calling store
 *
 * CRITICAL: Empty string with write(fd, "", 0) succeeds at VFS level!
 * This is NOT a kernel bug - it's standard VFS behavior
 */
static const char *power_dpm_force_performance_level_values[] = {
	"low", "high", "auto", "manual",
	"profile_exit", "profile_standard",
	"profile_min_sclk", "profile_min_mclk",
	"profile_peak", "perf_determinism",
	NULL
};

static const struct sysfs_validation_spec power_dpm_force_performance_level_spec = {
	.name = "power_dpm_force_performance_level",
	.accepts_negative = false,
	.accepts_empty_string = true, /* VFS write(fd, "", 0) = 0 without calling store */
	.accepts_zero = false,
	.min_value = 0,
	.max_value = -1,
	.valid_strings = power_dpm_force_performance_level_values,
	.is_bitmask = false,
	.max_bit_index = -1,
	.kernel_doc = "drivers/gpu/drm/amd/pm/amdgpu_pm.c:269 DOC: power_dpm_force_performance_level",
	.notes = "Accepts enum strings only. Empty with count=0 succeeds at VFS (doesn't call store)"
};

/*
 * pp_features
 *
 * Similar to pp_dpm_* but for feature bit enabling/disabling
 * Accepts space-delimited feature indices
 */
static const struct sysfs_validation_spec pp_features_spec = {
	.name = "pp_features",
	.accepts_negative = false,
	.accepts_empty_string = true, /* Reset to defaults */
	.accepts_zero = true,
	.min_value = 0,
	.max_value = 63,              /* Typical max features (may vary) */
	.valid_strings = NULL,
	.is_bitmask = true,
	.max_bit_index = 63,
	.kernel_doc = "drivers/gpu/drm/amd/pm/amdgpu_pm.c",
	.notes = "Feature bit indices. Out-of-range may be clamped or ignored depending on HW"
};

/* Lookup function */
static inline const struct sysfs_validation_spec *
find_sysfs_spec(const char *attr_name)
{
	if (strcmp(attr_name, "thermal_throttling_logging") == 0)
		return &thermal_throttling_logging_spec;
	
	if (strcmp(attr_name, "pp_dpm_sclk") == 0 ||
	    strcmp(attr_name, "pp_dpm_mclk") == 0 ||
	    strcmp(attr_name, "pp_dpm_fclk") == 0 ||
	    strcmp(attr_name, "pp_dpm_socclk") == 0 ||
	    strcmp(attr_name, "pp_dpm_pcie") == 0)
		return &pp_dpm_clock_spec;
	
	if (strcmp(attr_name, "power_dpm_force_performance_level") == 0 ||
	    strcmp(attr_name, "power_dpm_state") == 0 ||
	    strcmp(attr_name, "pp_power_profile_mode") == 0)
		return &power_dpm_force_performance_level_spec;
	
	if (strcmp(attr_name, "pp_features") == 0)
		return &pp_features_spec;
	
	return NULL; /* Unknown attribute */
}

#endif /* AMD_SYSFS_SPEC_H */
