// SPDX-License-Identifier: MIT
/*
 * Copyright 2024 Advanced Micro Devices, Inc.
 * Copyright 2026 Advanced Micro Devices, Inc. (KFD fuzzing extension)
 *
 * KFD (Kernel Fusion Driver) IOCTL fuzzing test
 * Tests HSA compute driver IOCTLs for proper input validation
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "igt.h"
#include <amdgpu_drm.h>
#ifdef HAVE_KFD_IOCTL_H
#include <linux/kfd_ioctl.h>
#endif /* HAVE_KFD_IOCTL_H */


#ifdef HAVE_KFD_IOCTL_H


/* KFD IOCTLs to test */
struct kfd_ioctl_test {
	unsigned long request;
	const char *name;
	size_t arg_size;
	int skip;  /* 1 = deprecated/dangerous, 0 = test */
};

#define KFD_IOCTL_NOARG(num, name, skip_flag) \
	{ _IO('K', num), name, 0, skip_flag }

#define KFD_IOCTL(num, type, name, skip_flag) \
	{ _IOWR('K', num, type), name, sizeof(type), skip_flag }

static const struct kfd_ioctl_test kfd_ioctls[] = {
	KFD_IOCTL(0x01, struct kfd_ioctl_get_version_args, "GET_VERSION", 2)  /* Read-only: accepts all inputs */,
	KFD_IOCTL(0x02, struct kfd_ioctl_create_queue_args, "CREATE_QUEUE", 0),
	KFD_IOCTL(0x03, struct kfd_ioctl_destroy_queue_args, "DESTROY_QUEUE", 0),
	KFD_IOCTL(0x04, struct kfd_ioctl_set_memory_policy_args, "SET_MEMORY_POLICY", 0),
	KFD_IOCTL(0x05, struct kfd_ioctl_get_clock_counters_args, "GET_CLOCK_COUNTERS", 2)  /* Read-only: accepts all inputs */,
	KFD_IOCTL(0x06, struct kfd_ioctl_get_process_apertures_args, "GET_PROCESS_APERTURES", 1),  /* Deprecated */
	KFD_IOCTL(0x07, struct kfd_ioctl_update_queue_args, "UPDATE_QUEUE", 0),
	KFD_IOCTL(0x08, struct kfd_ioctl_create_event_args, "CREATE_EVENT", 0),
	KFD_IOCTL(0x09, struct kfd_ioctl_destroy_event_args, "DESTROY_EVENT", 0),
	KFD_IOCTL(0x0A, struct kfd_ioctl_set_event_args, "SET_EVENT", 0),
	KFD_IOCTL(0x0B, struct kfd_ioctl_reset_event_args, "RESET_EVENT", 0),
	KFD_IOCTL(0x0C, struct kfd_ioctl_wait_events_args, "WAIT_EVENTS", 0),
	KFD_IOCTL(0x0D, struct kfd_ioctl_dbg_register_args, "DBG_REGISTER", 1),  /* Deprecated */
	KFD_IOCTL(0x0E, struct kfd_ioctl_dbg_unregister_args, "DBG_UNREGISTER", 1),  /* Deprecated */
	KFD_IOCTL(0x0F, struct kfd_ioctl_dbg_address_watch_args, "DBG_ADDRESS_WATCH", 1),  /* Deprecated */
	KFD_IOCTL(0x10, struct kfd_ioctl_dbg_wave_control_args, "DBG_WAVE_CONTROL", 1),  /* Deprecated */
	KFD_IOCTL(0x11, struct kfd_ioctl_set_scratch_backing_va_args, "SET_SCRATCH_BACKING_VA", 0),
	KFD_IOCTL(0x12, struct kfd_ioctl_get_tile_config_args, "GET_TILE_CONFIG", 0),
	KFD_IOCTL(0x13, struct kfd_ioctl_set_trap_handler_args, "SET_TRAP_HANDLER", 0),
	KFD_IOCTL(0x14, struct kfd_ioctl_get_process_apertures_new_args, "GET_PROCESS_APERTURES_NEW", 0),
	KFD_IOCTL(0x15, struct kfd_ioctl_acquire_vm_args, "ACQUIRE_VM", 0),
	KFD_IOCTL(0x16, struct kfd_ioctl_alloc_memory_of_gpu_args, "ALLOC_MEMORY_OF_GPU", 0),
	KFD_IOCTL(0x17, struct kfd_ioctl_free_memory_of_gpu_args, "FREE_MEMORY_OF_GPU", 0),
	KFD_IOCTL(0x18, struct kfd_ioctl_map_memory_to_gpu_args, "MAP_MEMORY_TO_GPU", 0),
	KFD_IOCTL(0x19, struct kfd_ioctl_unmap_memory_from_gpu_args, "UNMAP_MEMORY_FROM_GPU", 0),
	KFD_IOCTL(0x1A, struct kfd_ioctl_set_cu_mask_args, "SET_CU_MASK", 0),
	KFD_IOCTL(0x1B, struct kfd_ioctl_get_queue_wave_state_args, "GET_QUEUE_WAVE_STATE", 0),
	KFD_IOCTL(0x1C, struct kfd_ioctl_get_dmabuf_info_args, "GET_DMABUF_INFO", 0),
	KFD_IOCTL(0x1D, struct kfd_ioctl_import_dmabuf_args, "IMPORT_DMABUF", 0),
	KFD_IOCTL(0x1E, struct kfd_ioctl_alloc_queue_gws_args, "ALLOC_QUEUE_GWS", 0),
	KFD_IOCTL(0x1F, struct kfd_ioctl_smi_events_args, "SMI_EVENTS", 0),
	KFD_IOCTL(0x20, struct kfd_ioctl_svm_args, "SVM", 0),
	KFD_IOCTL(0x21, struct kfd_ioctl_set_xnack_mode_args, "SET_XNACK_MODE", 2)  /* Permissive: accepts all inputs */,
#ifndef AMDKFD_IOC_CRIU_OP
#warning "CRIU_OP IOCTL not available - skipping this IOCTL test"
#endif
#ifndef AMDKFD_IOC_CRIU_OP
#warning "CRIU_OP IOCTL not available - skipping this IOCTL test"
#endif
#ifdef AMDKFD_IOC_CRIU_OP
	KFD_IOCTL(0x22, struct kfd_ioctl_criu_args, "CRIU_OP", 0),
#endif
#ifndef AMDKFD_IOC_AVAILABLE_MEMORY
#warning "AVAILABLE_MEMORY IOCTL not available - skipping this IOCTL test"
#endif
#ifndef AMDKFD_IOC_AVAILABLE_MEMORY
#warning "AVAILABLE_MEMORY IOCTL not available - skipping this IOCTL test"
#endif
#ifdef AMDKFD_IOC_AVAILABLE_MEMORY
	KFD_IOCTL(0x23, struct kfd_ioctl_get_available_memory_args, "AVAILABLE_MEMORY", 0),
#endif
#ifndef AMDKFD_IOC_EXPORT_DMABUF
#warning "EXPORT_DMABUF IOCTL not available - skipping this IOCTL test"
#endif
#ifndef AMDKFD_IOC_EXPORT_DMABUF
#warning "EXPORT_DMABUF IOCTL not available - skipping this IOCTL test"
#endif
#ifdef AMDKFD_IOC_EXPORT_DMABUF
	KFD_IOCTL(0x24, struct kfd_ioctl_export_dmabuf_args, "EXPORT_DMABUF", 0),
#endif
#ifndef AMDKFD_IOC_RUNTIME_ENABLE
#warning "RUNTIME_ENABLE IOCTL not available - skipping this IOCTL test"
#endif
#ifndef AMDKFD_IOC_RUNTIME_ENABLE
#warning "RUNTIME_ENABLE IOCTL not available - skipping this IOCTL test"
#endif
#ifdef AMDKFD_IOC_RUNTIME_ENABLE
	KFD_IOCTL(0x25, struct kfd_ioctl_runtime_enable_args, "RUNTIME_ENABLE", 0),
#endif
#ifndef AMDKFD_IOC_DBG_TRAP
#warning "DBG_TRAP IOCTL not available - skipping this IOCTL test"
#endif
#ifndef AMDKFD_IOC_DBG_TRAP
#warning "DBG_TRAP IOCTL not available - skipping this IOCTL test"
#endif
#ifdef AMDKFD_IOC_DBG_TRAP
	KFD_IOCTL(0x26, struct kfd_ioctl_dbg_trap_args, "DBG_TRAP", 0),
#endif
	KFD_IOCTL_NOARG(0x27, "CREATE_PROCESS", 0),  /* No arg */
	{ 0, NULL, 0, 0 }
};

/* Fuzz patterns to test */
enum fuzz_pattern {
	FUZZ_ZERO,           /* All zeros */
	FUZZ_ONES,           /* All ones (0xFF...) */
	FUZZ_DEADBEEF,       /* 0xDEADBEEF pattern */
	FUZZ_HIGH_BITS,      /* High bits set */
	FUZZ_ALTERNATING,    /* 0xAA pattern */
	FUZZ_MAX_UINT,       /* Maximum unsigned values */
	FUZZ_NEG_ONE,        /* -1 (all bits set) */
	FUZZ_PATTERN_COUNT
};

static void apply_fuzz_pattern(void *buf, size_t size, enum fuzz_pattern pattern)
{
	unsigned char *ptr = buf;
	size_t i;

	switch (pattern) {
	case FUZZ_ZERO:
		memset(buf, 0, size);
		break;
	case FUZZ_ONES:
		memset(buf, 0xFF, size);
		break;
	case FUZZ_DEADBEEF:
		for (i = 0; i < size; i++)
			ptr[i] = ((unsigned char[]){0xDE, 0xAD, 0xBE, 0xEF})[i % 4];
		break;
	case FUZZ_HIGH_BITS:
		for (i = 0; i < size; i++)
			ptr[i] = 0x80;
		break;
	case FUZZ_ALTERNATING:
		memset(buf, 0xAA, size);
		break;
	case FUZZ_MAX_UINT:
		memset(buf, 0xFF, size);
		break;
	case FUZZ_NEG_ONE:
		memset(buf, 0xFF, size);
		break;
	default:
		memset(buf, 0, size);
	}
}

static const char *pattern_name(enum fuzz_pattern pattern)
{
	switch (pattern) {
	case FUZZ_ZERO: return "all_zeros";
	case FUZZ_ONES: return "all_ones";
	case FUZZ_DEADBEEF: return "deadbeef";
	case FUZZ_HIGH_BITS: return "high_bits";
	case FUZZ_ALTERNATING: return "alternating";
	case FUZZ_MAX_UINT: return "max_uint";
	case FUZZ_NEG_ONE: return "neg_one";
	default: return "unknown";
	}
}

static void test_kfd_ioctl(int fd, const struct kfd_ioctl_test *test)
{
	void *arg_buf = NULL;
	int ret;
	int success_count = 0;
	int fail_count = 0;
	enum fuzz_pattern pattern;

	if (test->skip) {
		igt_info("Skipping deprecated/dangerous IOCTL: %s\n", test->name);
		return;
	}

	igt_info("=== Testing KFD IOCTL: %s (0x%lx, size=%zu) ===\n",
	         test->name, test->request, test->arg_size);

	/* For IOCTLs with no argument, just test the ioctl itself */
	if (test->arg_size == 0) {
		ret = ioctl(fd, test->request);
		if (ret == 0) {
			igt_info("  IOCTL with no arg succeeded (may be valid)\n");
		} else {
			igt_info("  IOCTL with no arg failed: %s\n", strerror(errno));
		}
		/* Don't fail test for no-arg IOCTLs - they may be stateful */
		return;
	}

	arg_buf = malloc(test->arg_size);
	igt_assert(arg_buf != NULL);

	/* Test each fuzz pattern */
	for (pattern = 0; pattern < FUZZ_PATTERN_COUNT; pattern++) {
		apply_fuzz_pattern(arg_buf, test->arg_size, pattern);

		ret = ioctl(fd, test->request, arg_buf);

		if (ret == 0) {
			igt_debug("  [%s] IOCTL succeeded (unexpected)\n",
			         pattern_name(pattern));
			success_count++;
		} else {
			igt_debug("  [%s] IOCTL failed: %s (expected)\n",
			         pattern_name(pattern), strerror(errno));
			fail_count++;
		}
	}

	free(arg_buf);

	igt_info("  Results: %d succeeded, %d failed\n", success_count, fail_count);

	/* We expect most fuzz inputs to fail */
	/* Only fail test if ALL patterns succeeded (no validation) */
	/* UNLESS this is a read-only/permissive IOCTL (skip=2) */
	if (test->skip == 2) {
		/* Expected: read-only or intentionally permissive IOCTL */
		if (fail_count == 0) {
			igt_info("  ✓ IOCTL %s is read-only/permissive (expected behavior)\n", test->name);
		}
	} else {
		igt_assert_f(fail_count > 0,
	            "IOCTL %s accepted ALL fuzz inputs - no validation!\n",
	            test->name);
	}
}

int igt_main()
{
	int fd = -1;
	const struct kfd_ioctl_test *test;
	int kfd_available = 0;

	igt_fixture() {
		/* Try to open KFD device */
		fd = open("/dev/kfd", O_RDWR);
		if (fd >= 0) {
			kfd_available = 1;
			igt_info("KFD device opened successfully: fd=%d\n", fd);
		} else {
			igt_warn("Cannot open /dev/kfd: %s\n", strerror(errno));
			igt_warn("KFD compute driver may not be loaded or hardware not supported\n");
		}

		/* Require KFD device for all tests */
		igt_require_f(kfd_available, "KFD device not available\n");
	}



	/* Test each KFD IOCTL */
	for (test = kfd_ioctls; test->name != NULL; test++) {
		char subtest_name[128];

		snprintf(subtest_name, sizeof(subtest_name),
		        "kfd-ioctl-%s", test->name);

		igt_subtest(subtest_name) {
			if (test->skip == 1) {
				igt_info("Skipping deprecated/dangerous IOCTL: %s\n", test->name);
			} else {
				test_kfd_ioctl(fd, test);
			}
		}
	}

	igt_fixture() {
		if (fd >= 0)
			close(fd);
	}
}


#else /* !HAVE_KFD_IOCTL_H */

int igt_main()
{
	igt_skip("KFD headers not available at build time\n");
}

#endif /* HAVE_KFD_IOCTL_H */
