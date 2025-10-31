// SPDX-License-Identifier: MIT
/*
 * Copyright © 2025 Intel Corporation
 */

/**
 * TEST: kms sharpness filter
 * Category: Display
 * Description: Test to validate content adaptive sharpness filter
 * Driver requirement: xe
 * Mega feature: General Display Features
 */

#include "igt.h"
#include "igt_kms.h"

/**
 * SUBTEST: filter-basic
 * Description: Verify basic content adaptive sharpness filter.
 *
 * SUBTEST: filter-strength
 * Description: Verify that varying strength (0-255), affects the degree of sharpeness applied.
 *
 * SUBTEST: filter-modifiers
 * Description: Verify content adaptive sharpness filter with varying modifiers.
 *
 * SUBTEST: filter-rotations
 * Description: Verify content adaptive sharpness filter with varying rotations.
 *
 * SUBTEST: filter-formats
 * Description: Verify content adaptive sharpness filter with varying formats.
 *
 * SUBTEST: filter-toggle
 * Description: Verify toggling between enabling and disabling content adaptive sharpness filter.
*/

IGT_TEST_DESCRIPTION("Test to validate content adaptive sharpness filter");

/*
 * Until the CRC support is added test needs to be invoked with
 * --interactive|--i to manually verify if "sharpened" image
 * is seen without corruption for each subtest.
 */

#define DISABLE_FILTER			0
#define MIN_FILTER_STRENGTH		1
#define MID_FILTER_STRENGTH		128
#define MAX_FILTER_STRENGTH		255
#define NROUNDS				10

enum test_type {
	TEST_FILTER_BASIC,
	TEST_FILTER_MODIFIERS,
	TEST_FILTER_ROTATION,
	TEST_FILTER_FORMATS,
	TEST_FILTER_STRENGTH,
	TEST_FILTER_TOGGLE,
};

const int filter_strength_list[] = {
	MIN_FILTER_STRENGTH,
	(MIN_FILTER_STRENGTH + MID_FILTER_STRENGTH) / 2,
	MID_FILTER_STRENGTH,
	(MID_FILTER_STRENGTH + MAX_FILTER_STRENGTH) / 2,
	MAX_FILTER_STRENGTH,
};
static const struct {
	uint64_t modifier;
	const char *name;
} modifiers[] = {
	{ DRM_FORMAT_MOD_LINEAR, "linear", },
	{ I915_FORMAT_MOD_X_TILED, "x-tiled", },
	{ I915_FORMAT_MOD_4_TILED, "4-tiled", },
};
static const int formats[] = {
	DRM_FORMAT_NV12,
	DRM_FORMAT_RGB565,
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_XBGR16161616F,
};
static const igt_rotation_t rotations[] = {
	IGT_ROTATION_0,
	IGT_ROTATION_180,
};

typedef struct {
	int drm_fd;
	bool limited;
	enum pipe pipe_id;
	struct igt_fb fb[4];
	igt_pipe_t *pipe;
	igt_display_t display;
	igt_output_t *output;
	igt_plane_t *plane[4];
	drmModeModeInfo *mode;
	int filter_strength;
	uint64_t modifier;
	const char *modifier_name;
	uint32_t format;
	igt_rotation_t rotation;
} data_t;

static void set_filter_strength_on_pipe(data_t *data)
{
	igt_pipe_set_prop_value(&data->display, data->pipe_id,
				IGT_CRTC_SHARPNESS_STRENGTH,
				data->filter_strength);
}

static void paint_image(igt_fb_t *fb)
{
	cairo_t *cr = igt_get_cairo_ctx(fb->fd, fb);
	int img_x, img_y, img_w, img_h;
	const char *file = "1080p-left.png";

	img_x = img_y = 0;
	img_w = fb->width;
	img_h = fb->height;

	igt_paint_image(cr, file, img_x, img_y, img_w, img_h);

	igt_put_cairo_ctx(cr);
}

static void setup_fb(int fd, int width, int height, uint32_t format,
		     uint64_t modifier, struct igt_fb *fb)
{
	int fb_id;

	fb_id = igt_create_fb(fd, width, height, format, modifier, fb);
	igt_assert(fb_id);

	paint_image(fb);
}

static void cleanup_fbs(data_t *data)
{
	for (int i = 0; i < ARRAY_SIZE(data->fb); i++)
		igt_remove_fb(data->drm_fd, &data->fb[i]);
}

static void cleanup(data_t *data)
{
	igt_display_reset(&data->display);

	cleanup_fbs(data);
}

static int test_filter_toggle(data_t *data)
{
	int ret = 0;

	for (int i = 0; i < NROUNDS; i++) {
		if (i % 2 == 0)
			data->filter_strength = DISABLE_FILTER;
		else
			data->filter_strength = MAX_FILTER_STRENGTH;

		set_filter_strength_on_pipe(data);
		ret |= igt_display_try_commit2(&data->display, COMMIT_ATOMIC);
	}

	return ret;
}

static void test_sharpness_filter(data_t *data,  enum test_type type)
{
	drmModeModeInfo *mode = data->mode;
	int height = mode->hdisplay;
	int width =  mode->vdisplay;
	int ret;

	data->plane[0] = igt_pipe_get_plane_type(data->pipe, DRM_PLANE_TYPE_PRIMARY);
	igt_skip_on_f(!igt_plane_has_format_mod(data->plane[0], data->format, data->modifier),
		      "No requested format/modifier on pipe %s\n", kmstest_pipe_name(data->pipe_id));

	setup_fb(data->drm_fd, height, width, data->format, data->modifier, &data->fb[0]);
	igt_plane_set_fb(data->plane[0], &data->fb[0]);

	if (type == TEST_FILTER_ROTATION) {
		if (igt_plane_has_rotation(data->plane[0], data->rotation))
			igt_plane_set_rotation(data->plane[0], data->rotation);
		else
			igt_skip("No requested rotation on pipe %s\n", kmstest_pipe_name(data->pipe_id));
	}

	set_filter_strength_on_pipe(data);

	if (data->filter_strength != 0)
		igt_debug("Sharpened image should be observed for filter strength > 0\n");

	ret = igt_display_try_commit2(&data->display, COMMIT_ATOMIC);

	if (type == TEST_FILTER_TOGGLE)
		ret |= test_filter_toggle(data);

	igt_assert_eq(ret, 0);

	cleanup(data);
}

static bool has_sharpness_filter(igt_pipe_t *pipe)
{
	return igt_pipe_obj_has_prop(pipe, IGT_CRTC_SHARPNESS_STRENGTH);
}

static void
run_sharpness_filter_test(data_t *data, enum test_type type)
{
	igt_display_t *display = &data->display;
	igt_output_t *output;
	enum pipe pipe;
	char name[40];

	for_each_connected_output(display, output) {
		for_each_pipe(display, pipe) {
			igt_display_reset(display);

			data->output = output;
			data->pipe_id = pipe;
			data->pipe = &display->pipes[data->pipe_id];
			data->mode = igt_output_get_mode(data->output);

			if (!has_sharpness_filter(data->pipe)) {
				igt_info("%s: Doesn't support IGT_CRTC_SHARPNESS_STRENGTH.\n",
				kmstest_pipe_name(data->pipe_id));
				continue;
			}

			igt_output_set_pipe(data->output, data->pipe_id);

			if (!intel_pipe_output_combo_valid(display)) {
				igt_output_set_pipe(data->output, PIPE_NONE);
				continue;
			}

			switch (type) {
			case TEST_FILTER_BASIC:
				snprintf(name, sizeof(name), "-basic");
				break;
			case TEST_FILTER_MODIFIERS:
				snprintf(name, sizeof(name), "-%s", data->modifier_name);
				break;
			case TEST_FILTER_ROTATION:
				snprintf(name, sizeof(name), "-%srot", igt_plane_rotation_name(data->rotation));
				break;
			case TEST_FILTER_FORMATS:
				snprintf(name, sizeof(name), "-%s", igt_format_str(data->format));
				break;
			case TEST_FILTER_STRENGTH:
				snprintf(name, sizeof(name), "-strength-%d", data->filter_strength);
				break;
			case TEST_FILTER_TOGGLE:
				snprintf(name, sizeof(name), "-toggle");
				break;
			default:
				igt_assert(0);
			}

			igt_dynamic_f("pipe-%s-%s%s",  kmstest_pipe_name(data->pipe_id), data->output->name, name)
				test_sharpness_filter(data, type);

			if (data->limited)
				break;
		}
	}
}

static int opt_handler(int opt, int opt_index, void *_data)
{
	data_t *data = _data;

	switch (opt) {
	case 'l':
		data->limited = true;
		break;
	default:
		return IGT_OPT_HANDLER_ERROR;
	}

	return IGT_OPT_HANDLER_SUCCESS;
}

static const char help_str[] =
	"  --limited|-l\t\tLimit execution to 1 valid pipe-output combo\n";

data_t data = {};

igt_main_args("l", NULL, help_str, opt_handler, &data)
{
	igt_fixture {
		data.drm_fd = drm_open_driver_master(DRIVER_ANY);

		kmstest_set_vt_graphics_mode();

		igt_display_require(&data.display, data.drm_fd);
		igt_require(data.display.is_atomic);
		igt_display_require_output(&data.display);
	}

	igt_describe("Verify basic content adaptive sharpness filter.");
	igt_subtest_with_dynamic("filter-basic") {
		data.modifier = DRM_FORMAT_MOD_LINEAR;
		data.rotation = IGT_ROTATION_0;
		data.format = DRM_FORMAT_XRGB8888;
		data.filter_strength = MID_FILTER_STRENGTH;

		run_sharpness_filter_test(&data, TEST_FILTER_BASIC);
	}

	igt_describe("Verify that varying strength(0-255), affects "
		     "the degree of sharpeness applied.");
	igt_subtest_with_dynamic("filter-strength") {
		data.modifier = DRM_FORMAT_MOD_LINEAR;
		data.rotation = IGT_ROTATION_0;
		data.format = DRM_FORMAT_XRGB8888;

		for (int i = 0; i < ARRAY_SIZE(filter_strength_list); i++) {
			data.filter_strength = filter_strength_list[i];

			run_sharpness_filter_test(&data, TEST_FILTER_STRENGTH);
		}
	}

	igt_describe("Verify content adaptive sharpness filter with "
		     "varying modifiers.");
	igt_subtest_with_dynamic("filter-modifiers") {
		data.rotation = IGT_ROTATION_0;
		data.format = DRM_FORMAT_XRGB8888;
		data.filter_strength = MID_FILTER_STRENGTH;

		for (int i = 0; i < ARRAY_SIZE(modifiers); i++) {
			data.modifier = modifiers[i].modifier;
			data.modifier_name = modifiers[i].name;

			run_sharpness_filter_test(&data, TEST_FILTER_MODIFIERS);
		}
	}

	igt_describe("Verify content adaptive sharpness filter with "
		     "varying rotations.");
	igt_subtest_with_dynamic("filter-rotations") {
		data.modifier = DRM_FORMAT_MOD_LINEAR;
		data.format = DRM_FORMAT_XRGB8888;
		data.filter_strength = MID_FILTER_STRENGTH;

		for (int i = 0; i < ARRAY_SIZE(rotations); i++) {
			data.rotation = rotations[i];

			run_sharpness_filter_test(&data, TEST_FILTER_ROTATION);
		}
	}

	igt_describe("Verify content adaptive sharpness filter with "
		     "varying formats.");
	igt_subtest_with_dynamic("filter-formats") {
		data.modifier = DRM_FORMAT_MOD_LINEAR;
		data.rotation = IGT_ROTATION_0;
		data.filter_strength = MID_FILTER_STRENGTH;

		for (int i = 0; i < ARRAY_SIZE(formats); i++) {
			data.format = formats[i];

			run_sharpness_filter_test(&data, TEST_FILTER_FORMATS);
		}
	}

	igt_describe("Verify toggling between enabling and disabling "
		     "content adaptive sharpness filter.");
	igt_subtest_with_dynamic("filter-toggle") {
		data.modifier = DRM_FORMAT_MOD_LINEAR;
		data.rotation = IGT_ROTATION_0;
		data.format = DRM_FORMAT_XRGB8888;

		data.filter_strength = MAX_FILTER_STRENGTH;
		run_sharpness_filter_test(&data, TEST_FILTER_TOGGLE);
	}

	igt_fixture {
		igt_display_fini(&data.display);
		drm_close_driver(data.drm_fd);
	}
}
