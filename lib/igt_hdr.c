// SPDX-License-Identifier: MIT
/*
 * Copyright © 2026 Intel Corporation
 */

#include "igt.h"
#include "igt_edid.h"
#include "igt_hdr.h"

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

/**
 * SECTION:igt_hdr
 * @short_description: HDR metadata helpers
 * @title: HDR
 * @include: igt_hdr.h
 *
 * This library provides helpers for HDR (High Dynamic Range) metadata
 * handling, including EDID parsing for HDR capability detection, HDR
 * output metadata construction, and blob programming utilities.
 */

/* HDR EDID parsing. */
#define CTA_EXTENSION_VERSION		0x03
#define HDR_STATIC_METADATA_BLOCK	0x06
#define USE_EXTENDED_TAG		0x07

static bool cta_block(const char *edid_ext)
{
	/*
	 * Byte 1: 0x07 indicates Extended Tag
	 * Byte 2: 0x06 indicates HDMI Static Metadata Block
	 * Byte 3: bits 0 to 5 identify EOTF functions supported by sink
	 *	       where ET_0: Traditional Gamma - SDR Luminance Range
	 *	             ET_1: Traditional Gamma - HDR Luminance Range
	 *	             ET_2: SMPTE ST 2084
	 *	             ET_3: Hybrid Log-Gamma (HLG)
	 *	             ET_4 to ET_5: Reserved for future use
	 */

	if ((((edid_ext[0] & 0xe0) >> 5 == USE_EXTENDED_TAG) &&
	      (edid_ext[1] == HDR_STATIC_METADATA_BLOCK)) &&
	     (edid_ext[2] & ((1 << HDMI_EOTF_TRADITIONAL_GAMMA_HDR) |
			     (1 << HDMI_EOTF_SMPTE_ST2084))))
			return true;

	return false;
}

/**
 * igt_is_panel_hdr:
 * @fd: DRM file descriptor
 * @output: output to check
 *
 * Parses the EDID of the given output looking for an HDR Static Metadata
 * Block in the CTA extension. A panel is considered HDR-capable when it
 * advertises support for Traditional Gamma HDR or SMPTE ST 2084 EOTFs.
 *
 * Returns: true if the panel supports HDR, false otherwise.
 */
bool igt_is_panel_hdr(int fd, igt_output_t *output)
{
	bool ok;
	int i, j, offset;
	uint64_t edid_blob_id;
	drmModePropertyBlobRes *edid_blob;
	const struct edid_ext *edid_ext;
	const struct edid *edid;
	const struct edid_cea *edid_cea;
	const char *cea_data;
	bool ret = false;

	ok = kmstest_get_property(fd, output->id,
			DRM_MODE_OBJECT_CONNECTOR, "EDID",
			NULL, &edid_blob_id, NULL);

	if (!ok || !edid_blob_id)
		return ret;

	edid_blob = drmModeGetPropertyBlob(fd, edid_blob_id);
	igt_assert(edid_blob);

	edid = (const struct edid *) edid_blob->data;
	igt_assert(edid);

	for (i = 0; i < edid->extensions_len; i++) {
		edid_ext = &edid->extensions[i];
		edid_cea = &edid_ext->data.cea;

		/* HDR not defined in CTA Extension Version < 3. */
		if ((edid_ext->tag != EDID_EXT_CEA) ||
		    (edid_cea->revision != CTA_EXTENSION_VERSION))
				continue;
		else {
			offset = edid_cea->dtd_start;
			cea_data = edid_cea->data;

			for (j = 0; j < offset; j += (cea_data[j] & 0x1f) + 1) {
				ret = cta_block(cea_data + j);

				if (ret)
					break;
			}
		}
	}

	drmModeFreePropertyBlob(edid_blob);

	return ret;
}

/* Converts a double to 861-G spec FP format. */
static uint16_t igt_hdr_calc_float(double val)
{
	return (uint16_t)(val * 50000.0);
}

/**
 * igt_hdr_fill_st2084:
 * @meta: HDR output metadata structure to fill
 *
 * Fills the given metadata structure with test values for SMPTE ST 2084
 * (PQ) HDR output using Rec. 2020 primaries.
 *
 * Note: there isn't really a standard for what the metadata is supposed
 * to do on the display side of things. The display is free to ignore it
 * and clip the output, use it to help tonemap to the content range,
 * or do anything they want, really.
 */
void igt_hdr_fill_st2084(struct hdr_output_metadata *meta)
{
	memset(meta, 0, sizeof(*meta));

	meta->metadata_type = HDMI_STATIC_METADATA_TYPE1;
	meta->hdmi_metadata_type1.eotf = HDMI_EOTF_SMPTE_ST2084;

	/* Rec. 2020 */
	meta->hdmi_metadata_type1.display_primaries[0].x =
		igt_hdr_calc_float(0.708); /* Red */
	meta->hdmi_metadata_type1.display_primaries[0].y =
		igt_hdr_calc_float(0.292);
	meta->hdmi_metadata_type1.display_primaries[1].x =
		igt_hdr_calc_float(0.170); /* Green */
	meta->hdmi_metadata_type1.display_primaries[1].y =
		igt_hdr_calc_float(0.797);
	meta->hdmi_metadata_type1.display_primaries[2].x =
		igt_hdr_calc_float(0.131); /* Blue */
	meta->hdmi_metadata_type1.display_primaries[2].y =
		igt_hdr_calc_float(0.046);
	meta->hdmi_metadata_type1.white_point.x = igt_hdr_calc_float(0.3127);
	meta->hdmi_metadata_type1.white_point.y = igt_hdr_calc_float(0.3290);

	meta->hdmi_metadata_type1.max_display_mastering_luminance =
		1000; /* 1000 nits */
	meta->hdmi_metadata_type1.min_display_mastering_luminance =
		500;				   /* 0.05 nits */
	meta->hdmi_metadata_type1.max_fall = 1000; /* 1000 nits */
	meta->hdmi_metadata_type1.max_cll = 500;   /* 500 nits */
}

/**
 * igt_hdr_fill_sdr:
 * @meta: HDR output metadata structure to fill
 *
 * Fills the given metadata structure with test values for SDR output
 * using Rec. 709 primaries and traditional gamma EOTF.
 */
void igt_hdr_fill_sdr(struct hdr_output_metadata *meta)
{
	memset(meta, 0, sizeof(*meta));

	meta->metadata_type = HDMI_STATIC_METADATA_TYPE1;
	meta->hdmi_metadata_type1.eotf = HDMI_EOTF_TRADITIONAL_GAMMA_SDR;

	/* Rec. 709 */
	meta->hdmi_metadata_type1.display_primaries[0].x =
		igt_hdr_calc_float(0.640); /* Red */
	meta->hdmi_metadata_type1.display_primaries[0].y =
		igt_hdr_calc_float(0.330);
	meta->hdmi_metadata_type1.display_primaries[1].x =
		igt_hdr_calc_float(0.300); /* Green */
	meta->hdmi_metadata_type1.display_primaries[1].y =
		igt_hdr_calc_float(0.600);
	meta->hdmi_metadata_type1.display_primaries[2].x =
		igt_hdr_calc_float(0.150); /* Blue */
	meta->hdmi_metadata_type1.display_primaries[2].y =
		igt_hdr_calc_float(0.006);
	meta->hdmi_metadata_type1.white_point.x = igt_hdr_calc_float(0.3127);
	meta->hdmi_metadata_type1.white_point.y = igt_hdr_calc_float(0.3290);

	meta->hdmi_metadata_type1.max_display_mastering_luminance = 0;
	meta->hdmi_metadata_type1.min_display_mastering_luminance = 0;
	meta->hdmi_metadata_type1.max_fall = 0;
	meta->hdmi_metadata_type1.max_cll = 0;
}

/**
 * igt_hdr_set_metadata:
 * @output: output to set the metadata on
 * @meta: HDR output metadata to program, or NULL to disable
 *
 * Programs the HDR_OUTPUT_METADATA connector property blob on the
 * given output. Pass NULL to clear the metadata.
 */
void igt_hdr_set_metadata(igt_output_t *output,
                          const struct hdr_output_metadata *meta)
{
	igt_output_replace_prop_blob(output,
				     IGT_CONNECTOR_HDR_OUTPUT_METADATA, meta,
				     meta ? sizeof(*meta) : 0);
}

/**
 * igt_output_supports_hdr:
 * @output: output to check
 *
 * Returns: true if the output supports the HDR output metadata property.
 */
bool igt_output_supports_hdr(igt_output_t *output)
{
	return igt_output_has_prop(output, IGT_CONNECTOR_HDR_OUTPUT_METADATA);
}

void igt_hdr_disable(igt_output_t *output)
{
	igt_hdr_set_metadata(output, NULL);
	igt_output_set_prop_value(output, IGT_CONNECTOR_MAX_BPC, 8);
}

void igt_hdr_enable(igt_output_t *output)
{
	struct hdr_output_metadata meta;

	/* Fill HDR metadata and enable it on the output */
	igt_hdr_fill_st2084(&meta);
	igt_hdr_set_metadata(output, &meta);
	igt_output_set_prop_value(output, IGT_CONNECTOR_MAX_BPC, 10);
}
