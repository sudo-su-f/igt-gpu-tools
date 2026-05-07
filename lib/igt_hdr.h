#ifndef IGT_HDR_H
#define IGT_HDR_H

#include "igt_edid.h"
#include "igt_kms.h"

enum hdmi_eotf {
	HDMI_EOTF_TRADITIONAL_GAMMA_SDR,
	HDMI_EOTF_TRADITIONAL_GAMMA_HDR,
	HDMI_EOTF_SMPTE_ST2084,
};

/* DRM HDR definitions. Not in the UAPI header, unfortunately. */
enum hdmi_metadata_type {
	HDMI_STATIC_METADATA_TYPE1 = 0,
};

bool igt_is_panel_hdr(int fd, igt_output_t *output);

void igt_hdr_fill_st2084(struct hdr_output_metadata *meta);
void igt_hdr_fill_sdr(struct hdr_output_metadata *meta);

void igt_hdr_set_metadata(igt_output_t *output,
                          const struct hdr_output_metadata *meta);

bool igt_output_supports_hdr(igt_output_t *output);

void igt_hdr_disable(igt_output_t *output);
void igt_hdr_enable(igt_output_t *output);

#endif /* IGT_HDR_H */
