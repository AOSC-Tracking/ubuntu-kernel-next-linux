/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef __XE_GT_DEBUG_
#define __XE_GT_DEBUG_

#define PRELIM_TD_EU_ATTENTION_MAX_ROWS 2u

#include "xe_gt_types.h"

#define PRELIM_XE_GT_ATTENTION_TIMEOUT_MS 100

int prelim_xe_gt_eu_threads_needing_attention(struct xe_gt *gt);
int prelim_xe_gt_foreach_dss_group_instance(struct xe_gt *gt,
				     int (*fn)(struct xe_gt *gt,
					       void *data,
					       u16 group,
					       u16 instance),
				     void *data);

int prelim_xe_gt_eu_attention_bitmap_size(struct xe_gt *gt);
int prelim_xe_gt_eu_attention_bitmap(struct xe_gt *gt, u8 *bits,
			      unsigned int bitmap_size);

#endif
