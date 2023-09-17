/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2023 Intel Corporation
 */

#ifndef _XE_DEBUG_METADATA_H_
#define _XE_DEBUG_METADATA_H_

#include "xe_debug_metadata_types.h"

struct drm_device;
struct drm_file;
struct xe_file;

struct xe_debug_metadata *xe_debug_metadata_get(struct xe_file *xef, u32 id);
void xe_debug_metadata_put(struct xe_debug_metadata *mdata);

int xe_debug_metadata_create_ioctl(struct drm_device *dev,
				   void *data,
				   struct drm_file *file);

int xe_debug_metadata_destroy_ioctl(struct drm_device *dev,
				    void *data,
				    struct drm_file *file);
#endif
