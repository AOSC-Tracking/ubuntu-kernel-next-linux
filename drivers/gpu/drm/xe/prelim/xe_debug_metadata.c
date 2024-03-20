// SPDX-License-Identifier: MIT
/*
 * Copyright © 2023 Intel Corporation
 */
#include "prelim/xe_debug_metadata.h"

#include <drm/drm_device.h>
#include <drm/drm_file.h>
#include <drm/xe_drm.h>

#include "xe_device.h"
#include "prelim/xe_eudebug.h"
#include "xe_macros.h"

static void xe_debug_metadata_release(struct kref *ref)
{
	struct prelim_xe_debug_metadata *mdata = container_of(ref, struct prelim_xe_debug_metadata, refcount);

	kvfree(mdata->ptr);
	kfree(mdata);
}

void prelim_xe_debug_metadata_put(struct prelim_xe_debug_metadata *mdata)
{
	kref_put(&mdata->refcount, xe_debug_metadata_release);
}

struct prelim_xe_debug_metadata *prelim_xe_debug_metadata_get(struct xe_file *xef, u32 id)
{
	struct prelim_xe_debug_metadata *mdata;

	mutex_lock(&xef->debug_metadata.lock);
	mdata = xa_load(&xef->debug_metadata.xa, id);
	if (mdata)
		kref_get(&mdata->refcount);
	mutex_unlock(&xef->debug_metadata.lock);

	return mdata;
}

int prelim_xe_debug_metadata_create_ioctl(struct drm_device *dev,
				   void *data,
				   struct drm_file *file)
{
	struct xe_device *xe = to_xe_device(dev);
	struct xe_file *xef = to_xe_file(file);
	struct prelim_drm_xe_debug_metadata_create *args = data;
	struct prelim_xe_debug_metadata *mdata;
	int err;
	u32 id;

	if (XE_IOCTL_DBG(xe, args->extensions))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, args->type >= PRELIM_WORK_IN_PROGRESS_DRM_XE_DEBUG_METADATA_NUM))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, !args->user_addr || !args->len))
		return -EINVAL;

	if (XE_IOCTL_DBG(xe, !access_ok(u64_to_user_ptr(args->user_addr), args->len)))
		return -EFAULT;

	mdata = kzalloc(sizeof(*mdata), GFP_KERNEL);
	if (!mdata)
		return -ENOMEM;

	mdata->len = args->len;
	mdata->type = args->type;

	mdata->ptr = kvmalloc(mdata->len, GFP_KERNEL);
	if (!mdata->ptr) {
		kfree(mdata);
		return -ENOMEM;
	}
	kref_init(&mdata->refcount);

	err = copy_from_user(mdata->ptr, u64_to_user_ptr(args->user_addr), mdata->len);
	if (err) {
		err = -EFAULT;
		goto put_mdata;
	}

	mutex_lock(&xef->debug_metadata.lock);
	err = xa_alloc(&xef->debug_metadata.xa, &id, mdata, xa_limit_32b, GFP_KERNEL);
	mutex_unlock(&xef->debug_metadata.lock);

	args->metadata_id = id;
	mdata->id = id;

	if (err)
		goto put_mdata;

	prelim_xe_eudebug_debug_metadata_create(xef, mdata);

	return 0;

put_mdata:
	prelim_xe_debug_metadata_put(mdata);
	return err;
}

int prelim_xe_debug_metadata_destroy_ioctl(struct drm_device *dev,
				    void *data,
				    struct drm_file *file)
{
	struct xe_device *xe = to_xe_device(dev);
	struct xe_file *xef = to_xe_file(file);
	struct prelim_drm_xe_debug_metadata_destroy * const args = data;
	struct prelim_xe_debug_metadata *mdata;

	if (XE_IOCTL_DBG(xe, args->extensions))
		return -EINVAL;

	mutex_lock(&xef->debug_metadata.lock);
	mdata = xa_erase(&xef->debug_metadata.xa, args->metadata_id);
	mutex_unlock(&xef->debug_metadata.lock);
	if (XE_IOCTL_DBG(xe, !mdata))
		return -ENOENT;

	prelim_xe_eudebug_debug_metadata_destroy(xef, mdata);

	prelim_xe_debug_metadata_put(mdata);
	return 0;
}
