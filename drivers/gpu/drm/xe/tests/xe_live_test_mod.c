// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright © 2023 Intel Corporation
 */
#include <linux/module.h>

#if IS_ENABLED(CONFIG_DRM_XE_EUDEBUG)
extern struct kunit_suite xe_eudebug_test_suite;
kunit_test_suite(xe_eudebug_test_suite);
#endif

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("xe live kunit tests");
MODULE_IMPORT_NS(EXPORTED_FOR_KUNIT_TESTING);
