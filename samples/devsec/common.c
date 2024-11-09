// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2024 Intel Corporation. All rights reserved.

#include <linux/pci.h>
#include <linux/export.h>

struct pci_sysdata *devsec_sysdata;
EXPORT_SYMBOL_GPL(devsec_sysdata);

static int __init common_init(void)
{
	return 0;
}
module_init(common_init);

static void __exit common_exit(void)
{
}
module_exit(common_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Device Security Sample Infrastructure: Shared data");
