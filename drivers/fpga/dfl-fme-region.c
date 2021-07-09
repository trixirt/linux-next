// SPDX-License-Identifier: GPL-2.0
/*
 * FPGA Region Driver for FPGA Management Engine (FME)
 *
 * Copyright (C) 2017-2018 Intel Corporation, Inc.
 *
 * Authors:
 *   Wu Hao <hao.wu@intel.com>
 *   Joseph Grecco <joe.grecco@intel.com>
 *   Enno Luebbers <enno.luebbers@intel.com>
 *   Tim Whisonant <tim.whisonant@intel.com>
 *   Ananda Ravuri <ananda.ravuri@intel.com>
 *   Henry Mitchel <henry.mitchel@intel.com>
 */

#include <linux/module.h>
#include <linux/fpga/fpga-mgr.h>
#include <linux/fpga/fpga-region.h>

#include "dfl.h"
#include "dfl-fme-pr.h"

static int fme_region_get_bridges(struct fpga_region *region)
{
	struct dfl_fme_region_pdata *pdata = region->priv;
	struct device *dev = &pdata->br->dev;

	return fpga_bridge_get_to_list(dev, region->info, &region->bridge_list);
}

static ssize_t fme_region_compat_id_show(struct fpga_region *region, char *buf)
{
	struct fpga_manager *mgr = region->mgr;
	struct dfl_compat_id compat_id;

	fme_mgr_get_compat_id(mgr, &compat_id);

	return sysfs_emit(buf, "%016llx%016llx\n",
			  (unsigned long long)compat_id.id_h,
			  (unsigned long long)compat_id.id_l);
}

static const struct fpga_region_ops fme_fpga_region_ops = {
	.get_bridges = fme_region_get_bridges,
	.compat_id_show = fme_region_compat_id_show,
};

static int fme_region_probe(struct platform_device *pdev)
{
	struct dfl_fme_region_pdata *pdata = dev_get_platdata(&pdev->dev);
	struct device *dev = &pdev->dev;
	struct fpga_region *region;
	struct fpga_manager *mgr;
	int ret;

	mgr = fpga_mgr_get(&pdata->mgr->dev);
	if (IS_ERR(mgr))
		return -EPROBE_DEFER;

	region = fpga_region_register(dev, mgr, &fme_fpga_region_ops, pdata);
	if (!region) {
		ret = -ENOMEM;
		goto eprobe_mgr_put;
	}

	platform_set_drvdata(pdev, region);

	dev_dbg(dev, "DFL FME FPGA Region probed\n");

	return 0;

eprobe_mgr_put:
	fpga_mgr_put(mgr);
	return ret;
}

static int fme_region_remove(struct platform_device *pdev)
{
	struct fpga_region *region = platform_get_drvdata(pdev);
	struct fpga_manager *mgr = region->mgr;

	fpga_region_unregister(region);
	fpga_mgr_put(mgr);

	return 0;
}

static struct platform_driver fme_region_driver = {
	.driver	= {
		.name    = DFL_FPGA_FME_REGION,
	},
	.probe   = fme_region_probe,
	.remove  = fme_region_remove,
};

module_platform_driver(fme_region_driver);

MODULE_DESCRIPTION("FPGA Region for DFL FPGA Management Engine");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:dfl-fme-region");
