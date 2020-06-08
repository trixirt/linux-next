// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <linux/fcntl.h>
#include <linux/fpga-dfl.h>

#include "../../kselftest.h"

int main(int argc, char *argv[])
{
	int devfd, status;
	struct dfl_fpga_port_info port_info;
	uint32_t irq_num;

	devfd = open("/dev/dfl-port.0", O_RDONLY);
	if (devfd < 0)
		ksft_exit_skip("no fpga afu device 0\n");

	/*
	 * From fpga-dl.h :
	 * Currently hardware supports up to 1 irq.
	 * Return: 0 on success, -errno on failure.
	 */
	irq_num = -1;
	status = ioctl(devfd, DFL_FPGA_PORT_ERR_GET_IRQ_NUM, &irq_num);
	if (status != 0 || irq_num > 255)
		ksft_exit_fail_msg("Could not get the number of afu error irqs\n");

	close(devfd);
	ksft_exit_pass();
}
