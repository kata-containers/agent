//
// Copyright (c) 2019 Intel Corporation
// Copyright (c) 2019 ARM Limited
//
// SPDX-License-Identifier: Apache-2.0
//

package main

const (
	// From https://www.kernel.org/doc/Documentation/acpi/namespace.txt
	// The Linux kernel's core ACPI subsystem creates struct acpi_device
	// objects for ACPI namespace objects representing devices, power resources
	// processors, thermal zones. Those objects are exported to user space via
	// sysfs as directories in the subtree under /sys/devices/LNXSYSTM:00
	acpiDevPath = "/devices/LNXSYSTM"
)

func createRootBusPath() (string, error) {
	return "/devices/css0", nil
}
