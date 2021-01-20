//
// Copyright (c) 2019 ARM Limited
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const (
	// From https://www.kernel.org/doc/Documentation/acpi/namespace.txt
	// The Linux kernel's core ACPI subsystem creates struct acpi_device
	// objects for ACPI namespace objects representing devices, power resources
	// processors, thermal zones. Those objects are exported to user space via
	// sysfs as directories in the subtree under /sys/devices/LNXSYSTM:00
	acpiDevPath = "/devices/LNXSYSTM"
)

func createRootBusPath() (string, error) {
	acpiRootBusPath := "/devices/pci0000:00"
	startRootBusPath := "/devices/platform"
	endRootBusPath := "/pci0000:00"

	acpiSysRootBusPath := filepath.Join(sysfsDir, acpiRootBusPath)
	if _, err := os.Stat(acpiSysRootBusPath); err == nil {
		return acpiRootBusPath, nil
	}

	sysStartRootBusPath := filepath.Join(sysfsDir, startRootBusPath)
	files, err := ioutil.ReadDir(sysStartRootBusPath)
	if err != nil {
		return "", fmt.Errorf("Error reading %s: %s", sysStartRootBusPath, err)
	}

	// find out the directory end with ".pcie"
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".pcie") && file.IsDir() {
			return filepath.Join(startRootBusPath, file.Name(), endRootBusPath), nil
		}
	}

	return "", fmt.Errorf("no pcie bus found under %s", sysStartRootBusPath)
}
