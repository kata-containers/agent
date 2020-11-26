//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

var (
	testCtrPath = "test-ctr-path"
)

func createFakeDevicePath() (string, error) {
	f, err := ioutil.TempFile("", "fake-dev-path")
	if err != nil {
		return "", err
	}
	path := f.Name()
	f.Close()

	return path, nil
}

func testVirtioBlkDeviceHandlerFailure(t *testing.T, device pb.Device, spec *pb.Spec) {
	devPath, err := createFakeDevicePath()
	assert.Nil(t, err, "Fake device path creation failed: %v", err)
	defer os.RemoveAll(devPath)

	device.VmPath = devPath
	device.ContainerPath = "some-not-empty-path"

	ctx := context.Background()

	devIdx := makeDevIndex(spec)
	err = virtioBlkDeviceHandler(ctx, device, spec, &sandbox{}, devIdx)
	assert.NotNil(t, err, "blockDeviceHandler() should have failed")

	savedFunc := getPCIDeviceName
	getPCIDeviceName = func(s *sandbox, pciPath PciPath) (string, error) {
		return "foo", nil
	}

	defer func() {
		getPCIDeviceName = savedFunc
	}()

	err = virtioBlkDeviceHandler(ctx, device, spec, &sandbox{}, devIdx)
	assert.Error(t, err)
}

func TestVirtioBlkDeviceHandlerEmptyContainerPath(t *testing.T) {
	spec := &pb.Spec{}
	device := pb.Device{
		ContainerPath: testCtrPath,
	}

	testVirtioBlkDeviceHandlerFailure(t, device, spec)
}

func TestVirtioBlkDeviceHandlerNilLinuxSpecFailure(t *testing.T) {
	spec := &pb.Spec{}
	device := pb.Device{
		ContainerPath: testCtrPath,
	}

	testVirtioBlkDeviceHandlerFailure(t, device, spec)
}

func TestVirtioBlkDeviceHandlerEmptyLinuxDevicesSpecFailure(t *testing.T) {
	spec := &pb.Spec{
		Linux: &pb.Linux{},
	}
	device := pb.Device{
		ContainerPath: testCtrPath,
	}

	testVirtioBlkDeviceHandlerFailure(t, device, spec)
}

func TestPciPathToSysfs(t *testing.T) {
	var rootBusPath string
	var err error

	if runtime.GOARCH == "arm64" {
		rootBusPath = "/devices/platform/4010000000.pcie/pci0000:00"
	} else {
		rootBusPath, err = createRootBusPath()
		if err != nil {
			t.Fatal(t, err)
		}
	}
	testDir, err := ioutil.TempDir("", "kata-agent-tmp-")
	if err != nil {
		t.Fatal(t, err)
	}
	defer os.RemoveAll(testDir)

	// Set sysfsDir to test directory for unit tests.
	sysfsDir = testDir
	rootBus := filepath.Join(sysfsDir, rootBusPath)
	err = os.MkdirAll(rootBus, mountPerm)
	assert.NoError(t, err)

	sysRelPath, err := pciPathToSysfs(PciPath{"02"})
	assert.NoError(t, err)
	assert.Equal(t, sysRelPath, "0000:00:02.0")

	_, err = pciPathToSysfs(PciPath{"02/03"})
	assert.Error(t, err)

	_, err = pciPathToSysfs(PciPath{"02/03/04"})
	assert.Error(t, err)

	// Create mock sysfs files for the device at 0000:00:02.0
	bridge2Path := filepath.Join(rootBus, "0000:00:02.0")

	err = os.MkdirAll(bridge2Path, mountPerm)
	assert.NoError(t, err)

	sysRelPath, err = pciPathToSysfs(PciPath{"02"})
	assert.NoError(t, err)
	assert.Equal(t, sysRelPath, "0000:00:02.0")

	_, err = pciPathToSysfs(PciPath{"02/03"})
	assert.Error(t, err)

	_, err = pciPathToSysfs(PciPath{"02/03/04"})
	assert.Error(t, err)

	// Create mock sysfs files to indicate that 0000:00:02.0 is a bridge to bus 01
	bridge2Bus := "0000:01"
	err = os.MkdirAll(filepath.Join(bridge2Path, "pci_bus", bridge2Bus), mountPerm)
	assert.NoError(t, err)

	sysRelPath, err = pciPathToSysfs(PciPath{"02"})
	assert.NoError(t, err)
	assert.Equal(t, sysRelPath, "0000:00:02.0")

	sysRelPath, err = pciPathToSysfs(PciPath{"02/03"})
	assert.NoError(t, err)
	assert.Equal(t, sysRelPath, "0000:00:02.0/0000:01:03.0")

	_, err = pciPathToSysfs(PciPath{"02/03/04"})
	assert.Error(t, err)

	// Create mock sysfs files for a bridge at 0000:01:03.0 to bus 02
	bridge3Path := filepath.Join(bridge2Path, "0000:01:03.0")
	bridge3Bus := "0000:02"
	err = os.MkdirAll(filepath.Join(bridge3Path, "pci_bus", bridge3Bus), mountPerm)
	assert.NoError(t, err)

	err = os.MkdirAll(bridge3Path, mountPerm)
	assert.NoError(t, err)

	sysRelPath, err = pciPathToSysfs(PciPath{"02"})
	assert.NoError(t, err)
	assert.Equal(t, sysRelPath, "0000:00:02.0")

	sysRelPath, err = pciPathToSysfs(PciPath{"02/03"})
	assert.NoError(t, err)
	assert.Equal(t, sysRelPath, "0000:00:02.0/0000:01:03.0")

	sysRelPath, err = pciPathToSysfs(PciPath{"02/03/04"})
	assert.NoError(t, err)
	assert.Equal(t, sysRelPath, "0000:00:02.0/0000:01:03.0/0000:02:04.0")
}

func TestScanSCSIBus(t *testing.T) {
	testDir, err := ioutil.TempDir("", "kata-agent-tmp-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(testDir)

	savedSCSIHostPath := scsiHostPath
	defer func() {
		scsiHostPath = savedSCSIHostPath
	}()

	scsiHostPath = filepath.Join(testDir, "scsi_host")
	os.RemoveAll(scsiHostPath)

	defer os.RemoveAll(scsiHostPath)

	scsiAddr := "1"

	err = scanSCSIBus(scsiAddr)
	assert.NotNil(t, err, "scanSCSIBus() should have failed")

	if err := os.MkdirAll(scsiHostPath, mountPerm); err != nil {
		t.Fatal(err)
	}

	scsiAddr = "1:1"
	err = scanSCSIBus(scsiAddr)
	assert.Nil(t, err, "scanSCSIBus() failed: %v", err)

	host := filepath.Join(scsiHostPath, "host0")
	if err := os.MkdirAll(host, mountPerm); err != nil {
		t.Fatal(err)
	}

	err = scanSCSIBus(scsiAddr)
	assert.Nil(t, err, "scanSCSIBus() failed: %v", err)

	err = scanSCSIBus("foo:bar:baz")
	assert.Error(t, err)

	scanPath := filepath.Join(host, "scan")
	_, err = os.Stat(scanPath)
	assert.Nil(t, err, "os.Stat() %s failed: %v", scanPath, err)

	// The following test only works as a non-root user
	skipIfRoot(t)

	err = os.Chmod(scanPath, os.FileMode(0000))
	assert.NoError(t, err)

	err = scanSCSIBus("foo:bar")
	assert.Error(t, err)
}

func testAddDevicesSuccessful(t *testing.T, devices []*pb.Device, spec *pb.Spec) {
	ctx := context.Background()
	err := addDevices(ctx, devices, spec, &sandbox{})
	assert.Nil(t, err, "addDevices() failed: %v", err)
}

func TestAddDevicesEmptyDevicesSuccessful(t *testing.T) {
	var devices []*pb.Device
	spec := &pb.Spec{}

	testAddDevicesSuccessful(t, devices, spec)
}

func TestAddDevicesNilMountsSuccessful(t *testing.T) {
	devices := []*pb.Device{
		nil,
	}

	spec := &pb.Spec{}

	testAddDevicesSuccessful(t, devices, spec)
}

func noopDeviceHandlerReturnNil(_ context.Context, device pb.Device, spec *pb.Spec, s *sandbox, devIdx devIndex) error {
	return nil
}

func noopDeviceHandlerReturnError(_ context.Context, device pb.Device, spec *pb.Spec, s *sandbox, devIdx devIndex) error {
	return fmt.Errorf("Noop handler failure")
}

func TestAddDevicesNoopHandlerSuccessful(t *testing.T) {
	noopHandlerTag := "noop"
	deviceHandlerList = map[string]deviceHandler{
		noopHandlerTag: noopDeviceHandlerReturnNil,
	}

	devices := []*pb.Device{
		{
			Type: noopHandlerTag,
		},
	}

	spec := &pb.Spec{}

	testAddDevicesFailure(t, devices, spec)
}

func testAddDevicesFailure(t *testing.T, devices []*pb.Device, spec *pb.Spec) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := addDevices(ctx, devices, spec, &sandbox{})
	assert.NotNil(t, err, "addDevices() should have failed")
}

func TestAddDevicesUnknownHandlerFailure(t *testing.T) {
	deviceHandlerList = map[string]deviceHandler{}

	devices := []*pb.Device{
		{
			Type: "unknown",
		},
	}

	spec := &pb.Spec{}

	testAddDevicesFailure(t, devices, spec)
}

func TestAddDevicesNoopHandlerFailure(t *testing.T) {
	noopHandlerTag := "noop"
	deviceHandlerList = map[string]deviceHandler{
		noopHandlerTag: noopDeviceHandlerReturnError,
	}

	devices := []*pb.Device{
		{
			Type: noopHandlerTag,
		},
	}

	spec := &pb.Spec{}

	testAddDevicesFailure(t, devices, spec)
}

func TestAddDevice(t *testing.T) {
	assert := assert.New(t)

	emptySpec := &pb.Spec{}

	// Use a dummy handler so that addDevice() will be successful
	// if the Device itself is valid.
	noopHandlerTag := "noop"
	deviceHandlerList = map[string]deviceHandler{
		noopHandlerTag: noopDeviceHandlerReturnNil,
	}

	type testData struct {
		device      *pb.Device
		spec        *pb.Spec
		expectError bool
	}

	data := []testData{
		{
			device:      nil,
			spec:        nil,
			expectError: true,
		},
		{
			device:      &pb.Device{},
			spec:        nil,
			expectError: true,
		},
		{
			device:      &pb.Device{},
			spec:        emptySpec,
			expectError: true,
		},
		{
			device: &pb.Device{
				Id: "foo",
			},
			spec:        emptySpec,
			expectError: true,
		},
		{
			device: &pb.Device{
				Id: "foo",
			},
			spec:        emptySpec,
			expectError: true,
		},
		{
			device: &pb.Device{
				// Missing type
				VmPath:        "/foo",
				ContainerPath: "/foo",
			},
			spec:        emptySpec,
			expectError: true,
		},
		{
			device: &pb.Device{
				// Missing Id and missing VmPath
				Type:          noopHandlerTag,
				ContainerPath: "/foo",
			},
			spec:        emptySpec,
			expectError: true,
		},
		{
			device: &pb.Device{
				// Missing ContainerPath
				Type:   noopHandlerTag,
				VmPath: "/foo",
			},
			spec:        emptySpec,
			expectError: true,
		},
		{
			device: &pb.Device{
				Id:            "foo",
				Type:          "invalid-type",
				VmPath:        "/foo",
				ContainerPath: "/foo",
			},
			spec:        emptySpec,
			expectError: true,
		},
		{
			device: &pb.Device{
				// Id is optional if VmPath is provided
				Type:          noopHandlerTag,
				VmPath:        "/foo",
				ContainerPath: "/foo",
				Options:       []string{},
			},
			spec:        emptySpec,
			expectError: false,
		},
		{
			device: &pb.Device{
				// VmPath is optional if Id is provided
				Id:            "foo",
				Type:          noopHandlerTag,
				ContainerPath: "/foo",
				Options:       []string{},
			},
			spec:        emptySpec,
			expectError: false,
		},
		{
			device: &pb.Device{
				// Options are... optional ;)
				Id:            "foo",
				Type:          noopHandlerTag,
				VmPath:        "/foo",
				ContainerPath: "/foo",
			},
			spec:        emptySpec,
			expectError: false,
		},
		{
			device: &pb.Device{
				Id:            "foo",
				Type:          noopHandlerTag,
				VmPath:        "/foo",
				ContainerPath: "/foo",
				Options:       []string{},
			},
			spec:        emptySpec,
			expectError: false,
		},
		{
			device: &pb.Device{
				Type:          noopHandlerTag,
				VmPath:        "/foo",
				ContainerPath: "/foo",
			},
			spec:        emptySpec,
			expectError: false,
		},
	}

	s := &sandbox{}

	for i, d := range data {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		ctx, cancel := context.WithCancel(context.Background())

		devIdx := makeDevIndex(d.spec)
		err := addDevice(ctx, d.device, d.spec, s, devIdx)
		if d.expectError {
			assert.Error(err, msg)
		} else {
			assert.NoError(err, msg)
		}

		cancel()
	}
}

func TestUpdateSpecDeviceList(t *testing.T) {
	assert := assert.New(t)

	var err error
	spec := &pb.Spec{}
	devIdx := makeDevIndex(spec)
	device := pb.Device{}
	major := int64(7)
	minor := int64(2)

	//ContainerPath empty
	err = updateSpecDeviceList(device, spec, devIdx)
	assert.Error(err)

	device.ContainerPath = "/dev/null"

	//Linux is nil
	err = updateSpecDeviceList(device, spec, devIdx)
	assert.Error(err)

	spec.Linux = &pb.Linux{}

	/// Linux.Devices empty
	err = updateSpecDeviceList(device, spec, devIdx)
	assert.Error(err)

	spec.Linux.Devices = []pb.LinuxDevice{
		{
			Path:  "/dev/null2",
			Major: major,
			Minor: minor,
		},
	}
	devIdx = makeDevIndex(spec)

	// VmPath empty
	err = updateSpecDeviceList(device, spec, devIdx)
	assert.Error(err)

	device.VmPath = "/dev/null"

	// guest and host path are not the same
	err = updateSpecDeviceList(device, spec, devIdx)
	assert.Error(err)

	spec.Linux.Devices[0].Path = device.ContainerPath
	devIdx = makeDevIndex(spec)

	// spec.Linux.Resources is nil
	err = updateSpecDeviceList(device, spec, devIdx)
	assert.NoError(err)

	// update both devices and cgroup lists
	spec.Linux.Devices = []pb.LinuxDevice{
		{
			Path:  device.ContainerPath,
			Major: major,
			Minor: minor,
		},
	}
	spec.Linux.Resources = &pb.LinuxResources{
		Devices: []pb.LinuxDeviceCgroup{
			{
				Major: major,
				Minor: minor,
			},
		},
	}
	devIdx = makeDevIndex(spec)

	err = updateSpecDeviceList(device, spec, devIdx)
	assert.NoError(err)
}

// Test handling in the case that one device has the same guest
// major:minor as a different device's host major:minor
func TestUpdateSpecDeviceListGuestHostConflict(t *testing.T) {
	assert := assert.New(t)

	var nullStat, zeroStat, fullStat unix.Stat_t

	err := unix.Stat("/dev/null", &nullStat)
	assert.NoError(err)
	err = unix.Stat("/dev/zero", &zeroStat)
	assert.NoError(err)
	err = unix.Stat("/dev/full", &fullStat)
	assert.NoError(err)

	hostMajorA := int64(unix.Major(nullStat.Rdev))
	hostMinorA := int64(unix.Minor(nullStat.Rdev))
	hostMajorB := int64(unix.Major(zeroStat.Rdev))
	hostMinorB := int64(unix.Minor(zeroStat.Rdev))

	spec := &pb.Spec{
		Linux: &pb.Linux{
			Devices: []pb.LinuxDevice{
				{
					Path:  "/dev/a",
					Type:  "c",
					Major: hostMajorA,
					Minor: hostMinorA,
				},
				{
					Path:  "/dev/b",
					Type:  "c",
					Major: hostMajorB,
					Minor: hostMinorB,
				},
			},
			Resources: &pb.LinuxResources{
				Devices: []pb.LinuxDeviceCgroup{
					{
						Type:  "c",
						Major: hostMajorA,
						Minor: hostMinorA,
					},
					{
						Type:  "c",
						Major: hostMajorB,
						Minor: hostMinorB,
					},
				},
			},
		},
	}

	devA := pb.Device{
		ContainerPath: "/dev/a",
		VmPath:        "/dev/zero",
	}
	guestMajorA := int64(unix.Major(zeroStat.Rdev))
	guestMinorA := int64(unix.Minor(zeroStat.Rdev))

	devB := pb.Device{
		ContainerPath: "/dev/b",
		VmPath:        "/dev/full",
	}
	guestMajorB := int64(unix.Major(fullStat.Rdev))
	guestMinorB := int64(unix.Minor(fullStat.Rdev))

	devIdx := makeDevIndex(spec)

	assert.Equal(hostMajorA, spec.Linux.Devices[0].Major)
	assert.Equal(hostMinorA, spec.Linux.Devices[0].Minor)
	assert.Equal(hostMajorB, spec.Linux.Devices[1].Major)
	assert.Equal(hostMinorB, spec.Linux.Devices[1].Minor)

	assert.Equal(hostMajorA, spec.Linux.Resources.Devices[0].Major)
	assert.Equal(hostMinorA, spec.Linux.Resources.Devices[0].Minor)
	assert.Equal(hostMajorB, spec.Linux.Resources.Devices[1].Major)
	assert.Equal(hostMinorB, spec.Linux.Resources.Devices[1].Minor)

	err = updateSpecDeviceList(devA, spec, devIdx)
	assert.NoError(err)

	assert.Equal(guestMajorA, spec.Linux.Devices[0].Major)
	assert.Equal(guestMinorA, spec.Linux.Devices[0].Minor)
	assert.Equal(hostMajorB, spec.Linux.Devices[1].Major)
	assert.Equal(hostMinorB, spec.Linux.Devices[1].Minor)

	assert.Equal(guestMajorA, spec.Linux.Resources.Devices[0].Major)
	assert.Equal(guestMinorA, spec.Linux.Resources.Devices[0].Minor)
	assert.Equal(hostMajorB, spec.Linux.Resources.Devices[1].Major)
	assert.Equal(hostMinorB, spec.Linux.Resources.Devices[1].Minor)

	err = updateSpecDeviceList(devB, spec, devIdx)
	assert.NoError(err)

	assert.Equal(guestMajorA, spec.Linux.Devices[0].Major)
	assert.Equal(guestMinorA, spec.Linux.Devices[0].Minor)
	assert.Equal(guestMajorB, spec.Linux.Devices[1].Major)
	assert.Equal(guestMinorB, spec.Linux.Devices[1].Minor)

	assert.Equal(guestMajorA, spec.Linux.Resources.Devices[0].Major)
	assert.Equal(guestMinorA, spec.Linux.Resources.Devices[0].Minor)
	assert.Equal(guestMajorB, spec.Linux.Resources.Devices[1].Major)
	assert.Equal(guestMinorB, spec.Linux.Resources.Devices[1].Minor)
}

// Test handling in the case that the host has a block device and a
// character device with the same major:minor, but the equivalent
// guest devices do *not* have the same major:minor
func TestUpdateSpecDeviceListCharBlockConflict(t *testing.T) {
	assert := assert.New(t)

	var nullStat unix.Stat_t
	err := unix.Stat("/dev/null", &nullStat)
	assert.NoError(err)

	guestMajor := int64(unix.Major(nullStat.Rdev))
	guestMinor := int64(unix.Minor(nullStat.Rdev))

	hostMajor := int64(99)
	hostMinor := int64(99)

	spec := &pb.Spec{
		Linux: &pb.Linux{
			Devices: []pb.LinuxDevice{
				{
					Path:  "/dev/char",
					Type:  "c",
					Major: hostMajor,
					Minor: hostMinor,
				},
				{
					Path:  "/dev/block",
					Type:  "b",
					Major: hostMajor,
					Minor: hostMinor,
				},
			},
			Resources: &pb.LinuxResources{
				Devices: []pb.LinuxDeviceCgroup{
					{
						Type:  "c",
						Major: hostMajor,
						Minor: hostMinor,
					},
					{
						Type:  "b",
						Major: hostMajor,
						Minor: hostMinor,
					},
				},
			},
		},
	}

	dev := pb.Device{
		ContainerPath: "/dev/char",
		VmPath:        "/dev/null",
	}

	assert.Equal(hostMajor, spec.Linux.Resources.Devices[0].Major)
	assert.Equal(hostMinor, spec.Linux.Resources.Devices[0].Minor)
	assert.Equal(hostMajor, spec.Linux.Resources.Devices[1].Major)
	assert.Equal(hostMinor, spec.Linux.Resources.Devices[1].Minor)

	devIdx := makeDevIndex(spec)
	err = updateSpecDeviceList(dev, spec, devIdx)
	assert.NoError(err)

	// Only the char device, not the block device should be updated
	assert.Equal(guestMajor, spec.Linux.Resources.Devices[0].Major)
	assert.Equal(guestMinor, spec.Linux.Resources.Devices[0].Minor)
	assert.Equal(hostMajor, spec.Linux.Resources.Devices[1].Major)
	assert.Equal(hostMinor, spec.Linux.Resources.Devices[1].Minor)
}

func TestRescanPciBus(t *testing.T) {
	skipUnlessRoot(t)

	assert := assert.New(t)

	err := rescanPciBus()
	assert.Nil(err)

}

func TestRescanPciBusSubverted(t *testing.T) {
	assert := assert.New(t)

	dir, err := ioutil.TempDir("", "")
	assert.NoError(err)
	defer os.RemoveAll(dir)

	rescanDir := filepath.Join(dir, "rescan-dir")

	err = os.MkdirAll(rescanDir, testDirMode)
	assert.NoError(err)

	rescan := filepath.Join(rescanDir, "rescan")

	savedFile := pciBusRescanFile
	defer func() {
		pciBusRescanFile = savedFile
	}()

	pciBusRescanFile = rescan

	err = rescanPciBus()
	assert.NoError(err)

	os.RemoveAll(rescanDir)
	err = rescanPciBus()
	assert.Error(err)
}

func TestVirtioMmioBlkDeviceHandler(t *testing.T) {
	assert := assert.New(t)

	device := pb.Device{}
	spec := &pb.Spec{}
	devIdx := makeDevIndex(spec)
	sb := &sandbox{}

	ctx := context.Background()

	err := virtioMmioBlkDeviceHandler(ctx, device, spec, sb, devIdx)
	assert.Error(err)

	device.VmPath = "foo"
	device.ContainerPath = ""

	err = virtioMmioBlkDeviceHandler(ctx, device, spec, sb, devIdx)
	assert.Error(err)
}

func TestVirtioSCSIDeviceHandler(t *testing.T) {
	assert := assert.New(t)

	device := pb.Device{}
	spec := &pb.Spec{}
	devIdx := makeDevIndex(spec)
	sb := &sandbox{}

	ctx, cancel := context.WithCancel(context.Background())

	err := virtioSCSIDeviceHandler(ctx, device, spec, sb, devIdx)
	assert.Error(err)
	cancel()

	savedFunc := getSCSIDevPath
	getSCSIDevPath = func(s *sandbox, scsiAddr string) (string, error) {
		return "foo", nil
	}

	defer func() {
		getSCSIDevPath = savedFunc
	}()

	ctx, cancel = context.WithCancel(context.Background())

	err = virtioSCSIDeviceHandler(ctx, device, spec, sb, devIdx)
	assert.Error(err)
	cancel()
}

func TestNvdimmDeviceHandler(t *testing.T) {
	assert := assert.New(t)

	device := pb.Device{}
	spec := &pb.Spec{}
	devIdx := makeDevIndex(spec)
	sb := &sandbox{}

	ctx := context.Background()

	err := nvdimmDeviceHandler(ctx, device, spec, sb, devIdx)
	assert.Error(err)
}

func TestGetPCIDeviceName(t *testing.T) {
	assert := assert.New(t)

	dir, err := ioutil.TempDir("", "")
	assert.NoError(err)
	defer os.RemoveAll(dir)

	testSysfsDir := filepath.Join(dir, "sysfs")

	savedDir := sysfsDir
	defer func() {
		sysfsDir = savedDir
	}()

	sysfsDir = testSysfsDir

	savedFunc := pciPathToSysfs
	defer func() {
		pciPathToSysfs = savedFunc
	}()

	pciPathToSysfs = func(pciPath PciPath) (string, error) {
		return "", nil
	}

	sb := sandbox{
		deviceWatchers: make(map[string](chan string)),
	}

	_, err = getPCIDeviceNameImpl(&sb, PciPath{""})
	assert.Error(err)

	rescanDir := filepath.Dir(pciBusRescanFile)
	err = os.MkdirAll(rescanDir, testDirMode)
	assert.NoError(err)

	_, err = getPCIDeviceNameImpl(&sb, PciPath{""})
	assert.Error(err)
}

func TestGetSCSIDevPath(t *testing.T) {
	assert := assert.New(t)

	savedFunc := scanSCSIBus
	savedTimeout := hotplugTimeout

	defer func() {
		scanSCSIBus = savedFunc
		hotplugTimeout = savedTimeout
	}()

	scanSCSIBus = func(_ string) error {
		return nil
	}

	sb := sandbox{deviceWatchers: make(map[string](chan string))}

	_, err := getSCSIDevPathImpl(&sb, "")
	assert.Error(err)
}

func TestCheckCCWBusFormat(t *testing.T) {
	assert := assert.New(t)

	wrongBuses := []string{"", "fe.0.0000", "0.5.0000", "some_wrong_path", "0.1.fffff", "0.0.0"}
	rightBuses := []string{"0.3.abcd", "0.0.0000", "0.1.0000"}

	for _, bus := range wrongBuses {
		err := checkCCWBusFormat(bus)
		assert.NotNil(err, fmt.Sprintf("checkCCWBusFormat() should have been failed with bus %s", bus))
	}

	for _, bus := range rightBuses {
		err := checkCCWBusFormat(bus)
		assert.Nil(err)
	}
}

func TestGetDeviceName(t *testing.T) {
	assert := assert.New(t)
	devName := "vda"
	busID := "0.0.0005"
	devPath := path.Join("/devices/css0/0.0.0004", busID, "virtio4/block", devName)

	systodevmap := make(map[string]string)
	systodevmap[devPath] = devName

	sb := sandbox{
		deviceWatchers: make(map[string](chan string)),
		sysToDevMap:    systodevmap,
	}

	name, err := getDeviceName(&sb, busID)

	assert.Nil(err)
	assert.Equal(name, path.Join(devRootPath, devName))

	delete(sb.sysToDevMap, devPath)

	go func() {
		for {
			sb.Lock()
			for devAddress, ch := range sb.deviceWatchers {
				if ch == nil {
					continue
				}

				if strings.Contains(devPath, devAddress) && strings.HasSuffix(devAddress, blkCCWSuffix) {
					ch <- devName
					close(ch)
					delete(sb.deviceWatchers, devAddress)
					goto OUT
				}
			}
			sb.Unlock()
		}
	OUT:
		sb.Unlock()
	}()

	name, err = getDeviceName(&sb, path.Join(busID, blkCCWSuffix))

	assert.Nil(err)
	assert.Equal(name, path.Join(devRootPath, devName))
}

func TestUpdateDeviceCgroupForGuestRootfs(t *testing.T) {
	skipUnlessRoot(t)
	assert := assert.New(t)

	spec := &pb.Spec{}

	spec.Linux = &pb.Linux{}
	spec.Linux.Resources = &pb.LinuxResources{}

	updateDeviceCgroupForGuestRootfs(spec)
	assert.Equal(1, len(spec.Linux.Resources.Devices))

	var devStat unix.Stat_t
	err := unix.Stat(vmRootfs, &devStat)
	if err != nil {
		return
	}

	assert.Equal(spec.Linux.Resources.Devices[0].Major, int64(unix.Major(devStat.Dev)))
	assert.Equal(spec.Linux.Resources.Devices[0].Minor, int64(unix.Minor(devStat.Dev)))
}
