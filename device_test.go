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
	"path/filepath"
	"testing"

	"github.com/kata-containers/agent/pkg/uevent"
	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/stretchr/testify/assert"
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

	err = virtioBlkDeviceHandler(ctx, device, spec, &sandbox{})
	assert.NotNil(t, err, "blockDeviceHandler() should have failed")

	savedFunc := getPCIDeviceName
	getPCIDeviceName = func(s *sandbox, pciID string) (string, error) {
		return "foo", nil
	}

	defer func() {
		getPCIDeviceName = savedFunc
	}()

	err = virtioBlkDeviceHandler(ctx, device, spec, &sandbox{})
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

func TestGetPCIAddress(t *testing.T) {
	testDir, err := ioutil.TempDir("", "kata-agent-tmp-")
	if err != nil {
		t.Fatal(t, err)
	}
	defer os.RemoveAll(testDir)

	pciID := "02"
	_, err = getDevicePCIAddress(pciID)
	assert.NotNil(t, err)

	pciID = "02/03/04"
	_, err = getDevicePCIAddress(pciID)
	assert.NotNil(t, err)

	bridgeID := "02"
	deviceID := "03"
	pciBus := "0000:01"
	expectedPCIAddress := "0000:00:02.0/0000:01:03.0"
	pciID = fmt.Sprintf("%s/%s", bridgeID, deviceID)

	// Set sysBusPrefix to test directory for unit tests.
	sysBusPrefix = testDir
	bridgeBusPath := fmt.Sprintf(pciBusPathFormat, sysBusPrefix, "0000:00:02.0")

	_, err = getDevicePCIAddress(pciID)
	assert.NotNil(t, err)

	err = os.MkdirAll(bridgeBusPath, mountPerm)
	assert.Nil(t, err)

	_, err = getDevicePCIAddress(pciID)
	assert.NotNil(t, err)

	err = os.MkdirAll(filepath.Join(bridgeBusPath, pciBus), mountPerm)
	assert.Nil(t, err)

	addr, err := getDevicePCIAddress(pciID)
	assert.Nil(t, err)

	assert.Equal(t, addr, expectedPCIAddress)
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

func noopDeviceHandlerReturnNil(_ context.Context, device pb.Device, spec *pb.Spec, s *sandbox) error {
	return nil
}

func noopDeviceHandlerReturnError(_ context.Context, device pb.Device, spec *pb.Spec, s *sandbox) error {
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

		err := addDevice(ctx, d.device, d.spec, s)
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
	device := pb.Device{}
	major := int64(7)
	minor := int64(2)

	//ContainerPath empty
	err = updateSpecDeviceList(device, spec)
	assert.Error(err)

	device.ContainerPath = "/dev/null"

	//Linux is nil
	err = updateSpecDeviceList(device, spec)
	assert.Error(err)

	spec.Linux = &pb.Linux{}

	/// Linux.Devices empty
	err = updateSpecDeviceList(device, spec)
	assert.Error(err)

	spec.Linux.Devices = []pb.LinuxDevice{
		{
			Path:  "/dev/null2",
			Major: major,
			Minor: minor,
		},
	}

	// VmPath empty
	err = updateSpecDeviceList(device, spec)
	assert.Error(err)

	device.VmPath = "/dev/null"

	// guest and host path are not the same
	err = updateSpecDeviceList(device, spec)
	assert.Error(err)

	spec.Linux.Devices[0].Path = device.ContainerPath

	// spec.Linux.Resources is nil
	err = updateSpecDeviceList(device, spec)
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

	err = updateSpecDeviceList(device, spec)
	assert.NoError(err)
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
	sb := &sandbox{}

	ctx := context.Background()

	err := virtioMmioBlkDeviceHandler(ctx, device, spec, sb)
	assert.Error(err)

	device.VmPath = "foo"
	device.ContainerPath = ""

	err = virtioMmioBlkDeviceHandler(ctx, device, spec, sb)
	assert.Error(err)
}

func TestVirtioSCSIDeviceHandler(t *testing.T) {
	assert := assert.New(t)

	device := pb.Device{}
	spec := &pb.Spec{}
	sb := &sandbox{}

	ctx, cancel := context.WithCancel(context.Background())

	err := virtioSCSIDeviceHandler(ctx, device, spec, sb)
	assert.Error(err)
	cancel()

	savedFunc := getSCSIDevPath
	getSCSIDevPath = func(_ context.Context, scsiAddr string) (string, error) {
		return "foo", nil
	}

	defer func() {
		getSCSIDevPath = savedFunc
	}()

	ctx, cancel = context.WithCancel(context.Background())

	err = virtioSCSIDeviceHandler(ctx, device, spec, sb)
	assert.Error(err)
	cancel()
}

func TestNvdimmDeviceHandler(t *testing.T) {
	assert := assert.New(t)

	device := pb.Device{}
	spec := &pb.Spec{}
	sb := &sandbox{}

	ctx := context.Background()

	err := nvdimmDeviceHandler(ctx, device, spec, sb)
	assert.Error(err)
}

func TestWaitForDevice(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		devicePath  string
		deviceName  string
		cb          checkUeventCb
		expectError bool
	}

	existingDevice := "/dev/null"

	invalidDevice := "/dev/silly-invalid-device-name"
	_, err := os.Stat(invalidDevice)
	assert.Error(err)
	assert.True(os.IsNotExist(err))

	cb := func(uEv *uevent.Uevent) bool {
		return true
	}

	savedTimeout := timeoutHotplug
	timeoutHotplug = 0
	defer func() {
		timeoutHotplug = savedTimeout
	}()

	data := []testData{
		{"", "", nil, true},
		{"foo", "", nil, true},
		{"", "foo", nil, true},
		{"foo", "bar", nil, true},
		{"foo", "bar", cb, true},
		{existingDevice, "", nil, true},
		{existingDevice, "", cb, true},
		{invalidDevice, "bar", cb, true},

		{existingDevice, "bar", cb, false},
	}

	for i, d := range data {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		ctx, cancel := context.WithCancel(context.Background())
		err := waitForDevice(ctx, d.devicePath, d.deviceName, d.cb)
		cancel()

		if d.expectError {
			assert.Error(err, msg)
			continue
		}

		assert.NoError(err)
	}
}

func TestFindSCSIDisk(t *testing.T) {
	assert := assert.New(t)

	dir, err := ioutil.TempDir("", "")
	assert.NoError(err)
	defer os.RemoveAll(dir)

	goodDir := filepath.Join(dir, "correct-number-of-files")
	emptyDir := filepath.Join(dir, "empty")
	badDir := filepath.Join(dir, "too-many-files")

	dirs := []string{goodDir, emptyDir, badDir}

	for _, dir := range dirs {
		err = os.MkdirAll(dir, testDirMode)
		assert.NoError(err)
	}

	goodFileName := "good-file"
	goodFile := filepath.Join(goodDir, goodFileName)
	err = createEmptyFile(goodFile)
	assert.NoError(err)

	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("file-%d", i+1)
		fullPath := filepath.Join(badDir, name)
		err := createEmptyFile(fullPath)
		assert.NoError(err)
	}

	type testData struct {
		scsiPath     string
		expectedName string
		expectError  bool
	}

	data := []testData{
		{"", "", true},
		{emptyDir, "", true},
		{badDir, "", true},
		{goodDir, goodFileName, false},
	}

	for i, d := range data {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		name, err := findSCSIDisk(d.scsiPath)

		if d.expectError {
			assert.Error(err, msg)
			continue
		}

		assert.NoError(err, msg)
		assert.Equal(d.expectedName, name, msg)
	}
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

	savedFunc := getDevicePCIAddress
	defer func() {
		getDevicePCIAddress = savedFunc
	}()

	getDevicePCIAddress = func(pciID string) (string, error) {
		return "", nil
	}

	sb := sandbox{
		deviceWatchers: make(map[string](chan string)),
	}

	_, err = getPCIDeviceNameImpl(&sb, "")
	assert.Error(err)

	rescanDir := filepath.Dir(pciBusRescanFile)
	err = os.MkdirAll(rescanDir, testDirMode)
	assert.NoError(err)

	_, err = getPCIDeviceNameImpl(&sb, "")
	assert.Error(err)
}

func TestGetSCSIDevPath(t *testing.T) {
	assert := assert.New(t)

	savedFunc := scanSCSIBus
	savedTimeout := timeoutHotplug

	defer func() {
		scanSCSIBus = savedFunc
		timeoutHotplug = savedTimeout
	}()

	scanSCSIBus = func(_ string) error {
		return nil
	}

	timeoutHotplug = 0

	ctx, cancel := context.WithCancel(context.Background())
	_, err := getSCSIDevPathImpl(ctx, "")
	assert.Error(err)
	cancel()

}

func TestFindBlkCCWDevPath(t *testing.T) {
	bus := "0.0.0005"
	assert := assert.New(t)
	expectDev := "vdb"
	dir := fmt.Sprintf("/tmp/sys/bus/ccw/devices/%s/virtio5/block/%s", bus, expectDev)
	busPath := fmt.Sprintf("/tmp/sys/bus/ccw/devices/%s", bus)
	err := os.MkdirAll(dir, mountPerm)
	assert.Nil(err)

	dev, err := findBlkCCWDevPath(busPath)
	assert.Nil(err)

	if dev != expectDev {
		t.Errorf("Expected value %s got %s", expectDev, dev)
	}

	bus = "../dev"
	busPath = fmt.Sprintf("/tmp/sys/bus/ccw/devices/%s", bus)
	err = os.MkdirAll(dir, mountPerm)
	assert.Nil(err)
	_, err = findBlkCCWDevPath(busPath)
	assert.NotNil(err, fmt.Sprintf("findBlkCCWDevPath() should have been failed with bus %s", bus))

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
