//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

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

	err = virtioBlkDeviceHandler(device, spec)
	assert.NotNil(t, err, "blockDeviceHandler() should have failed")
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

func testAddDevicesSuccessful(t *testing.T, devices []*pb.Device, spec *pb.Spec) {
	err := addDevices(devices, spec)
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

func noopDeviceHandlerReturnNil(device pb.Device, spec *pb.Spec) error {
	return nil
}

func noopDeviceHandlerReturnError(device pb.Device, spec *pb.Spec) error {
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

	testAddDevicesSuccessful(t, devices, spec)
}

func testAddDevicesFailure(t *testing.T, devices []*pb.Device, spec *pb.Spec) {
	err := addDevices(devices, spec)
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
