//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"io/ioutil"
	"os"
	"testing"

	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/stretchr/testify/assert"
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

func testblockDeviceHandlerSuccessful(t *testing.T, device pb.Device, spec *pb.Spec) {
	devPath, err := createFakeDevicePath()
	assert.Nil(t, err, "Fake device path creation failed: %v", err)
	defer os.RemoveAll(devPath)

	device.VmPath = devPath

	err = blockDeviceHandler(device, spec)
	assert.Nil(t, err, "blockDeviceHandler() failed: %v", err)
}

func TestBlockDeviceHandlerNilLinuxSpecSuccessful(t *testing.T) {
	spec := &pb.Spec{}

	testblockDeviceHandlerSuccessful(t, pb.Device{}, spec)
}

func testblockDeviceHandlerFailure(t *testing.T, device pb.Device, spec *pb.Spec) {
	devPath, err := createFakeDevicePath()
	assert.Nil(t, err, "Fake device path creation failed: %v", err)
	defer os.RemoveAll(devPath)

	device.VmPath = devPath
	device.ContainerPath = "some-not-empty-path"

	err = blockDeviceHandler(device, spec)
	assert.NotNil(t, err, "blockDeviceHandler() should have failed")
}

func TestBlockDeviceHandlerNilLinuxSpecFailure(t *testing.T) {
	spec := &pb.Spec{}

	testblockDeviceHandlerFailure(t, pb.Device{}, spec)
}

func TestBlockDeviceHandlerEmptyLinuxDevicesSpecFailure(t *testing.T) {
	spec := &pb.Spec{
		Linux: &pb.Linux{},
	}

	testblockDeviceHandlerFailure(t, pb.Device{}, spec)
}
