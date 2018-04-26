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
	"path/filepath"
	"syscall"
	"testing"

	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/stretchr/testify/assert"
)

func createSafeAndFakeStorage() (pb.Storage, error) {
	dirPath, err := ioutil.TempDir("", "fake-dir")
	if err != nil {
		return pb.Storage{}, err
	}

	return pb.Storage{
		Source:     dirPath,
		MountPoint: filepath.Join(dirPath, "test-mount"),
	}, nil
}

func TestVirtio9pStorageHandlerSuccessful(t *testing.T) {
	skipUnlessRoot(t)

	storage, err := createSafeAndFakeStorage()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storage.Source)
	defer syscall.Unmount(storage.MountPoint, 0)

	storage.Fstype = "bind"
	storage.Options = []string{"rbind"}

	_, err = virtio9pStorageHandler(storage, &sandbox{})
	assert.Nil(t, err, "storage9pDriverHandler() failed: %v", err)
}

func TestVirtioBlkStorageHandlerSuccessful(t *testing.T) {
	skipUnlessRoot(t)

	testDir, err := ioutil.TempDir("", "kata-agent-tmp-")
	if err != nil {
		t.Fatal(t, err)
	}

	bridgeID := "02"
	deviceID := "03"
	pciBus := "0000:01"
	completePCIAddr := fmt.Sprintf("0000:00:%s.0/%s:%s.0", bridgeID, pciBus, deviceID)

	pciID := fmt.Sprintf("%s/%s", bridgeID, deviceID)

	sysBusPrefix = testDir
	bridgeBusPath := fmt.Sprintf(pciBusPathFormat, sysBusPrefix, "0000:00:02.0")

	err = os.MkdirAll(filepath.Join(bridgeBusPath, pciBus), mountPerm)
	assert.Nil(t, err)

	devPath, err := createFakeDevicePath()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(devPath)

	dirPath, err := ioutil.TempDir("", "fake-dir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dirPath)

	storage := pb.Storage{
		Source:     pciID,
		MountPoint: filepath.Join(dirPath, "test-mount"),
	}
	defer syscall.Unmount(storage.MountPoint, 0)

	s := &sandbox{
		pciDeviceMap: make(map[string]string),
	}

	s.Lock()
	s.pciDeviceMap[completePCIAddr] = devPath
	s.Unlock()

	storage.Fstype = "bind"
	storage.Options = []string{"rbind"}

	systemDevPath = ""
	_, err = virtioBlkStorageHandler(storage, s)
	assert.Nil(t, err, "storageBlockStorageDriverHandler() failed: %v", err)
}

func testAddStoragesSuccessful(t *testing.T, storages []*pb.Storage) {
	_, err := addStorages(storages, &sandbox{})
	assert.Nil(t, err, "addStorages() failed: %v", err)
}

func TestAddStoragesEmptyStoragesSuccessful(t *testing.T) {
	var storages []*pb.Storage

	testAddStoragesSuccessful(t, storages)
}

func TestAddStoragesNilStoragesSuccessful(t *testing.T) {
	storages := []*pb.Storage{
		nil,
	}

	testAddStoragesSuccessful(t, storages)
}

func noopStorageHandlerReturnNil(storage pb.Storage, s *sandbox) (string, error) {
	return "", nil
}

func noopStorageHandlerReturnError(storage pb.Storage, s *sandbox) (string, error) {
	return "", fmt.Errorf("Noop handler failure")
}

func TestAddStoragesNoopHandlerSuccessful(t *testing.T) {
	noopHandlerTag := "noop"
	storageHandlerList = map[string]storageHandler{
		noopHandlerTag: noopStorageHandlerReturnNil,
	}

	storages := []*pb.Storage{
		{
			Driver: noopHandlerTag,
		},
	}

	testAddStoragesSuccessful(t, storages)
}

func testAddStoragesFailure(t *testing.T, storages []*pb.Storage) {
	_, err := addStorages(storages, &sandbox{})
	assert.NotNil(t, err, "addStorages() should have failed")
}

func TestAddStoragesUnknownHandlerFailure(t *testing.T) {
	storageHandlerList = map[string]storageHandler{}

	storages := []*pb.Storage{
		{
			Driver: "unknown",
		},
	}

	testAddStoragesFailure(t, storages)
}

func TestAddStoragesNoopHandlerFailure(t *testing.T) {
	noopHandlerTag := "noop"
	storageHandlerList = map[string]storageHandler{
		noopHandlerTag: noopStorageHandlerReturnError,
	}

	storages := []*pb.Storage{
		{
			Driver: noopHandlerTag,
		},
	}

	testAddStoragesFailure(t, storages)
}

func TestMount(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		source      string
		destination string
		fsType      string
		flags       int
		options     string

		expectError bool
	}

	data := []testData{
		{"", "", "", 0, "", true},
		{"", "/foo", "9p", 0, "", true},
		{"proc", "", "9p", 0, "", true},
		{"proc", "/proc", "", 0, "", true},
	}

	for i, d := range data {
		err := mount(d.source, d.destination, d.fsType, d.flags, d.options)

		if d.expectError {
			assert.Errorf(err, "test %d (%+v)", i, d)
		} else {
			assert.NoErrorf(err, "test %d (%+v)", i, d)
		}
	}
}
