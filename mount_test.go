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

	_, err = virtio9pStorageHandler(storage)
	assert.Nil(t, err, "storage9pDriverHandler() failed: %v", err)
}

func TestVirtioBlkStorageHandlerSuccessful(t *testing.T) {
	skipUnlessRoot(t)

	devPath, err := createFakeDevicePath()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(devPath)

	storage, err := createSafeAndFakeStorage()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(storage.Source)
	defer syscall.Unmount(storage.MountPoint, 0)

	storage.Fstype = "bind"
	storage.Options = []string{"rbind"}

	_, err = virtioBlkStorageHandler(storage)
	assert.Nil(t, err, "storageBlockStorageDriverHandler() failed: %v", err)
}

func testAddStoragesSuccessful(t *testing.T, storages []*pb.Storage) {
	_, err := addStorages(storages)
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

func noopStorageHandlerReturnNil(storage pb.Storage) (string, error) {
	return "", nil
}

func noopStorageHandlerReturnError(storage pb.Storage) (string, error) {
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
	_, err := addStorages(storages)
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
