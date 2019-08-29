//
// Copyright (c) 2018-2019 Intel Corporation
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

func TestEphemeralStorageHandlerSuccessful(t *testing.T) {
	skipUnlessRoot(t)

	storage, err := createSafeAndFakeStorage()
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Unmount(storage.MountPoint, 0)
	defer os.RemoveAll(storage.MountPoint)

	storage.Fstype = typeTmpFs
	storage.Source = typeTmpFs
	sbs := make(map[string]*sandboxStorage)

	ctx := context.Background()

	_, err = ephemeralStorageHandler(ctx, storage, &sandbox{storages: sbs})
	assert.Nil(t, err, "ephemeralStorageHandler() failed: %v", err)

	// Try again. This time the storage won't be new
	result, err := ephemeralStorageHandler(ctx, storage, &sandbox{storages: sbs})
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestLocalStorageHandlerSuccessful(t *testing.T) {
	skipUnlessRoot(t)

	storage, err := createSafeAndFakeStorage()
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Unmount(storage.MountPoint, 0)
	defer os.RemoveAll(storage.MountPoint)

	sbs := make(map[string]*sandboxStorage)

	ctx := context.Background()

	_, err = localStorageHandler(ctx, storage, &sandbox{storages: sbs})
	assert.Nil(t, err, "localStorageHandler() failed: %v", err)

	// Check the default mode of the mountpoint
	info, err := os.Stat(storage.MountPoint)
	assert.Nil(t, err)
	assert.Equal(t, os.ModePerm|os.ModeDir, info.Mode())

	// Try again. This time the storage won't be new
	result, err := localStorageHandler(ctx, storage, &sandbox{storages: sbs})
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestLocalStorageHandlerPermModeSuccessful(t *testing.T) {
	skipUnlessRoot(t)

	// Test a set of different modes for the mount point
	tests := []struct {
		requested string
		expected  os.FileMode
	}{
		{
			"0400",
			os.FileMode(0400),
		},
		{
			"0600",
			os.FileMode(0600),
		},
		{
			"0755",
			os.FileMode(0755),
		},
		{
			"0777",
			os.FileMode(0777),
		},
	}

	for _, tt := range tests {
		t.Run(tt.requested, func(t *testing.T) {
			storage, err := createSafeAndFakeStorage()
			if err != nil {
				t.Fatal(err)
			}
			defer syscall.Unmount(storage.MountPoint, 0)
			defer os.RemoveAll(storage.MountPoint)

			storage.Options = []string{
				"mode=" + tt.requested,
			}

			ctx := context.Background()

			sbs := make(map[string]*sandboxStorage)
			_, err = localStorageHandler(ctx, storage, &sandbox{storages: sbs})
			assert.Nil(t, err, "localStorageHandler() failed: %v", err)

			// Check the mode of the mountpoint
			info, err := os.Stat(storage.MountPoint)
			assert.Nil(t, err)
			assert.Equal(t, tt.expected|os.ModeDir, info.Mode())
		})
	}
}

func TestLocalStorageHandlerPermModeFailure(t *testing.T) {
	skipUnlessRoot(t)

	storage, err := createSafeAndFakeStorage()
	if err != nil {
		t.Fatal(err)
	}
	//defer syscall.Unmount(storage.MountPoint, 0)
	//defer os.RemoveAll(storage.MountPoint)

	// Set the mode to something invalid
	storage.Options = []string{
		"mode=abcde",
	}

	sbs := make(map[string]*sandboxStorage)

	ctx := context.Background()

	_, err = localStorageHandler(ctx, storage, &sandbox{storages: sbs})
	assert.NotNil(t, err, "localStorageHandler() should have failed")
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

	ctx := context.Background()

	_, err = virtio9pStorageHandler(ctx, storage, &sandbox{})
	assert.Nil(t, err, "storage9pDriverHandler() failed: %v", err)
}

func TestVirtioBlkStoragePathFailure(t *testing.T) {
	s := &sandbox{}

	storage := pb.Storage{
		Source: "/home/developer/test",
	}

	ctx := context.Background()

	_, err := virtioBlkStorageHandler(ctx, storage, s)
	assert.NotNil(t, err, "virtioBlkStorageHandler() should have failed")
}

func TestVirtioBlkStorageDeviceFailure(t *testing.T) {
	s := &sandbox{}

	for i, source := range []string{"/dev/foo", "/dev/disk"} {
		msg := fmt.Sprintf("source[%d]: %+v\n", i, source)
		storage := pb.Storage{
			Source: source,
		}

		ctx := context.Background()

		_, err := virtioBlkStorageHandler(ctx, storage, s)
		assert.NotNil(t, err, fmt.Sprintf("%s: virtioBlkStorageHandler() should have failed", msg))
	}
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

	ctx := context.Background()

	systemDevPath = ""
	_, err = virtioBlkStorageHandler(ctx, storage, s)
	assert.Nil(t, err, "storageBlockStorageDriverHandler() failed: %v", err)
}

func TestVirtioSCSIStorageHandlerFailure(t *testing.T) {
	skipIfRoot(t)

	assert := assert.New(t)

	const expectedDevPath = "/dev/some/where"

	savedSCSIDevPathFunc := getSCSIDevPath
	getSCSIDevPath = func(s *sandbox, scsiAddr string) (string, error) {
		return expectedDevPath, nil
	}

	defer func() {
		getSCSIDevPath = savedSCSIDevPathFunc
	}()

	storage := pb.Storage{
		MountPoint: "/new/mount/point",
	}

	sb := sandbox{
		storages: make(map[string]*sandboxStorage),
	}

	assert.Empty(storage.Source)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := virtioSCSIStorageHandler(ctx, storage, &sb)
	assert.Error(err)
}

func testAddStoragesSuccessful(t *testing.T, storages []*pb.Storage) {
	_, err := addStorages(context.Background(), storages, &sandbox{})
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

func noopStorageHandlerReturnNil(_ context.Context, storage pb.Storage, s *sandbox) (string, error) {
	return "", nil
}

func noopStorageHandlerReturnError(_ context.Context, storage pb.Storage, s *sandbox) (string, error) {
	return "", fmt.Errorf("Noop handler failure")
}

func TestAddStoragesNoopHandlerSuccessful(t *testing.T) {
	noopHandlerTag := "noop"
	savedStorageHandlerList := storageHandlerList

	storageHandlerList = map[string]storageHandler{
		noopHandlerTag: noopStorageHandlerReturnNil,
	}

	defer func() {
		storageHandlerList = savedStorageHandlerList
	}()

	storages := []*pb.Storage{
		{
			Driver: noopHandlerTag,
		},
	}

	testAddStoragesSuccessful(t, storages)
}

func testAddStoragesFailure(t *testing.T, storages []*pb.Storage) {
	_, err := addStorages(context.Background(), storages, &sandbox{})
	assert.NotNil(t, err, "addStorages() should have failed")
}

func TestAddStoragesUnknownHandlerFailure(t *testing.T) {
	savedStorageHandlerList := storageHandlerList

	storageHandlerList = map[string]storageHandler{}

	defer func() {
		storageHandlerList = savedStorageHandlerList
	}()

	storages := []*pb.Storage{
		{
			Driver: "unknown",
		},
	}

	testAddStoragesFailure(t, storages)
}

func TestAddStoragesNoopHandlerFailure(t *testing.T) {
	noopHandlerTag := "noop"

	savedStorageHandlerList := storageHandlerList

	storageHandlerList = map[string]storageHandler{
		noopHandlerTag: noopStorageHandlerReturnError,
	}

	defer func() {
		storageHandlerList = savedStorageHandlerList
	}()

	storages := []*pb.Storage{
		{
			Driver: noopHandlerTag,
		},
	}

	testAddStoragesFailure(t, storages)
}

func TestMount(t *testing.T) {
	assert := assert.New(t)

	tmpdir, err := ioutil.TempDir("", "")
	assert.NoError(err)
	defer os.RemoveAll(tmpdir)

	dir := filepath.Join(tmpdir, "dir")

	// make directory unreadable by non-root user
	err = os.Mkdir(dir, os.FileMode(0000))
	assert.NoError(err)

	subdir := filepath.Join(dir, "sub1", "sub2")

	validSubdir := filepath.Join(tmpdir, "valid-subdir")

	existsFile := filepath.Join(tmpdir, "exists-file")
	err = createEmptyFile(existsFile)
	assert.NoError(err)

	existingNonCreatableFile := filepath.Join(tmpdir, "uncreatable")
	err = createEmptyFileWithPerms(existingNonCreatableFile, 0000)
	assert.NoError(err)

	// We only test error scenarios
	skipIfRoot(t)

	symLinkName := filepath.Join(tmpdir, "sym-link-name")
	symLinkDest := filepath.Join(tmpdir, "sym-link-dest")

	//err = createEmptyFile(symLinkDest)
	//assert.NoError(err)

	err = os.Symlink(symLinkDest, symLinkName)
	assert.NoError(err)

	// Now, break the symlink
	////os.Remove(symLinkDest)

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
		{"proc", "", "virtio_fs", 0, "", true},
		{"proc", subdir, "virtio_fs", 0, "", true},
		{"proc", subdir, "foo", 0, "", true},
		{symLinkName, symLinkDest, "moo", 0, "", true},
		{existsFile, existingNonCreatableFile, "bind", 0, "", true},
		{"tmpfs", validSubdir, "tmpfs", 0, "", true},
		{"proc", validSubdir, "9p", 0, "", true},
		{"proc", validSubdir, "virtio_fs", 0, "", true},
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

func TestMountParseMountFlagsAndOptions(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		options []string

		expectedFlags   int
		expectedOptions string
	}

	// Start with some basic tests
	data := []testData{
		{[]string{}, 0, ""},
		{[]string{"moo"}, 0, "moo"},
		{[]string{"moo", "foo"}, 0, "moo,foo"},
		{[]string{"foo", "moo"}, 0, "foo,moo"},
	}

	// Add the expected flag handling tests
	for name, value := range flagList {
		td := testData{
			options:         []string{"foo", name, "bar"},
			expectedFlags:   value,
			expectedOptions: "foo,bar",
		}

		data = append(data, td)
	}

	for i, d := range data {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		flags, options := parseMountFlagsAndOptions(d.options)

		assert.Equal(d.expectedFlags, flags, msg)
		assert.Equal(d.expectedOptions, options, msg)

	}
}

func TestMountParseOptions(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		options []string

		result map[string]string
	}

	data := []testData{
		{[]string{}, map[string]string{}},
		{[]string{" "}, map[string]string{}},
		{[]string{"="}, map[string]string{}},
		{[]string{"moo"}, map[string]string{}},
		{[]string{"foo", "moo"}, map[string]string{}},
		{[]string{"=bar"}, map[string]string{}},
		{[]string{"foo=bar"}, map[string]string{
			"foo": "bar",
		}},
	}

	for i, d := range data {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		result := parseOptions(d.options)

		assert.Equal(d.result, result, msg)
	}
}

func TestCommonStorageHandler(t *testing.T) {
	skipIfRoot(t)

	assert := assert.New(t)

	storage := pb.Storage{}

	mountPoint, err := commonStorageHandler(storage)
	assert.Empty(mountPoint)
	assert.Error(err)

}

func TestStorageHandlers(t *testing.T) {
	skipIfRoot(t)

	assert := assert.New(t)

	for name, handler := range storageHandlerList {
		msg := fmt.Sprintf("test: storage handler: %s", name)

		fmt.Println(msg)

		storage := pb.Storage{
			MountPoint: "/new/mount/point",
		}

		sb := sandbox{
			storages: make(map[string]*sandboxStorage),
		}

		ctx, cancel := context.WithCancel(context.Background())
		mountPoint, err := handler(ctx, storage, &sb)

		assert.Empty(mountPoint, msg)
		assert.Error(err, msg)
		cancel()
	}
}

func TestMountEnsureDestinationExists(t *testing.T) {
	skipIfRoot(t)

	assert := assert.New(t)

	tmpdir, err := ioutil.TempDir("", "")
	assert.NoError(err)

	type testData struct {
		source string
		dest   string
		fsType string

		expectError bool
	}

	existsFile := filepath.Join(tmpdir, "exists-file")
	err = createEmptyFile(existsFile)
	assert.NoError(err)

	existsDir := filepath.Join(tmpdir, "exists-dir")
	err = os.Mkdir(existsDir, os.FileMode(0755))
	assert.NoError(err)

	noExistsDir := filepath.Join(tmpdir, "does-not-exist")

	dir := filepath.Join(tmpdir, "dir")

	// make directory unreadable by non-root user
	err = os.Mkdir(dir, os.FileMode(0000))
	assert.NoError(err)

	existingNonCreatableFile := filepath.Join(tmpdir, "uncreatable")
	err = createEmptyFileWithPerms(existingNonCreatableFile, 0000)
	assert.NoError(err)

	uncreatableDir := filepath.Join(dir, "invalid-dir", "another-invalid-dir")

	data := []testData{
		{"", "", "", true},
		{noExistsDir, "", "", true},
		{"", noExistsDir, "", true},
		{existsDir, uncreatableDir, "", true},
		{existsDir, uncreatableDir, "bind", true},
		{existsFile, uncreatableDir, "moo", true},
		{existsFile, existingNonCreatableFile, "bind", true},
	}

	for i, d := range data {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		err := ensureDestinationExists(d.source, d.dest, d.fsType)

		if d.expectError {
			assert.Error(err, msg)
		} else {
			assert.NoError(err, msg)
		}
	}
}

func TestGetMountFSType(t *testing.T) {
	assert := assert.New(t)

	// Type used to hold function parameters and expected results.
	type testData struct {
		param1         string
		expectedResult string
		expectError    bool
	}

	// List of tests to run including the expected results
	data := []testData{
		// failure scenarios
		{"/thisPathShouldNotBeAMountPoint", "", true},

		// success scenarios
		{"/proc", "proc", false},
		{"/sys", "sysfs", false},
		{"/run", "tmpfs", false},
	}

	// Run the tests
	for i, d := range data {
		// Create a test-specific string that is added to each assert
		// call. It will be displayed if any assert test fails.
		msg := fmt.Sprintf("test[%d]: %+v", i, d)

		// Call the function under test
		result, err := getMountFSType(d.param1)

		if d.expectError {
			assert.Error(err, msg)

			// If an error is expected, there is no point
			// performing additional checks.
			continue
		}

		assert.NoError(err, msg)
		assert.Equal(d.expectedResult, result, msg)
	}
}
