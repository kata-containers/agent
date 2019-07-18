//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/specconv"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

const (
	testExecID      = "testExecID"
	testContainerID = "testContainerID"
	testFileMode    = os.FileMode(0640)
	testDirMode     = os.FileMode(0750)
)

func createFileWithPerms(file, contents string, perms os.FileMode) error {
	return ioutil.WriteFile(file, []byte(contents), perms)
}

func createFile(file, contents string) error {
	return createFileWithPerms(file, contents, testFileMode)
}

func createEmptyFile(file string) error {
	return createFile(file, "")
}

func createEmptyFileWithPerms(file string, perms os.FileMode) error {
	return createFileWithPerms(file, "", perms)
}

func skipUnlessRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test disabled as requires root user")
	}
}

func skipIfRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Test disabled as requires non-root user")
	}
}

func TestClosePostStartFDsAllNil(t *testing.T) {
	p := &process{}

	p.closePostStartFDs()
}

func TestClosePostStartFDsAllInitialized(t *testing.T) {
	rStdin, wStdin, err := os.Pipe()
	assert.Nil(t, err, "%v", err)
	defer wStdin.Close()

	rStdout, wStdout, err := os.Pipe()
	assert.Nil(t, err, "%v", err)
	defer rStdout.Close()

	rStderr, wStderr, err := os.Pipe()
	assert.Nil(t, err, "%v", err)
	defer rStderr.Close()

	rConsoleSocket, wConsoleSocket, err := os.Pipe()
	assert.Nil(t, err, "%v", err)
	defer wConsoleSocket.Close()

	rConsoleSock, wConsoleSock, err := os.Pipe()
	assert.Nil(t, err, "%v", err)
	defer wConsoleSock.Close()

	p := &process{
		process: libcontainer.Process{
			Stdin:         rStdin,
			Stdout:        wStdout,
			Stderr:        wStderr,
			ConsoleSocket: rConsoleSocket,
		},
		consoleSock: rConsoleSock,
	}

	p.closePostStartFDs()
}

func TestClosePostExitFDsAllNil(t *testing.T) {
	p := &process{}

	p.closePostExitFDs()
}

func TestClosePostExitFDsAllInitialized(t *testing.T) {
	rTermMaster, wTermMaster, err := os.Pipe()
	assert.Nil(t, err, "%v", err)
	defer wTermMaster.Close()

	rStdin, wStdin, err := os.Pipe()
	assert.Nil(t, err, "%v", err)
	defer rStdin.Close()

	rStdout, wStdout, err := os.Pipe()
	assert.Nil(t, err, "%v", err)
	defer wStdout.Close()

	rStderr, wStderr, err := os.Pipe()
	assert.Nil(t, err, "%v", err)
	defer wStderr.Close()

	p := &process{
		termMaster: rTermMaster,
		stdin:      wStdin,
		stdout:     rStdout,
		stderr:     rStderr,
	}

	p.closePostExitFDs()
}

func TestSetProcess(t *testing.T) {
	c := &container{
		processes: make(map[string]*process),
	}

	p := &process{
		id: testExecID,
	}

	c.setProcess(p)

	proc, exist := c.processes[testExecID]
	assert.True(t, exist, "Process entry should exist")

	assert.True(t, reflect.DeepEqual(p, proc),
		"Process structures should be identical: got %+v, expecting %+v",
		proc, p)
}

func TestDeleteProcess(t *testing.T) {
	c := &container{
		processes: make(map[string]*process),
	}

	p := &process{
		id: testExecID,
	}

	c.processes[testExecID] = p

	c.deleteProcess(testExecID)

	_, exist := c.processes[testExecID]
	assert.False(t, exist, "Process entry should not exist")
}

func TestGetProcessEntryExist(t *testing.T) {
	c := &container{
		processes: make(map[string]*process),
	}

	p := &process{
		id: testExecID,
	}

	c.processes[testExecID] = p

	proc, err := c.getProcess(testExecID)
	assert.Nil(t, err, "%v", err)

	assert.True(t, reflect.DeepEqual(p, proc),
		"Process structures should be identical: got %+v, expecting %+v",
		proc, p)
}

func TestGetProcessNoEntry(t *testing.T) {
	c := &container{
		processes: make(map[string]*process),
	}

	_, err := c.getProcess(testExecID)
	assert.Error(t, err, "Should fail because no entry has been created")
}

func TestSetSandboxStorage(t *testing.T) {
	s := &sandbox{
		containers: make(map[string]*container),
	}

	s.storages = make(map[string]*sandboxStorage)

	storagePath := "/tmp/testEphe/"

	// Add a new sandbox storage
	newStorage := s.setSandboxStorage(storagePath)

	// Check the reference counter
	refCount := s.storages[storagePath].refCount
	assert.Equal(t, 1, refCount, "Invalid refcount, got %d expected 1", refCount)
	assert.True(t, newStorage, "expected value was true")

	// Use the existing sandbox storage
	newStorage = s.setSandboxStorage(storagePath)

	assert.False(t, newStorage, "expected value was false")

	// Since we are using existing storage, the reference counter
	// should read 2 by now
	refCount = s.storages[storagePath].refCount
	assert.Equal(t, 2, refCount, "Invalid refcount, got %d expected 2", refCount)
}

func bindMount(src, dest string) error {
	return mount(src, dest, "bind", syscall.MS_BIND, "")
}

func TestRemoveSandboxStorage(t *testing.T) {
	skipUnlessRoot(t)

	s := &sandbox{
		containers: make(map[string]*container),
	}

	tmpDir, err := ioutil.TempDir("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	src, err := ioutil.TempDir(tmpDir, "src")
	assert.NoError(t, err)

	dest, err := ioutil.TempDir(tmpDir, "dest")
	assert.NoError(t, err)

	emptyDir, err := ioutil.TempDir(tmpDir, "empty")
	assert.NoError(t, err)

	err = s.removeSandboxStorage(emptyDir)
	assert.Error(t, err, "expect failure as directory is not a mountpoint")

	err = s.removeSandboxStorage("")
	assert.Error(t, err)

	invalidDir := filepath.Join(emptyDir, "invalid")

	err = s.removeSandboxStorage(invalidDir)
	assert.Error(t, err)

	// Now, create a double mount as this guarantees the directory cannot
	// be deleted after the first unmount
	for range []int{0, 1} {
		err = bindMount(src, dest)
		assert.NoError(t, err)
	}

	err = s.removeSandboxStorage(dest)
	assert.Error(t, err, "expect fail as deletion cannot happen due to the second mount")

	// This time it should work as the previous two calls have undone the double mount.
	err = s.removeSandboxStorage(dest)
	assert.NoError(t, err)

	s.storages = make(map[string]*sandboxStorage)
	err = s.removeSandboxStorage("/tmp/testEphePath/")

	assert.Error(t, err, "Should fail because sandbox storage doesn't exist")
}

func TestUnsetAndRemoveSandboxStorage(t *testing.T) {
	skipUnlessRoot(t)

	s := &sandbox{
		containers: make(map[string]*container),
		storages:   make(map[string]*sandboxStorage),
	}

	path := "/tmp/testEphePath"
	err := s.unsetAndRemoveSandboxStorage(path)

	assert.Error(t, err, "Should fail because sandbox storage doesn't exist")

	tmpDir, err := ioutil.TempDir("", "")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	src, err := ioutil.TempDir(tmpDir, "src")
	assert.NoError(t, err)

	dest, err := ioutil.TempDir(tmpDir, "dest")
	assert.NoError(t, err)

	err = bindMount(src, dest)
	assert.NoError(t, err)

	newPath := s.setSandboxStorage(dest)
	assert.True(t, newPath)

	err = s.unsetAndRemoveSandboxStorage(dest)
	assert.NoError(t, err)

	// Create another directory
	dir, err := ioutil.TempDir(tmpDir, "dir")
	assert.NoError(t, err)

	// Register it
	newPath = s.setSandboxStorage(dir)
	assert.True(t, newPath)

	// Now, delete the directory to ensure the following call fails
	err = os.RemoveAll(dir)
	assert.NoError(t, err)

	err = s.unsetAndRemoveSandboxStorage(dir)
	assert.Error(t, err, "should fail as path has been deleted")
}

func TestUnSetSandboxStorage(t *testing.T) {
	s := &sandbox{
		containers: make(map[string]*container),
	}

	s.storages = make(map[string]*sandboxStorage)

	storagePath := "/tmp/testEphe/"

	// Add a new sandbox storage
	s.setSandboxStorage(storagePath)
	// Use the existing sandbox storage
	s.setSandboxStorage(storagePath)

	removeSandboxStorage, _ := s.unSetSandboxStorage(storagePath)
	assert.False(t, removeSandboxStorage, "Expected value was false")

	// Reference counter should decrement to 1
	refCount := s.storages[storagePath].refCount
	assert.Equal(t, 1, refCount, "Invalid refcount, got %d expected 1", refCount)

	removeSandboxStorage, _ = s.unSetSandboxStorage(storagePath)
	assert.True(t, removeSandboxStorage, "Expected value was true")

	// Since no container is using this sandbox storage anymore
	// there should not be any reference in sandbox struct
	// for the given storage
	_, ok := s.storages[storagePath]
	assert.False(t, ok, "expected value was false")

	// If no container is using the sandbox storage, the reference
	// counter for it should not exist
	_, err := s.unSetSandboxStorage(storagePath)
	assert.Error(t, err, "Should fail because sandbox storage doesn't exist")

	_, err = s.unSetSandboxStorage("/tmp/nosbs/")
	assert.Error(t, err, "Should fail because sandbox storage doesn't exist")
}

func TestGetContainerEntryExist(t *testing.T) {
	s := &sandbox{
		containers: make(map[string]*container),
	}

	c := &container{
		id: testContainerID,
	}

	s.containers[testContainerID] = c

	cont, err := s.getContainer(testContainerID)
	assert.Nil(t, err, "%v", err)

	assert.True(t, reflect.DeepEqual(c, cont),
		"Container structures should be identical: got %+v, expecting %+v",
		cont, c)
}

func TestGetContainerNoEntry(t *testing.T) {
	s := &sandbox{
		containers: make(map[string]*container),
	}

	_, err := s.getContainer(testContainerID)
	assert.Error(t, err, "Should fail because no entry has been created")
}

func TestSetContainer(t *testing.T) {
	s := &sandbox{
		containers: make(map[string]*container),
	}

	c := &container{
		id: testContainerID,
	}

	s.setContainer(context.Background(), testContainerID, c)

	cont, exist := s.containers[testContainerID]
	assert.True(t, exist, "Container entry should exist")

	assert.True(t, reflect.DeepEqual(c, cont),
		"Container structures should be identical: got %+v, expecting %+v",
		cont, c)
}

func TestDeleteContainer(t *testing.T) {
	s := &sandbox{
		containers: make(map[string]*container),
	}

	c := &container{
		id: testContainerID,
	}

	s.containers[testContainerID] = c

	s.deleteContainer(testContainerID)

	_, exist := s.containers[testContainerID]
	assert.False(t, exist, "Process entry should not exist")
}

func TestGetProcessFromSandbox(t *testing.T) {
	s := &sandbox{
		running:    false,
		containers: make(map[string]*container),
	}

	c := &container{
		id:        testContainerID,
		processes: make(map[string]*process),
	}

	p := &process{
		id: testExecID,
	}

	c.processes[testExecID] = p
	s.containers[testContainerID] = c

	_, _, err := s.getProcess(testContainerID, testExecID)
	assert.Error(t, err, "sandbox not running")

	s.running = true

	_, _, err = s.getProcess("invalidCID", testExecID)
	assert.Error(t, err, "invalid container ID")

	_, _, err = s.getProcess(testContainerID, "invalidExecID")
	assert.Error(t, err, "invalid exec ID")

	proc, _, err := s.getProcess(testContainerID, testExecID)
	assert.Nil(t, err, "%v", err)

	assert.True(t, reflect.DeepEqual(p, proc),
		"Process structures should be identical: got %+v, expecting %+v",
		proc, p)
}

func TestStartStopGRPCServer(t *testing.T) {
	_, out, err := os.Pipe()
	assert.Nil(t, err, "%v", err)

	s := &sandbox{
		containers: make(map[string]*container),
		channel:    &serialChannel{serialConn: out},
	}

	s.startGRPC()
	assert.NotNil(t, s.server, "failed starting grpc server")

	s.stopGRPC()
	assert.Nil(t, s.server, "failed stopping grpc server")
}

func TestSettingGrpcTracer(t *testing.T) {
	_, out, err := os.Pipe()
	assert.Nil(t, err, "%v", err)

	s := &sandbox{
		containers:      make(map[string]*container),
		channel:         &serialChannel{serialConn: out},
		enableGrpcTrace: true,
	}

	s.startGRPC()
	assert.NotNil(t, s.server, "failed starting grpc server")

	s.stopGRPC()
	assert.Nil(t, s.server, "failed stopping grpc server")
}

func TestMountToRootfs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mount need cap_sys_admin")
	}

	cgprocDir, err := ioutil.TempDir("", "proc-cgroup")
	assert.Nil(t, err, "%v", err)
	defer os.RemoveAll(cgprocDir)

	mounts := []initMount{
		{"proc", "proc", filepath.Join(cgprocDir, "proc"), []string{"nosuid", "nodev", "noexec"}},
		{"sysfs", "sysfs", filepath.Join(cgprocDir, "sysfs"), []string{"nosuid", "nodev", "noexec"}},
		{"devtmpfs", "dev", filepath.Join(cgprocDir, "dev"), []string{"nosuid"}},
		{"tmpfs", "tmpfs", filepath.Join(cgprocDir, "tmpfs"), []string{"nosuid", "nodev"}},
		{"devpts", "devpts", filepath.Join(cgprocDir, "devpts"), []string{"nosuid", "noexec"}},
	}

	for _, m := range mounts {
		err = mountToRootfs(m)
		assert.Nil(t, err, "%v", err)
	}

	for _, m := range mounts {
		err = syscall.Unmount(m.dest, 0)
		assert.Nil(t, err, "%v", err)
	}
}

func TestMountToRootfsFailed(t *testing.T) {
	assert := assert.New(t)

	if os.Geteuid() == 0 {
		t.Skip("need non-root")
	}

	tmpDir, err := ioutil.TempDir("", "")
	assert.NoError(err)
	defer os.RemoveAll(tmpDir)

	existingDir := filepath.Join(tmpDir, "exists")
	err = os.Mkdir(existingDir, 0750)
	assert.NoError(err)

	dir := filepath.Join(tmpDir, "dir")

	mounts := []initMount{
		{"", "", "", []string{}},
		{"", "", existingDir, []string{}},
		{"", "", dir, []string{}},
	}

	for i, m := range mounts {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, m)

		err := mountToRootfs(m)
		assert.Error(err, msg)
	}

}

func TestGetCgroupMountsFailed(t *testing.T) {
	cgprocDir, err := ioutil.TempDir("", "proc-cgroup")
	assert.Nil(t, err, "%v", err)
	defer os.RemoveAll(cgprocDir)

	_, err = getCgroupMounts(filepath.Join(cgprocDir, "cgroups"))
	assert.NotNil(t, err, "proc/cgroups is not exist: but got nil")
}

func TestGetCgroupMountsSuccessful(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mount need cap_sys_admin")
	}

	cgprocDir, err := ioutil.TempDir("", "proc-cgroup")
	assert.Nil(t, err, "%v", err)
	defer os.RemoveAll(cgprocDir)

	testMounts := initMount{"proc", "proc", cgprocDir, []string{"nosuid", "nodev", "noexec"}}
	err = mountToRootfs(testMounts)
	assert.Nil(t, err, "%v", err)
	defer os.RemoveAll(cgprocDir)

	_, err = getCgroupMounts(filepath.Join(cgprocDir, "cgroups"))
	assert.Nil(t, err, "%v", err)

	err = syscall.Unmount(cgprocDir, 0)
	assert.Nil(t, err, "%v", err)
}

func TestAddGuestHooks(t *testing.T) {
	assert := assert.New(t)

	hookPath, err := ioutil.TempDir("", "hooks")
	assert.NoError(err)
	defer os.RemoveAll(hookPath)

	poststopPath := path.Join(hookPath, "poststop")
	err = os.Mkdir(poststopPath, 0750)
	assert.NoError(err)

	dirPath := path.Join(poststopPath, "directory")
	err = os.Mkdir(dirPath, 0750)
	assert.NoError(err)

	normalPath := path.Join(poststopPath, "normalfile")
	f, err := os.OpenFile(normalPath, os.O_RDONLY|os.O_CREATE, 0640)
	assert.NoError(err)
	f.Close()

	symlinkPath := path.Join(poststopPath, "symlink")
	err = os.Link(normalPath, symlinkPath)
	assert.NoError(err)

	s := &sandbox{
		guestHooks:        &specs.Hooks{},
		guestHooksPresent: false,
	}

	s.scanGuestHooks(hookPath)
	assert.False(s.guestHooksPresent)

	// No test to perform but this does check the function doesn't panic.
	s.addGuestHooks(nil)

	spec := &specs.Spec{}
	s.addGuestHooks(spec)
	assert.True(len(spec.Hooks.Poststop) == 0)

	execPath := path.Join(poststopPath, "executable")
	f, err = os.OpenFile(execPath, os.O_RDONLY|os.O_CREATE, 0750)
	assert.NoError(err)
	f.Close()

	s.scanGuestHooks(hookPath)
	assert.True(s.guestHooksPresent)

	s.addGuestHooks(spec)
	assert.True(len(spec.Hooks.Poststop) == 1)
	assert.True(strings.Contains(spec.Hooks.Poststop[0].Path, "executable"))
}

type myPostStopHook struct {
}

const hookErrorMsg = "hook always fails"

func (h *myPostStopHook) Run(_ *specs.State) error {
	return errors.New(hookErrorMsg)
}

func TestContainerRemoveContainer(t *testing.T) {
	skipUnlessRoot(t)

	assert := assert.New(t)

	cid := "foo"

	dir, err := ioutil.TempDir("", "")
	assert.NoError(err)
	defer os.RemoveAll(dir)

	containerPath := filepath.Join(dir, "container")

	invalidMountDir := filepath.Join(dir, "bad-mount-dir")

	containerFactory, err := libcontainer.New(containerPath)
	assert.NoError(err)

	spec := &specs.Spec{
		Root: &specs.Root{
			Path:     containerPath,
			Readonly: false,
		},
	}

	hooks := &configs.Hooks{
		Poststop: []configs.Hook{
			&myPostStopHook{},
		},
	}

	mounts := []string{invalidMountDir}

	type testData struct {
		withBadMount bool
		withBadHook  bool
		expectError  bool
	}

	data := []testData{
		{false, false, false},
		{true, false, true},
		{false, true, true},
		{true, true, true},
	}

	for i, d := range data {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		config, err := specconv.CreateLibcontainerConfig(&specconv.CreateOpts{
			CgroupName:   cid,
			NoNewKeyring: true,
			Spec:         spec,
			NoPivotRoot:  true,
		})
		assert.NoError(err, msg)

		if d.withBadHook {
			config.Hooks = hooks
		}

		libContainerContainer, err := containerFactory.Create(cid, config)
		assert.NoError(err, msg)

		c := container{
			ctx:       context.Background(),
			id:        cid,
			processes: make(map[string]*process),
			container: libContainerContainer,
		}

		if d.withBadMount {
			c.mounts = mounts
		}

		err = c.removeContainer()
		if d.expectError {
			assert.Error(err, msg)

			if d.withBadHook {
				assert.Equal(err.Error(), hookErrorMsg, msg)
			}

			continue
		}

		assert.NoError(err, msg)
	}
}

func TestGetGRPCContext(t *testing.T) {
	assert := assert.New(t)

	grpcContext = nil
	ctx := getGRPCContext()
	assert.NotNil(ctx)

	grpcContext = context.Background()
	ctx = getGRPCContext()
	assert.NotNil(ctx)
	assert.Equal(ctx, grpcContext)
}

func TestGetMemory(t *testing.T) {
	assert := assert.New(t)

	dir, err := ioutil.TempDir("", "")
	assert.NoError(err)
	defer os.RemoveAll(dir)

	file := filepath.Join(dir, "meminfo")

	savedMeminfo := meminfo
	defer func() {
		meminfo = savedMeminfo
	}()

	// Override the file
	meminfo = file

	type testData struct {
		contents       string
		expectedResult string
		createFile     bool
		expectError    bool
	}

	memKB := 13
	memKBStr := fmt.Sprintf("%d", memKB)

	entry := fmt.Sprintf("MemTotal:      %d\n", memKB)
	tooManyFieldsEntry := fmt.Sprintf("MemTotal: foo:     %d\n", memKB)
	noNumericEntry := fmt.Sprintf("MemTotal: \n")

	data := []testData{
		{
			"",
			"",
			false,
			true,
		},
		{
			"",
			"",
			true,
			true,
		},
		{
			"hello",
			"",
			true,
			true,
		},
		{
			"hello:",
			"",
			true,
			true,
		},
		{
			"hello: world",
			"",
			true,
			true,
		},
		{
			"hello: world:",
			"",
			true,
			true,
		},
		{
			"MemTotal:      ",
			"",
			true,
			true,
		},
		{
			"MemTotal:",
			"",
			true,
			true,
		},
		{
			tooManyFieldsEntry,
			"",
			true,
			true,
		},
		{
			noNumericEntry,
			"",
			true,
			true,
		},
		{
			entry,
			memKBStr,
			true,
			false,
		},
	}

	for i, d := range data {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		if d.createFile {
			err := createFile(file, d.contents)
			assert.NoError(err, msg)
			defer os.Remove(file)
		} else {
			// Ensure it does not exist
			os.Remove(file)
		}

		mem, err := getMemory()
		if d.expectError {
			assert.Error(err, msg)
			continue
		}

		assert.NoError(err, msg)

		assert.Equal(d.expectedResult, mem, msg)
	}
}

func TestSetupDebugConsole(t *testing.T) {
	assert := assert.New(t)

	dir, err := ioutil.TempDir("", "")
	assert.NoError(err)
	defer os.RemoveAll(dir)

	sh := filepath.Join(dir, "sh")
	console := filepath.Join(dir, "console")

	savedDebugConsole := debugConsole
	savedSupportedShells := supportedShells

	defer func() {
		debugConsole = savedDebugConsole
		supportedShells = savedSupportedShells
	}()

	type testData struct {
		consolePath   string
		shells        []string
		debugConsole  bool
		createConsole bool
		createShells  bool
		expectError   bool
	}

	data := []testData{
		{"", []string{}, false, false, false, false},
		{"", []string{}, true, false, false, true},
		{"", []string{sh}, true, false, false, true},
		{"", []string{sh}, true, false, true, true},
		{console, []string{sh}, true, false, true, true},
		{console, []string{}, true, true, false, true},

		{console, []string{sh}, true, true, true, false},
	}

	for i, d := range data {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		// override
		debugConsole = d.debugConsole
		supportedShells = d.shells

		if d.createConsole {
			err = createEmptyFile(d.consolePath)
			assert.NoError(err, msg)
		} else {
			os.Remove(d.consolePath)
		}

		for _, shell := range d.shells {
			if d.createShells {
				err = createEmptyFile(shell)
				assert.NoError(err, msg)
			} else {
				os.Remove(shell)
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err := setupDebugConsole(ctx, d.consolePath)

		if d.expectError {
			assert.Error(err, msg)
			continue
		}

		assert.NoError(err, msg)
	}
}
