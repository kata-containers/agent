//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/opencontainers/runc/libcontainer"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

const (
	testExecID      = "testExecID"
	testContainerID = "testContainerID"
)

func skipUnlessRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test disabled as requires root user")
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

func TestRemoveSandboxStorage(t *testing.T) {
	s := &sandbox{
		containers: make(map[string]*container),
	}

	s.storages = make(map[string]*sandboxStorage)
	err := s.removeSandboxStorage("/tmp/testEphePath/")

	assert.Error(t, err, "Should fail because sandbox storage doesn't exist")
}
func TestUnsetAndRemoveSandboxStorage(t *testing.T) {
	s := &sandbox{
		containers: make(map[string]*container),
	}

	s.storages = make(map[string]*sandboxStorage)
	err := s.unsetAndRemoveSandboxStorage("/tmp/testEphePath/")

	assert.Error(t, err, "Should fail because sandbox storage doesn't exist")
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

	s.setContainer(testContainerID, c)

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
		running:    true,
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

func TestGrpcTracer(t *testing.T) {
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return &pb.HealthCheckResponse{}, nil
	}
	_, err := grpcTracer(context.Background(), &pb.CheckRequest{}, &grpc.UnaryServerInfo{}, handler)
	assert.Nil(t, err, "failed to trace grpc request: %v", err)
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
