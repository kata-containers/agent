//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/opencontainers/runc/libcontainer"
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

	c.deleteProcess(p)

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
