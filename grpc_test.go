//
// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"sync"
)

var testSharedPidNs = "testSharedPidNs"
var testSharedUTSNs = "testSharedUTSNs"
var testSharedIPCNs = "testSharedIPCNs"

func testUpdateContainerConfigNamespacesSharedPid(t *testing.T, sharedPidNs, sharedUTSNs, sharedIPCNs string, config, expected configs.Config) {
	testUpdateContainerConfigNamespaces(t, sharedPidNs, sharedUTSNs, sharedIPCNs, config, expected, true)
}

func testUpdateContainerConfigNamespacesNonSharedPid(t *testing.T, sharedPidNs, sharedUTSNs, sharedIPCNs string, config, expected configs.Config) {
	testUpdateContainerConfigNamespaces(t, sharedPidNs, sharedUTSNs, sharedIPCNs, config, expected, false)
}

func testUpdateContainerConfigNamespaces(t *testing.T, sharedPidNs, sharedUTSNs, sharedIPCNs string, config, expected configs.Config, sharedPid bool) {
	s := &sandbox{
		sharedPidNs: namespace{
			path: sharedPidNs,
		},
		sharedIPCNs: namespace{
			path: sharedIPCNs,
		},
		sharedUTSNs: namespace{
			path: sharedUTSNs,
		},
		containers: make(map[string]*container),
	}

	contID := "testContainer"
	ctr := &container{
		id:              contID,
		useSandboxPidNs: sharedPid,
	}

	s.containers[contID] = ctr

	a := &agentGRPC{
		sandbox: s,
	}

	a.updateContainerConfigNamespaces(&config, ctr)

	assert.True(t, reflect.DeepEqual(config, expected),
		"Config structures should be identical: got %+v, expecting %+v",
		config, expected)

}

func TestUpdateContainerConfigNamespacesNonEmptyConfig(t *testing.T) {
	config := configs.Config{
		Namespaces: []configs.Namespace{
			{
				Type: configs.NEWIPC,
			},
			{
				Type: configs.NEWUTS,
			},
		},
	}

	expectedConfig := configs.Config{
		Namespaces: []configs.Namespace{
			{
				Type: configs.NEWIPC,
				Path: testSharedIPCNs,
			},
			{
				Type: configs.NEWUTS,
				Path: testSharedUTSNs,
			},
			{
				Type: configs.NEWPID,
				Path: testSharedPidNs,
			},
		},
	}

	testUpdateContainerConfigNamespacesSharedPid(t, testSharedPidNs, testSharedUTSNs, testSharedIPCNs, config, expectedConfig)

	expectedConfig = configs.Config{
		Namespaces: []configs.Namespace{
			{
				Type: configs.NEWIPC,
				Path: testSharedIPCNs,
			},
			{
				Type: configs.NEWUTS,
				Path: testSharedUTSNs,
			},
			{
				Type: configs.NEWPID,
				Path: "",
			},
		},
	}

	testUpdateContainerConfigNamespacesNonSharedPid(t, testSharedPidNs, testSharedUTSNs, testSharedIPCNs, config, expectedConfig)
}

func TestUpdateContainerConfigNamespacesEmptyConfig(t *testing.T) {
	expectedConfig := configs.Config{
		Namespaces: []configs.Namespace{
			{
				Type: configs.NEWIPC,
				Path: testSharedIPCNs,
			},
			{
				Type: configs.NEWUTS,
				Path: testSharedUTSNs,
			},
			{
				Type: configs.NEWPID,
				Path: testSharedPidNs,
			},
		},
	}

	testUpdateContainerConfigNamespacesSharedPid(t, testSharedPidNs, testSharedUTSNs, testSharedIPCNs, configs.Config{}, expectedConfig)

	expectedConfig = configs.Config{
		Namespaces: []configs.Namespace{
			{
				Type: configs.NEWIPC,
				Path: testSharedIPCNs,
			},
			{
				Type: configs.NEWUTS,
				Path: testSharedUTSNs,
			},
			{
				Type: configs.NEWPID,
				Path: "",
			},
		},
	}

	testUpdateContainerConfigNamespacesNonSharedPid(t, testSharedPidNs, testSharedUTSNs, testSharedIPCNs, configs.Config{}, expectedConfig)
}

func testUpdateContainerConfigPrivileges(t *testing.T, spec *specs.Spec, config, expected configs.Config) {
	a := &agentGRPC{}

	err := a.updateContainerConfigPrivileges(spec, &config)
	assert.Nil(t, err, "updateContainerConfigPrivileges() failed: %v", err)

	assert.True(t, reflect.DeepEqual(config, expected),
		"Config structures should be identical: got %+v, expecting %+v",
		config, expected)
}

func TestUpdateContainerConfigPrivilegesNilSpec(t *testing.T) {
	testUpdateContainerConfigPrivileges(t, nil, configs.Config{}, configs.Config{})
}

func TestUpdateContainerConfigPrivilegesNilSpecProcess(t *testing.T) {
	testUpdateContainerConfigPrivileges(t, &specs.Spec{}, configs.Config{}, configs.Config{})
}

func TestUpdateContainerConfigPrivilegesNoNewPrivileges(t *testing.T) {
	for _, priv := range []bool{false, true} {
		spec := &specs.Spec{
			Process: &specs.Process{
				NoNewPrivileges: priv,
			},
		}
		config := configs.Config{}
		expectedConfig := configs.Config{
			NoNewPrivileges: priv,
		}

		testUpdateContainerConfigPrivileges(t, spec, config, expectedConfig)
	}
}

func TestOnlineCPUMem(t *testing.T) {
	assert := assert.New(t)
	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	containerID := "1"
	containerID2 := "2"
	container := &container{
		container: &mockContainer{
			id:        containerID,
			processes: []int{1},
		},
	}
	a.sandbox.containers[containerID] = container
	a.sandbox.containers[containerID2] = container

	req := &pb.OnlineCPUMemRequest{
		NbCpus: 1,
		Wait:   true,
	}
	sysfsCPUOnlinePath = "/xyz/123/rgb/abc"
	sysfsMemOnlinePath = "/xyz/123/rgb/abc"

	_, err := a.OnlineCPUMem(context.TODO(), req)
	assert.Error(err, "sysfs paths do not exist")

	sysfsCPUOnlinePath, err = ioutil.TempDir("", "cpu")
	assert.NoError(err)
	defer os.RemoveAll(sysfsCPUOnlinePath)
	sysfsConnectedCPUsPath = filepath.Join(sysfsCPUOnlinePath, "online")

	sysfsMemOnlinePath, err = ioutil.TempDir("", "memory")
	assert.NoError(err)
	defer os.RemoveAll(sysfsMemOnlinePath)

	_, err = a.OnlineCPUMem(context.TODO(), req)
	assert.Error(err, "CPU sysfs is empty")

	cpu0dir := filepath.Join(sysfsCPUOnlinePath, "cpu0")
	err = os.Mkdir(cpu0dir, 0775)
	assert.NoError(err)

	_, err = a.OnlineCPUMem(context.TODO(), req)
	assert.Error(err)

	cpu0Online := filepath.Join(cpu0dir, "online")
	err = ioutil.WriteFile(cpu0Online, []byte("0"), 0755)
	assert.NoError(err)

	memory0dir := filepath.Join(sysfsMemOnlinePath, "memory0")
	err = os.Mkdir(memory0dir, 0775)
	assert.NoError(err)

	memory0Online := filepath.Join(memory0dir, "online")
	err = ioutil.WriteFile(memory0Online, []byte("0"), 0755)
	assert.NoError(err)

	_, err = a.OnlineCPUMem(context.TODO(), req)
	assert.Error(err, "connected cpus path does not exist")
	sysfsConnectedCPUsPath = filepath.Join(sysfsCPUOnlinePath, "online")
	ioutil.WriteFile(sysfsConnectedCPUsPath, []byte("0-4"), 0644)

	_, err = a.OnlineCPUMem(context.TODO(), req)
	assert.Error(err, "docker cgroup path does not exist")

	cgroupCpusetPath, err = ioutil.TempDir("", "cgroup")
	assert.NoError(err)
	cfg := container.container.Config()
	cgroupPath := filepath.Join(cgroupCpusetPath, cfg.Cgroups.Path)
	err = os.MkdirAll(cgroupPath, 0777)
	assert.NoError(err)
	defer os.RemoveAll(cgroupCpusetPath)

	err = ioutil.WriteFile(memory0Online, []byte("0"), 0755)
	assert.NoError(err)
	err = ioutil.WriteFile(cpu0Online, []byte("0"), 0755)
	assert.NoError(err)

	_, err = a.OnlineCPUMem(context.TODO(), req)
	assert.NoError(err)
}

func TestGetPIDIndex(t *testing.T) {
	assert := assert.New(t)

	title := "UID PID PPID C STIME TTY TIME CMD"
	pidIndex := 1
	index := getPIDIndex(title)
	assert.Equal(pidIndex, index)

	title = "PID PPID C STIME TTY TIME CMD"
	pidIndex = 0
	index = getPIDIndex(title)
	assert.Equal(pidIndex, index)

	title = "PPID C STIME TTY TIME CMD PID"
	pidIndex = 6
	index = getPIDIndex(title)
	assert.Equal(pidIndex, index)

	title = "PPID C STIME TTY TIME CMD"
	pidIndex = -1
	index = getPIDIndex(title)
	assert.Equal(pidIndex, index)
}

func TestListProcesses(t *testing.T) {
	containerID := "1"
	assert := assert.New(t)
	req := &pb.ListProcessesRequest{
		ContainerId: containerID,
		Format:      "table",
		Args:        []string{"-ef"},
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
			subreaper:  &mockreaper{},
		},
	}
	// getContainer should fail
	r, err := a.ListProcesses(context.TODO(), req)
	assert.Error(err)
	assert.NotNil(r)

	// should fail, unknown format
	req.Format = "unknown"
	a.sandbox.containers[containerID] = &container{
		container: &mockContainer{
			id:        containerID,
			processes: []int{1},
		},
	}
	r, err = a.ListProcesses(context.TODO(), req)
	assert.Error(err)
	assert.NotNil(r)

	// json format
	req.Format = "json"
	r, err = a.ListProcesses(context.TODO(), req)
	assert.NoError(err)
	assert.NotNil(r)
	assert.NotEmpty(r.ProcessList)

	// table format
	req.Format = "table"
	r, err = a.ListProcesses(context.TODO(), req)
	assert.NoError(err)
	assert.NotNil(r)
	assert.NotEmpty(r.ProcessList)
}

func TestUpdateContainer(t *testing.T) {
	containerID := "1"
	assert := assert.New(t)
	req := &pb.UpdateContainerRequest{
		ContainerId: containerID,
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	// Resources are nil, should fail
	r, err := a.UpdateContainer(context.TODO(), req)
	assert.Error(err)
	assert.Equal(emptyResp, r)

	// getContainer should fail
	req.Resources = &pb.LinuxResources{
		BlockIO: &pb.LinuxBlockIO{},
		Memory:  &pb.LinuxMemory{},
		CPU:     &pb.LinuxCPU{},
		Pids:    &pb.LinuxPids{},
		Network: &pb.LinuxNetwork{},
	}
	r, err = a.UpdateContainer(context.TODO(), req)
	assert.Error(err)
	assert.Equal(emptyResp, r)

	a.sandbox.containers[containerID] = &container{
		container: &mockContainer{
			id:        containerID,
			processes: []int{1},
		},
	}

	r, err = a.UpdateContainer(context.TODO(), req)
	assert.NoError(err)
	assert.Equal(emptyResp, r)
}

func TestStatsContainer(t *testing.T) {
	containerID := "1"
	assert := assert.New(t)
	req := &pb.StatsContainerRequest{
		ContainerId: containerID,
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	//getcontainer should failed
	r, err := a.StatsContainer(context.TODO(), req)
	assert.Error(err)
	assert.Nil(r)

	a.sandbox.containers[containerID] = &container{
		container: &mockContainer{
			id: containerID,
		},
	}

	r, err = a.StatsContainer(context.TODO(), req)
	assert.NoError(err)
	assert.NotNil(r)

}

func TestPauseContainer(t *testing.T) {
	containerID := "1"
	assert := assert.New(t)
	req := &pb.PauseContainerRequest{
		ContainerId: containerID,
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	r, err := a.PauseContainer(context.TODO(), req)
	assert.Error(err)
	assert.Equal(r, emptyResp)

	a.sandbox.containers[containerID] = &container{
		container: &mockContainer{
			id:        containerID,
			processes: []int{1},
		},
	}
	r, err = a.PauseContainer(context.TODO(), req)
	assert.NoError(err)
	assert.Equal(r, emptyResp)
}

func TestResumeContainer(t *testing.T) {
	containerID := "1"
	assert := assert.New(t)
	req := &pb.ResumeContainerRequest{
		ContainerId: containerID,
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	r, err := a.ResumeContainer(context.TODO(), req)
	assert.Error(err)
	assert.Equal(r, emptyResp)

	a.sandbox.containers[containerID] = &container{
		container: &mockContainer{
			id:        containerID,
			processes: []int{1},
		},
	}
	r, err = a.ResumeContainer(context.TODO(), req)
	assert.NoError(err)
	assert.Equal(r, emptyResp)
}

func TestHandleError(t *testing.T) {
	assert := assert.New(t)

	err := errors.New("")
	e := handleError(true, err)
	assert.Error(e)

	e = handleError(true, nil)
	assert.NoError(e)

	e = handleError(false, err)
	assert.Error(e)

	e = handleError(false, nil)
	assert.NoError(e)
}

func TestUpdateContainerCpuset(t *testing.T) {
	var err error
	assert := assert.New(t)

	cgroupCpusetPath, err = ioutil.TempDir("", "cgroup")
	assert.NoError(err)
	defer os.Remove(cgroupCpusetPath)

	cgroupPath := "kata"
	err = os.MkdirAll(filepath.Join(cgroupCpusetPath, cgroupPath), 0777)
	assert.NoError(err)

	cookies := make(cookie)
	cgroupPath += "///"

	err = updateContainerCpuset(cgroupPath, "0-7", cookies)
	assert.NoError(err)

	// run again to ensure cookies are used
	err = updateContainerCpuset(cgroupPath, "0-7", cookies)
	assert.NoError(err)
}

func TestReseedRandomDev(t *testing.T) {
	assert := assert.New(t)
	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	req := &pb.ReseedRandomDevRequest{
		Data: []byte{'f'},
	}

	r, err := a.ReseedRandomDev(context.TODO(), req)
	assert.NoError(err)
	assert.Equal(r, emptyResp)
}

func TestSingleWaitProcess(t *testing.T) {
	containerID := "1"
	exitCode := 9
	assert := assert.New(t)
	req := &pb.WaitProcessRequest{
		ContainerId: containerID,
		ExecId:      containerID,
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
			running:    true,
			subreaper:  &agentReaper{},
		},
	}

	a.sandbox.containers[containerID] = &container{
		id:        containerID,
		processes: make(map[string]*process),
	}

	a.sandbox.containers[containerID].processes[containerID] = &process{
		id:         containerID,
		process:    libcontainer.Process{},
		exitCodeCh: make(chan int, 1),
	}

	go func() {
		time.Sleep(time.Second)
		a.sandbox.containers[containerID].processes[containerID].exitCodeCh <- exitCode
	}()

	resp, _ := a.WaitProcess(context.TODO(), req)
	assert.Equal(resp.Status, int32(exitCode))
}

func TestMultiWaitProcess(t *testing.T) {
	containerID := "1"
	exitCode := 9
	wg := sync.WaitGroup{}

	assert := assert.New(t)
	req := &pb.WaitProcessRequest{
		ContainerId: containerID,
		ExecId:      containerID,
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
			running:    true,
			subreaper:  &agentReaper{},
		},
	}

	a.sandbox.containers[containerID] = &container{
		id:        containerID,
		processes: make(map[string]*process),
	}

	a.sandbox.containers[containerID].processes[containerID] = &process{
		id:         containerID,
		process:    libcontainer.Process{},
		exitCodeCh: make(chan int, 1),
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			resp, _ := a.WaitProcess(context.TODO(), req)
			assert.Equal(resp.Status, int32(exitCode))
			wg.Done()
		}()
	}

	go func() {
		time.Sleep(time.Second)
		a.sandbox.containers[containerID].processes[containerID].exitCodeCh <- exitCode
	}()

	wg.Wait()
}
