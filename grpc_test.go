//
// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"syscall"
	"testing"
	"time"

	"sync"

	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
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

	oldOnlineCPUMaxTries := onlineCPUMaxTries
	onlineCPUMaxTries = 10
	defer func() {
		onlineCPUMaxTries = oldOnlineCPUMaxTries
	}()

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

	req.NbCpus = 0
	req.CpuOnly = true
	_, err = a.OnlineCPUMem(context.TODO(), req)
	assert.Error(err)
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

func TestIsNetworkSysctl(t *testing.T) {
	assert := assert.New(t)

	sysctl := "net.core.somaxconn"
	isNet := isNetworkSysctl(sysctl)
	assert.True(isNet)

	sysctl = "kernel.shmmax"
	isNet = isNetworkSysctl(sysctl)
	assert.False(isNet)
}

func TestWriteSystemProperty(t *testing.T) {
	assert := assert.New(t)

	tmpDir, err := ioutil.TempDir("", "procsys")
	assert.Nil(err)
	defer os.RemoveAll(tmpDir)

	key := "net.core.somaxconn"
	value := "1024"
	procSysDir = filepath.Join(tmpDir, "proc", "sys")
	err = os.MkdirAll(procSysDir, 0755)
	assert.Nil(err)

	netCoreDir := filepath.Join(procSysDir, "net", "core")
	err = os.MkdirAll(netCoreDir, 0755)
	assert.Nil(err)

	sysFile := filepath.Join(netCoreDir, "somaxconn")
	fd, err := os.Create(sysFile)
	assert.Nil(err)
	fd.Close()

	err = writeSystemProperty(key, value)
	assert.Nil(err)

	// Read file and verify
	content, err := ioutil.ReadFile(sysFile)
	assert.Nil(err)
	assert.Equal(value, string(content))

	// Following checks require root privileges to remove a read-only dir
	if os.Geteuid() != 0 {
		return
	}

	// Remove write permissions for procSysDir to what they normally are
	// for /proc/sys so that files cannot be created
	err = os.Chmod(procSysDir, 0555)
	assert.Nil(err)

	// Nonexistent sys file
	key = "net.ipv4.ip_forward"
	value = "1"
	err = writeSystemProperty(key, value)
	assert.NotNil(err)
}

func TestApplyNetworkSysctls(t *testing.T) {
	assert := assert.New(t)
	a := &agentGRPC{}

	spec := &specs.Spec{}
	spec.Linux = &specs.Linux{}

	spec.Linux.Sysctl = make(map[string]string)
	spec.Linux.Sysctl["kernel.shmmax"] = "512"

	err := a.applyNetworkSysctls(spec)
	assert.Nil(err)
	assert.Equal(len(spec.Linux.Sysctl), 1)
	assert.Equal(spec.Linux.Sysctl["kernel.shmmax"], "512")

	// Check with network sysctl
	spec.Linux.Sysctl["net.core.somaxconn"] = "1024"
	tmpDir, err := ioutil.TempDir("", "procsys")
	assert.Nil(err)
	defer os.RemoveAll(tmpDir)

	procSysDir = filepath.Join(tmpDir, "proc", "sys")
	netCoreDir := filepath.Join(procSysDir, "net", "core")
	err = os.MkdirAll(netCoreDir, 0755)
	assert.Nil(err)

	assert.Equal(len(spec.Linux.Sysctl), 2)
	err = a.applyNetworkSysctls(spec)
	assert.Nil(err)
	assert.Equal(len(spec.Linux.Sysctl), 1)
	assert.Equal(spec.Linux.Sysctl["kernel.shmmax"], "512")
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

	network := &libcontainer.NetworkInterface{}
	interfaces := make([]*libcontainer.NetworkInterface, 0)
	interfaces = append(interfaces, network)

	a.sandbox.containers[containerID] = &container{
		container: &mockContainer{
			id: containerID,
			stats: libcontainer.Stats{
				CgroupStats: &cgroups.Stats{},
				Interfaces:  interfaces,
			},
		},
	}

	r, err = a.StatsContainer(context.TODO(), req)
	assert.NoError(err)
	assert.NotNil(r)

	assert.NotNil(r.CgroupStats)
	assert.NotNil(r.NetworkStats)
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

	savedFunc := getCpusetGuest

	getCpusetGuest = func() (string, error) {
		return "", errors.New("an error")
	}

	err = updateCpusetPath(cgroupPath, "", cookies)
	assert.Error(err)

	getCpusetGuest = savedFunc

	err = updateCpusetPath(cgroupPath, "0-7", cookies)
	assert.NoError(err)

	// run again to ensure cookies are used
	err = updateCpusetPath(cgroupPath, "0-7", cookies)
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

	_, err := a.WaitProcess(context.TODO(), req)

	// No sandbox processes
	assert.Error(err)

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

func testAgentDetails(assert *assert.Assertions, details *pb.AgentDetails, haveSeccomp bool) {
	assert.NotNil(details)

	assert.Equal(details.Version, version)
	assert.Equal(details.InitDaemon, os.Getpid() == 1)

	var devices []string
	var storages []string

	for handler := range deviceHandlerList {
		devices = append(devices, handler)
	}

	for handler := range storageHandlerList {
		storages = append(storages, handler)
	}

	sort.Strings(details.DeviceHandlers)
	sort.Strings(details.StorageHandlers)

	sort.Strings(devices)
	sort.Strings(storages)

	assert.Equal(details.DeviceHandlers, devices)
	assert.Equal(details.StorageHandlers, storages)

	assert.Equal(details.SupportsSeccomp, haveSeccomp)
}

func TestGetGuestDetails(t *testing.T) {
	assert := assert.New(t)
	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	req := &pb.GuestDetailsRequest{
		MemBlockSize:    true,
		MemHotplugProbe: true,
	}

	// sysfsMemoryBlockSizePath exist with error format
	file, err := ioutil.TempFile("", "test")
	assert.NoError(err)

	oldsysfsMemoryBlockSizePath := sysfsMemoryBlockSizePath
	defer func() {
		sysfsMemoryBlockSizePath = oldsysfsMemoryBlockSizePath
	}()

	sysfsMemoryBlockSizePath = file.Name()
	// empty
	_, err = a.GetGuestDetails(context.TODO(), req)
	assert.Error(err)
	// random string
	err = ioutil.WriteFile(sysfsMemoryBlockSizePath, []byte(sysfsMemoryBlockSizePath), 0666)
	assert.NoError(err)
	_, err = a.GetGuestDetails(context.TODO(), req)
	assert.Error(err)

	// sysfsMemoryBlockSizePath exist with correct format
	err = ioutil.WriteFile(sysfsMemoryBlockSizePath, []byte("123"), 0666)
	assert.NoError(err)
	resp, err := a.GetGuestDetails(context.TODO(), req)
	assert.NoError(err)
	data, err := ioutil.ReadFile(sysfsMemoryBlockSizePath)
	assert.NoError(err)
	size, err := strconv.ParseUint(string(data[:len(data)-1]), 16, 64)
	assert.NoError(err)
	assert.Equal(resp.MemBlockSizeBytes, size)

	seccompSupport := a.haveSeccomp()
	testAgentDetails(assert, resp.AgentDetails, seccompSupport)

	// sysfsMemoryBlockSizePath not exist
	os.Remove(sysfsMemoryBlockSizePath)
	resp, err = a.GetGuestDetails(context.TODO(), req)
	assert.NoError(err)
	assert.Equal(resp.MemBlockSizeBytes, uint64(0))

	// sysfsMemoryHotplugProbePath exist
	probeFile, err := ioutil.TempFile("", "probe")
	assert.NoError(err)

	oldSysfsMemoryHotplugProbePath := sysfsMemoryHotplugProbePath
	defer func() {
		sysfsMemoryHotplugProbePath = oldSysfsMemoryHotplugProbePath
	}()

	sysfsMemoryHotplugProbePath = probeFile.Name()
	resp, err = a.GetGuestDetails(context.TODO(), req)
	assert.NoError(err)
	assert.Equal(resp.SupportMemHotplugProbe, true)

	// sysfsMemoryHotplugProbePath does not exist
	os.Remove(sysfsMemoryHotplugProbePath)
	resp, err = a.GetGuestDetails(context.TODO(), req)
	assert.NoError(err)
	assert.Equal(resp.SupportMemHotplugProbe, false)
}

func TestGetAgentDetails(t *testing.T) {
	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	details := a.getAgentDetails(context.TODO())

	seccompSupport := a.haveSeccomp()
	testAgentDetails(assert, details, seccompSupport)
}

func TestHaveSeccomp(t *testing.T) {
	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	savedSeccompSupport := seccompSupport

	defer func() {
		seccompSupport = savedSeccompSupport
	}()

	for _, seccompSupport := range []string{"yes", "no"} {
		if seccompSupport == "yes" {
			assert.Equal(a.haveSeccomp(), seccomp.IsEnabled())
		} else {
			assert.Equal(a.haveSeccomp(), false)
		}
	}
}

func TestPosixRlimitsToRlimits(t *testing.T) {
	assert := assert.New(t)

	expectedRlimits := []configs.Rlimit{
		{Type: unix.RLIMIT_CPU, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_FSIZE, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_DATA, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_STACK, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_CORE, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_RSS, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_NPROC, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_NOFILE, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_MEMLOCK, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_AS, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_LOCKS, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_SIGPENDING, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_MSGQUEUE, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_NICE, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_RTPRIO, Hard: 100, Soft: 120},
		{Type: unix.RLIMIT_RTTIME, Hard: 100, Soft: 120},
	}

	posixRlimits := []specs.POSIXRlimit{
		{Type: "RLIMIT_CPU", Hard: 100, Soft: 120},
		{Type: "RLIMIT_FSIZE", Hard: 100, Soft: 120},
		{Type: "RLIMIT_DATA", Hard: 100, Soft: 120},
		{Type: "RLIMIT_STACK", Hard: 100, Soft: 120},
		{Type: "RLIMIT_CORE", Hard: 100, Soft: 120},
		{Type: "RLIMIT_RSS", Hard: 100, Soft: 120},
		{Type: "RLIMIT_NPROC", Hard: 100, Soft: 120},
		{Type: "RLIMIT_NOFILE", Hard: 100, Soft: 120},
		{Type: "RLIMIT_MEMLOCK", Hard: 100, Soft: 120},
		{Type: "RLIMIT_AS", Hard: 100, Soft: 120},
		{Type: "RLIMIT_LOCKS", Hard: 100, Soft: 120},
		{Type: "RLIMIT_SIGPENDING", Hard: 100, Soft: 120},
		{Type: "RLIMIT_MSGQUEUE", Hard: 100, Soft: 120},
		{Type: "RLIMIT_NICE", Hard: 100, Soft: 120},
		{Type: "RLIMIT_RTPRIO", Hard: 100, Soft: 120},
		{Type: "RLIMIT_RTTIME", Hard: 100, Soft: 120},
		{Type: "RLIMIT_UNSUPPORTED", Hard: 0, Soft: 0},
	}

	rlimits := posixRlimitsToRlimits(posixRlimits)

	assert.Equal(rlimits, expectedRlimits)
}

func TestCopyFile(t *testing.T) {
	assert := assert.New(t)

	oldContainersRootfsPath := containersRootfsPath
	containersRootfsPath = "/tmp"
	defer func() {
		containersRootfsPath = oldContainersRootfsPath
	}()

	a := &agentGRPC{}
	req := &pb.CopyFileRequest{
		DirMode:  0755,
		FileMode: 0755,
		Uid:      int32(os.Getuid()),
		Gid:      int32(os.Getgid()),
	}

	_, err := a.CopyFile(context.Background(), req)
	assert.Error(err)

	dir, err := ioutil.TempDir("", "copy")
	assert.NoError(err)
	defer os.RemoveAll(dir)

	req.Path = filepath.Join(dir, "file")

	part1 := []byte("hello")
	part2 := []byte("world")
	req.FileSize = int64(len(part1) + len(part2))

	// send first part
	req.Offset = 0
	req.Data = part1
	_, err = a.CopyFile(context.Background(), req)
	assert.NoError(err)

	// send second part
	req.Offset = int64(len(part1))
	req.Data = part2
	_, err = a.CopyFile(context.Background(), req)
	assert.NoError(err)

	// check file exist
	assert.FileExists(req.Path)
	content, err := ioutil.ReadFile(req.Path)
	assert.NoError(err)
	// check file's content
	assert.Equal(content, append(part1, part2...))

	req.Path = "/does/not/exist/foo/bar"
	_, err = a.CopyFile(context.Background(), req)
	assert.Error(err)
}

func TestIsSignalHandled(t *testing.T) {
	assert := assert.New(t)
	pid := 1

	// process will not handle SIGKILL signal
	signum := syscall.SIGKILL
	handled := isSignalHandled(pid, signum)
	assert.False(handled)

	// init process will not handle SIGTERM signal
	signum = syscall.SIGTERM
	handled = isSignalHandled(pid, signum)
	assert.False(handled)

	// init process will handle the SIGQUIT signal
	signum = syscall.SIGQUIT
	handled = isSignalHandled(pid, signum)
	assert.True(handled)

	handled = isSignalHandled(-1, signum)
	assert.False(handled)
}

func TestOnlineResources(t *testing.T) {
	assert := assert.New(t)

	cpusDir, err := ioutil.TempDir("", "cpu")
	assert.NoError(err)
	defer os.RemoveAll(cpusDir)

	// cold plug CPU
	cpu0Path := filepath.Join(cpusDir, "cpu0")
	err = os.Mkdir(cpu0Path, 0755)
	assert.NoError(err)

	// readonly CPU
	cpu1Path := filepath.Join(cpusDir, "cpu1")
	err = os.Mkdir(cpu1Path, 0755)
	assert.NoError(err)
	f, err := os.Create(filepath.Join(cpu1Path, "online"))
	assert.NoError(err)
	_, err = f.Write([]byte("0"))
	assert.NoError(err)
	assert.NoError(f.Close())
	err = os.Chmod(f.Name(), 0400)
	assert.NoError(err)
	err = os.Chmod(cpu1Path, 0400)
	assert.NoError(err)

	// Hot plug CPU
	cpu2Path := filepath.Join(cpusDir, "cpu2")
	err = os.Mkdir(cpu2Path, 0755)
	assert.NoError(err)
	f, err = os.Create(filepath.Join(cpu2Path, "online"))
	assert.NoError(err)
	_, err = f.Write([]byte("0"))
	assert.NoError(err)
	assert.NoError(f.Close())

	// nothing related to CPUs
	argbPath := filepath.Join(cpusDir, "argb")
	err = os.Mkdir(argbPath, 0755)
	assert.NoError(err)

	resource := onlineResource{
		sysfsOnlinePath: cpusDir,
		regexpPattern:   "[invalid.regex",
	}

	_, err = onlineResources(resource, 0)
	assert.Error(err)

	resource.regexpPattern = cpuRegexpPattern

	expectedCpus := int32(1)
	r, err := onlineResources(resource, expectedCpus)
	assert.NoError(err)
	assert.Equal(uint32(expectedCpus), r)

	// Error: path doesn't exist
	resource.sysfsOnlinePath = "/abc/123/rgb/:)"
	r, err = onlineResources(resource, expectedCpus)
	assert.Error(err)
	assert.Equal(uint32(0), r)
}

func TestSetConsoleCarriageReturn(t *testing.T) {
	assert := assert.New(t)

	err := setConsoleCarriageReturn(-1)
	assert.Error(err)
}

func TestCheck(t *testing.T) {
	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	req := &pb.CheckRequest{}
	ctx := context.Background()

	resp, err := a.Check(ctx, req)
	assert.NoError(err)
	assert.Equal(resp.Status, pb.HealthCheckResponse_SERVING)
}

func TestVersion(t *testing.T) {
	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	req := &pb.CheckRequest{}
	ctx := context.Background()

	resp, err := a.Version(ctx, req)
	assert.NoError(err)
	assert.Equal(resp.GrpcVersion, pb.APIVersion)
	assert.Equal(resp.AgentVersion, a.version)
}

func TestGetContainer(t *testing.T) {
	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	a.sandbox.running = false
	_, err := a.getContainer("")
	assert.Error(err)

	a.sandbox.running = true
	_, err = a.getContainer("")
	assert.Error(err)

	ctr := &container{}
	a.sandbox.containers["foo"] = ctr
	_, err = a.getContainer("foo")
	assert.NoError(err)
}

func TestPrivateExecProcess(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		nilContainer bool
		nilProc      bool
		expectError  bool
	}

	data := []testData{
		{true, false, true},
		{false, true, true},
		{true, true, true},
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	testCtr := &container{}

	testProc := &process{}

	for i, d := range data {
		var ctr *container
		var proc *process

		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		if d.nilContainer {
			ctr = nil
		} else {
			ctr = testCtr
		}

		if d.nilProc {
			proc = nil
		} else {
			proc = testProc
		}

		err := a.execProcess(ctr, proc, true)
		if d.expectError {
			assert.Error(err, msg)
			continue
		}

		assert.NoError(err, msg)
	}
}

func TestPostExecProcess(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		nilContainer bool
		nilProc      bool
		expectError  bool
	}

	data := []testData{
		{true, false, true},
		{false, true, true},
		{true, true, true},
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	testCtr := &container{}

	testProc := &process{}

	for i, d := range data {
		var ctr *container
		var proc *process

		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		if d.nilContainer {
			ctr = nil
		} else {
			ctr = testCtr
		}

		if d.nilProc {
			proc = nil
		} else {
			proc = testProc
		}

		err := a.postExecProcess(ctr, proc)
		if d.expectError {
			assert.Error(err, msg)
			continue
		}

		assert.NoError(err, msg)
	}
}

func TestPidNsExists(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		spec           *pb.Spec
		expectNSexists bool
	}

	data := []testData{
		{
			&pb.Spec{
				Linux: nil,
			},
			false,
		},
		{
			&pb.Spec{
				Linux: &pb.Linux{
					Namespaces: []pb.LinuxNamespace{
						{
							Type: "NEWPID",
							Path: "foo",
						},
					},
				},
			},
			true,
		},
	}

	for i, d := range data {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		a := &agentGRPC{}

		result := a.pidNsExists(d.spec)

		if d.expectNSexists {
			assert.True(result, msg)
		} else {
			assert.False(result, msg)
		}
	}
}

func TestCreateContainerChecks(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		sandbox     *sandbox
		req         *pb.CreateContainerRequest
		expectError bool
	}

	data := []testData{
		{
			&sandbox{
				containers: make(map[string]*container),
				running:    false,
			},
			&pb.CreateContainerRequest{},
			true,
		},
		{
			&sandbox{
				containers: map[string]*container{
					"foo": {
						id: "foo",
					},
				},
				running: true,
			},
			&pb.CreateContainerRequest{
				ContainerId: "foo",
			},
			true,
		},
		{
			&sandbox{
				containers: make(map[string]*container),
				running:    true,
			},
			&pb.CreateContainerRequest{
				ContainerId: "foo",
				OCI: &pb.Spec{
					Linux: &pb.Linux{
						Namespaces: []pb.LinuxNamespace{
							{
								Type: "NEWPID",
								Path: "foo",
							},
						},
					},
				},
			},
			true,
		},
		{
			&sandbox{
				containers: make(map[string]*container),
				running:    true,
			},
			&pb.CreateContainerRequest{
				ContainerId: "foo",
				OCI: &pb.Spec{
					Linux: &pb.Linux{
						Namespaces: []pb.LinuxNamespace{},
					},
				},
			},
			false,
		},
	}

	for i, d := range data {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		a := &agentGRPC{
			sandbox: d.sandbox,
		}

		err := a.createContainerChecks(d.req)

		if d.expectError {
			assert.Error(err, msg)
			continue
		}

		assert.NoError(err, msg)
	}
}

func TestCreateContainer(t *testing.T) {
	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
			running:    false,
		},
	}

	req := &pb.CreateContainerRequest{}

	_, err := a.CreateContainer(context.Background(), req)
	assert.Error(err)
}

func TestRemoveContainer(t *testing.T) {
	assert := assert.New(t)

	req := &pb.RemoveContainerRequest{
		ContainerId: "foo",
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
			running:    true,
		},
	}

	_, err := a.RemoveContainer(context.Background(), req)
	assert.Error(err)
}

func TestCreateSandbox(t *testing.T) {
	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
			running:    true,
		},
	}

	req := &pb.CreateSandboxRequest{}

	_, err := a.CreateSandbox(context.Background(), req)
	assert.Error(err)
}

func TestDestroySandbox(t *testing.T) {
	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
			running:    false,
		},
	}

	req := &pb.DestroySandboxRequest{}

	result, err := a.DestroySandbox(context.Background(), req)
	assert.NoError(err)
	assert.Equal(result, emptyResp)
}

func TestStartContainer(t *testing.T) {
	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
			running:    false,
		},
	}

	req := &pb.StartContainerRequest{}

	_, err := a.StartContainer(context.Background(), req)
	assert.Error(err)
}

func TestExecProcess(t *testing.T) {
	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
			running:    false,
		},
	}

	req := &pb.ExecProcessRequest{}

	_, err := a.ExecProcess(context.Background(), req)
	assert.Error(err)
}

func TestSignalProcess(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		sandbox     *sandbox
		req         *pb.SignalProcessRequest
		expectError bool
	}

	basicReq := &pb.SignalProcessRequest{
		ContainerId: "foo",
	}

	execReq := &pb.SignalProcessRequest{
		ContainerId: "foo",
		ExecId:      "1",
	}

	data := []testData{
		{
			&sandbox{
				containers: make(map[string]*container),
				running:    false,
			},
			basicReq,
			true,
		},
		{
			&sandbox{
				containers: make(map[string]*container),
				running:    true,
			},
			basicReq,
			true,
		},
		{
			&sandbox{
				containers: map[string]*container{
					"foo": {
						id: "foo",
						container: &mockContainer{
							processes: []int{1},
						},
					},
				},
				running: true,
			},
			basicReq,
			false,
		},
		{
			&sandbox{
				containers: map[string]*container{
					"foo": {
						id: "foo",
						container: &mockContainer{
							processes: []int{1},
							status:    libcontainer.Stopped,
						},
					},
				},
				running: true,
			},
			basicReq,
			false,
		},
		{
			&sandbox{
				containers: map[string]*container{
					"foo": {
						id: "foo",
						container: &mockContainer{
							processes: []int{1},
						},
						initProcess: &process{
							id: "1",
						},
					},
				},
				running: true,
			},
			execReq,
			true,
		},
	}

	for i, d := range data {
		msg := fmt.Sprintf("test[%d]: %+v\n", i, d)

		a := &agentGRPC{
			sandbox: d.sandbox,
		}

		_, err := a.SignalProcess(context.Background(), d.req)
		if d.expectError {
			assert.Error(err, msg)
			continue
		}
		assert.NoError(err, msg)
	}
}

func TestHandleCPUSet(t *testing.T) {
	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	linuxSpec := &specs.Linux{
		Resources: &specs.LinuxResources{},
	}

	spec := &specs.Spec{
		Linux: linuxSpec,
	}

	err := a.handleCPUSet(spec)
	assert.NoError(err)

	linuxCPU := &specs.LinuxCPU{}

	spec.Linux.Resources.CPU = linuxCPU
	err = a.handleCPUSet(spec)
	assert.NoError(err)

	spec.Linux.Resources.CPU.Cpus = "foo"
	err = a.handleCPUSet(spec)
	assert.Error(err)
}

func TestMemHotplugByProbe(t *testing.T) {
	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	req := &pb.MemHotplugByProbeRequest{}

	_, err := a.MemHotplugByProbe(context.Background(), req)
	assert.NoError(err)
}

func TestSetGuestDateTime(t *testing.T) {
	// Ensure a non-priv users runs the test to guarantee a failure
	skipIfRoot(t)

	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	req := &pb.SetGuestDateTimeRequest{}

	_, err := a.SetGuestDateTime(context.Background(), req)
	assert.Error(err)
}

func TestFinishCreateContainer(t *testing.T) {
	skipIfRoot(t)

	assert := assert.New(t)

	a := &agentGRPC{
		sandbox: &sandbox{
			id:         "foo",
			containers: make(map[string]*container),
		},
	}

	_, err := a.finishCreateContainer(nil, nil, nil)

	// EPERM
	assert.Error(err)
}

func TestUpdateSharedPidNs(t *testing.T) {
	assert := assert.New(t)

	ctr := &container{
		id: "foo",
		container: &mockContainer{
			processes: []int{1},
		},
		initProcess: &process{
			id:      "1",
			process: libcontainer.Process{},
		},
	}

	s := &sandbox{
		sandboxPidNs: false,
		containers: map[string]*container{
			"foo": ctr,
		},
	}

	a := &agentGRPC{
		sandbox: s,
	}

	err := a.updateSharedPidNs(ctr)
	assert.Error(err)
}

func TestWriteStdin(t *testing.T) {
	assert := assert.New(t)

	req := &pb.WriteStreamRequest{
		ContainerId: "foo",
		ExecId:      "foo",
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	_, err := a.WriteStdin(context.Background(), req)
	assert.Error(err)
}

func TestCloseStdin(t *testing.T) {
	assert := assert.New(t)

	req := &pb.CloseStdinRequest{
		ContainerId: "foo",
		ExecId:      "foo",
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	_, err := a.CloseStdin(context.Background(), req)
	assert.Error(err)
}

func TestTtyWinResize(t *testing.T) {
	assert := assert.New(t)

	req := &pb.TtyWinResizeRequest{
		ContainerId: "foo",
		ExecId:      "foo",
	}

	a := &agentGRPC{
		sandbox: &sandbox{
			containers: make(map[string]*container),
		},
	}

	_, err := a.TtyWinResize(context.Background(), req)
	assert.Error(err)
}
