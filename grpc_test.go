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
	"sort"
	"strconv"
	"syscall"
	"testing"
	"time"

	"sync"

	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/opencontainers/runc/libcontainer"
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

	sort.Sort(sort.StringSlice(details.DeviceHandlers))
	sort.Sort(sort.StringSlice(details.StorageHandlers))

	sort.Sort(sort.StringSlice(devices))
	sort.Sort(sort.StringSlice(storages))

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
		{unix.RLIMIT_CPU, 100, 120},
		{unix.RLIMIT_FSIZE, 100, 120},
		{unix.RLIMIT_DATA, 100, 120},
		{unix.RLIMIT_STACK, 100, 120},
		{unix.RLIMIT_CORE, 100, 120},
		{unix.RLIMIT_RSS, 100, 120},
		{unix.RLIMIT_NPROC, 100, 120},
		{unix.RLIMIT_NOFILE, 100, 120},
		{unix.RLIMIT_MEMLOCK, 100, 120},
		{unix.RLIMIT_AS, 100, 120},
		{unix.RLIMIT_LOCKS, 100, 120},
		{unix.RLIMIT_SIGPENDING, 100, 120},
		{unix.RLIMIT_MSGQUEUE, 100, 120},
		{unix.RLIMIT_NICE, 100, 120},
		{unix.RLIMIT_RTPRIO, 100, 120},
		{unix.RLIMIT_RTTIME, 100, 120},
	}

	posixRlimits := []specs.POSIXRlimit{
		{"RLIMIT_CPU", 100, 120},
		{"RLIMIT_FSIZE", 100, 120},
		{"RLIMIT_DATA", 100, 120},
		{"RLIMIT_STACK", 100, 120},
		{"RLIMIT_CORE", 100, 120},
		{"RLIMIT_RSS", 100, 120},
		{"RLIMIT_NPROC", 100, 120},
		{"RLIMIT_NOFILE", 100, 120},
		{"RLIMIT_MEMLOCK", 100, 120},
		{"RLIMIT_AS", 100, 120},
		{"RLIMIT_LOCKS", 100, 120},
		{"RLIMIT_SIGPENDING", 100, 120},
		{"RLIMIT_MSGQUEUE", 100, 120},
		{"RLIMIT_NICE", 100, 120},
		{"RLIMIT_RTPRIO", 100, 120},
		{"RLIMIT_RTTIME", 100, 120},
		{"RLIMIT_UNSUPPORTED", 0, 0},
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
}
