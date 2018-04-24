//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"syscall"
	"testing"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/stretchr/testify/assert"
)

func TestMockContainerID(t *testing.T) {
	assert := assert.New(t)
	expectedContID := "abc"
	m := &mockContainer{id: expectedContID}
	id := m.ID()
	assert.Equal(expectedContID, id)
}

func TestMockContainerStatus(t *testing.T) {
	assert := assert.New(t)
	expectedStatus := libcontainer.Running
	m := &mockContainer{status: expectedStatus}
	status, err := m.Status()
	assert.NoError(err)
	assert.Equal(expectedStatus, status)
}

func TestMockContainerState(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	st, err := m.State()
	assert.NoError(err)
	assert.Nil(st)
}

func TestMockContainerConfig(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	cfg := m.Config()
	assert.NotNil(cfg)
}

func TestMockContainerProcesses(t *testing.T) {
	assert := assert.New(t)
	expectedProcesses := []int{1}
	m := &mockContainer{processes: expectedProcesses}
	p, err := m.Processes()
	assert.NoError(err)
	assert.Equal(expectedProcesses, p)
}

func TestMockContainerStats(t *testing.T) {
	assert := assert.New(t)
	expectedStats := &libcontainer.Stats{
		CgroupStats: &cgroups.Stats{},
	}
	m := &mockContainer{stats: *expectedStats}
	st, err := m.Stats()
	assert.NoError(err)
	assert.Equal(expectedStats, st)
}

func TestMockContainerSet(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	err := m.Set(configs.Config{})
	assert.NoError(err)
}

func TestMockContainerStart(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	err := m.Start(nil)
	assert.NoError(err)
}

func TestMockContainerRun(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	err := m.Run(nil)
	assert.NoError(err)
}

func TestMockContainerDestroy(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	err := m.Destroy()
	assert.NoError(err)
}

func TestMockContainerSignal(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	err := m.Signal(syscall.SIGKILL, true)
	assert.NoError(err)
}

func TestMockContainerExec(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	err := m.Exec()
	assert.NoError(err)
}

func TestMockContainerCheckpoint(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	err := m.Checkpoint(nil)
	assert.NoError(err)
}

func TestMockContainerRestore(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	err := m.Restore(nil, nil)
	assert.NoError(err)
}

func TestMockContainerPause(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	err := m.Pause()
	assert.NoError(err)
}

func TestMockContainerResume(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	err := m.Resume()
	assert.NoError(err)
}

func TestMockContainerNotifyOOM(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	c, err := m.NotifyOOM()
	assert.NoError(err)
	assert.Nil(c)
}

func TestMockContainerNotifyMemoryPressure(t *testing.T) {
	assert := assert.New(t)
	m := &mockContainer{}
	c, err := m.NotifyMemoryPressure(libcontainer.LowPressure)
	assert.NoError(err)
	assert.Nil(c)
}
