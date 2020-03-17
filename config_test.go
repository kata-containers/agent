//
// Copyright (c) 2018-2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestParseCmdlineOptionEmptyOption(t *testing.T) {
	assert := assert.New(t)
	err := parseCmdlineOption("")
	assert.NoError(err, "%v", err)
}

func TestParseCmdlineOptionWrongOptionValue(t *testing.T) {
	assert := assert.New(t)

	wrongOption := logLevelFlag + "=debgu"

	err := parseCmdlineOption(wrongOption)
	assert.Errorf(err, "Parsing should fail because wrong option %q", wrongOption)
}

func TestParseCmdlineOptionWrongOptionParam(t *testing.T) {
	assert := assert.New(t)

	wrongOption := "agent.lgo=debug"

	err := parseCmdlineOption(wrongOption)
	assert.Errorf(err, "Parsing should fail because wrong option %q", wrongOption)
}

func TestParseCmdlineOptionCorrectOptions(t *testing.T) {
	assert := assert.New(t)

	logFlagList := []string{"debug", "info", "warn", "error", "fatal", "panic"}

	for _, logFlag := range logFlagList {
		debug = false
		option := logLevelFlag + "=" + logFlag

		err := parseCmdlineOption(option)
		assert.NoError(err, "%v", err)

		if logFlag == "debug" {
			assert.True(debug)
		}
	}
}

func TestParseCmdlineOptionIncorrectOptions(t *testing.T) {
	assert := assert.New(t)

	logFlagList := []string{"debg", "ifo", "wan", "eror", "ftal", "pnic"}

	for _, logFlag := range logFlagList {
		option := logLevelFlag + "=" + logFlag

		err := parseCmdlineOption(option)
		assert.Errorf(err, "Should fail because of incorrect option %q", logFlag)
	}
}

func TestParseCmdlineOptionDevMode(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		option               string
		expectDevModeEnabled bool
	}

	data := []testData{
		{"agent.Devmode", false},
		{"agent.DevMode", false},
		{"devmode", false},
		{"DevMode", false},
		{"agent.devmodel", false},
		{"agent.devmode.", false},
		{"agent.devmode-", false},
		{"agent.devmode:", false},

		{"agent.devmode", true},
	}

	for i, d := range data {
		debug = false
		crashOnError = false

		err := parseCmdlineOption(d.option)
		assert.NoError(err)

		if !d.expectDevModeEnabled {
			continue
		}

		assert.True(debug, "test %d (%+v)", i, d)
		assert.True(crashOnError, "test %d (%+v)", i, d)
	}
}

func TestGetConfigFilePathNotExist(t *testing.T) {
	assert := assert.New(t)

	tmpFile, err := ioutil.TempFile("", "test")
	assert.NoError(err, "%v", err)

	fileName := tmpFile.Name()
	tmpFile.Close()
	err = os.Remove(fileName)
	assert.NoError(err, "%v", err)

	kernelCmdlineFileOld := kernelCmdlineFile
	defer func() {
		kernelCmdlineFile = kernelCmdlineFileOld
	}()
	kernelCmdlineFile = fileName
	assert.Error(parseKernelCmdline())
}

func TestParseKernelCmdline(t *testing.T) {
	assert := assert.New(t)

	tmpFile, err := ioutil.TempFile("", "test")
	assert.NoError(err, "%v", err)
	fileName := tmpFile.Name()

	tmpFile.Write([]byte(logLevelFlag + "=info"))
	tmpFile.Close()

	defer os.Remove(fileName)

	kernelCmdlineFileOld := kernelCmdlineFile
	defer func() {
		kernelCmdlineFile = kernelCmdlineFileOld
	}()
	kernelCmdlineFile = fileName

	assert.NoError(parseKernelCmdline())

	assert.True(logLevel == logrus.InfoLevel,
		"Log levels should be identical: got %+v, expecting %+v",
		logLevel, logrus.InfoLevel)
}

func TestParseCmdlineOptionTracing(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		option              string
		expectTraceEnabled  bool
		expectCollatedTrace bool
	}

	data := []testData{
		{"", false, false},
		{"moo", false, false},
		{"." + traceModeFlag, false, false},
		{traceModeFlag + ".", false, false},
		{"x" + traceModeFlag, false, false},
		{traceModeFlag + "x", false, false},
		{"x" + traceModeFlag + "x", false, false},
		{"=" + traceModeFlag, false, false},
		{traceModeFlag + "=", false, false},

		{traceModeFlag, true, false},
		{traceModeFlag + "=" + traceTypeIsolated, true, false},
		{traceModeFlag + "=" + traceTypeCollated, true, true},

		{traceModeFlag + "=" + traceTypeIsolated + "x", false, false},
		{traceModeFlag + "=" + traceTypeCollated + "x", false, false},
	}

	kernelCmdlineFileOld := kernelCmdlineFile
	defer func() {
		kernelCmdlineFile = kernelCmdlineFileOld
	}()

	for i, d := range data {
		// force reset
		tracing = false
		collatedTrace = false
		debug = false

		tmpFile, err := ioutil.TempFile("", "")
		assert.NoError(err)

		fileName := tmpFile.Name()
		defer os.Remove(fileName)

		tmpFile.Write([]byte(d.option))
		tmpFile.Close()

		assert.False(tracing)
		assert.False(collatedTrace)
		assert.False(debug)

		kernelCmdlineFile = fileName
		assert.NoError(parseKernelCmdline())

		if d.expectTraceEnabled {
			assert.Truef(tracing, "test %d (%+v)", i, d)
		} else {
			assert.Falsef(tracing, "test %d (%+v)", i, d)
		}

		if d.expectCollatedTrace {
			assert.Truef(collatedTrace, "test %d (%+v)", i, d)
		} else {
			assert.Falsef(collatedTrace, "test %d (%+v)", i, d)
		}

		if d.expectTraceEnabled || d.expectCollatedTrace {
			assert.True(debug, "test %d (%+v)", i, d)
		}
	}
}

func TestEnableTracing(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		traceMode           string
		traceType           string
		expectCollatedTrace bool
	}

	data := []testData{
		{traceModeStatic, traceTypeIsolated, false},
		{traceModeStatic, traceTypeCollated, true},

		{traceModeDynamic, traceTypeIsolated, false},
		{traceModeDynamic, traceTypeCollated, true},
	}

	for i, d := range data {
		// force reset
		tracing = false
		collatedTrace = false
		debug = false

		enableTracing(d.traceMode, d.traceType)

		assert.True(debug, "test %d (%+v)", i, d)
		assert.True(tracing, "test %d (%+v)", i, d)

		if d.expectCollatedTrace {
			assert.True(collatedTrace, "test %d (%+v)", i, d)
		} else {
			assert.False(collatedTrace, "test %d (%+v)", i, d)
		}
	}
}

func TestParseCmdlineOptionWrongOptionVsock(t *testing.T) {
	t.Skip()
	assert := assert.New(t)

	wrongOption := "use_vsockkk=true"

	err := parseCmdlineOption(wrongOption)
	assert.Errorf(err, "Parsing should fail because wrong option %q", wrongOption)
}

func TestParseCmdlineOptionsVsock(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		val            string
		shouldErr      bool
		expectedCommCh commType
	}

	data := []testData{
		{"true", false, vsockCh},
		{"false", false, serialCh},
		{"blah", true, unknownCh},
	}

	for _, d := range data {
		commCh = unknownCh
		option := useVsockFlag + "=" + d.val

		err := parseCmdlineOption(option)
		if d.shouldErr {
			assert.Error(err)
		} else {
			assert.NoError(err)
		}
		assert.Equal(commCh, d.expectedCommCh)
	}
}

func TestParseCmdlineOptionDebugConsole(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		option                    string
		expectDebugConsoleEnabled bool
	}

	data := []testData{
		{"", false},
		{"debug_console", false},
		{"debug_console=true", false},
		{"debug_console=1", false},

		{"agent.debug_console", true},
	}

	for i, d := range data {
		debugConsole = false

		err := parseCmdlineOption(d.option)
		assert.NoError(err)

		if !d.expectDebugConsoleEnabled {
			continue
		}

		assert.True(debugConsole, "test %d (%+v)", i, d)
	}
}

func TestParseCmdlineOptionDebugConsoleVPort(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		option                    string
		expectDebugConsoleEnabled bool
		expectedError             bool
		expectedVPort             uint32
	}

	data := []testData{
		{"", false, false, 0},
		{"debug_console_vport", false, false, 0},
		{"debug_console_vport=xxx", false, false, 0},
		{"debug_console_vport=1026", false, false, 0},
		{debugConsoleVPortFlag + "=", false, true, 0},
		{debugConsoleVPortFlag + "=xxxx", false, true, 0},
		{debugConsoleVPortFlag, false, false, 0},
		{debugConsoleVPortFlag + "=1026", false, false, 1026},
	}

	for i, d := range data {
		debugConsole = false
		debugConsoleVSockPort = 0

		err := parseCmdlineOption(d.option)
		if d.expectedError {
			assert.Error(err)
		} else {
			assert.NoError(err)
		}

		if d.expectDebugConsoleEnabled {
			assert.True(debugConsole, "test %d (%+v)", i, d)
		}

		assert.Equal(debugConsoleVSockPort, d.expectedVPort)
	}
}

func TestParseCmdlineOptionHotplugTimeout(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		option                 string
		shouldErr              bool
		expectedHotplugTimeout time.Duration
	}

	data := []testData{
		{"", false, 3 * time.Second},
		{"hotpug_timout", false, 3 * time.Second},
		{"hotplug_timeout", false, 3 * time.Second},
		{"hotplug_timeout=1h", false, 3 * time.Second},
		{"agnt.hotplug_timeout=1h", false, 3 * time.Second},
		{"agent.hotplug_timeout=3h", false, 3 * time.Hour},
		{"agent.hotplug_timeout=1s", false, 1 * time.Second},
		{"agent.hotplug_timeout=0s", false, 3 * time.Second},
		{"agent.hotplug_timeout=0", false, 3 * time.Second},
		{"agent.hotplug_timeout=100ms", false, 100 * time.Millisecond},
		{"agent.hotplug_timeout=-1", true, 3 * time.Second},
		{"agent.hotplug_timeout=foobar", true, 3 * time.Second},
		{"agent.hotplug_timeout=5.0", true, 3 * time.Second},
	}

	for i, d := range data {
		// reset the hotplug timeout
		hotplugTimeout = 3 * time.Second

		err := parseCmdlineOption(d.option)
		if d.shouldErr {
			assert.Error(err)
		} else {
			assert.NoError(err)
		}

		assert.Equal(d.expectedHotplugTimeout, hotplugTimeout, "test %d (%+v)", i, d)
	}
}

func TestParseCmdlineOptionUnifiedCgroupHierarchy(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		option      string
		expected    bool
		expectError bool
	}

	data := []testData{
		{"agent.unifiedCgroupHierarchy", false, false},
		{"agent.unified_cgroup_hierarchy", false, false},
		{"agent.unified_cgroup_hierarchi", false, false},
		{"agent.unified_cgroup_hierarchy=fal", false, true},
		{"agent.unified_cgroup_hierarchy=ttt", false, true},
		{"agent.unified_cgroup_hierarchy=tru", false, true},
		{"agent.unified_cgroup_hierarchy=5", false, true},

		{"agent.unified_cgroup_hierarchy=false", false, false},
		{"agent.unified_cgroup_hierarchy=0", false, false},

		{"agent.unified_cgroup_hierarchy=true", true, false},
		{"agent.unified_cgroup_hierarchy=1", true, false},
	}

	for _, d := range data {
		unifiedCgroupHierarchy = false

		err := parseCmdlineOption(d.option)
		if d.expectError {
			assert.Error(err)
		} else {
			assert.NoError(err)
		}
		assert.Equal(d.expected, unifiedCgroupHierarchy)
	}
}

func TestParseCmdlineOptionContainerPipeSize(t *testing.T) {
	assert := assert.New(t)

	type testData struct {
		option                    string
		shouldErr                 bool
		expectedContainerPipeSize uint32
	}

	data := []testData{
		{"", false, 0},
		{"container_pip_siz", false, 0},
		{"container_pipe_size", false, 0},
		{"container_pipe_size=3", false, 0},
		{"agnt.container_pipe_size=3", false, 0},
		{"agent.container_pipe_size=3", false, 3},
		{"agent.container_pipe_size=2097152", false, 2097152},
		{"agent.container_pipe_size=-1", true, 0},
		{"agent.container_pipe_size=foobar", true, 0},
		{"agent.container_pipe_size=5.0", true, 0},
		{"agent.container_pipe_size=0", false, 0},
	}

	for i, d := range data {
		// reset the container pipe size
		containerPipeSize = uint32(0)

		err := parseCmdlineOption(d.option)
		if d.shouldErr {
			assert.Error(err)
		} else {
			assert.NoError(err)
		}

		assert.Equal(d.expectedContainerPipeSize, containerPipeSize, "test %d (%+v)", i, d)
	}
}
