//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVSockPathExistTrue(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test")
	assert.Nil(t, err, "%v", err)
	fileName := tmpFile.Name()
	defer tmpFile.Close()
	defer os.Remove(fileName)

	vSockDevPath = fileName

	result, err := vSockPathExist()
	assert.Nil(t, err, "%v", err)

	assert.True(t, result, "VSOCK should be found")
}

func TestVSockPathExistFalse(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "test")
	assert.Nil(t, err, "%v", err)

	fileName := tmpFile.Name()
	tmpFile.Close()
	err = os.Remove(fileName)
	assert.Nil(t, err, "%v", err)

	vSockDevPath = fileName

	result, err := vSockPathExist()
	assert.Nil(t, err, "%v", err)

	assert.False(t, result, "VSOCK should not be found")
}

func TestSetupVSockChannel(t *testing.T) {
	c := &vSockChannel{}

	err := c.setup()
	assert.Nil(t, err, "%v", err)
}

func TestTeardownVSockChannel(t *testing.T) {
	c := &vSockChannel{}

	err := c.teardown()
	assert.Nil(t, err, "%v", err)
}

func TestWaitVSockChannel(t *testing.T) {
	c := &vSockChannel{}

	err := c.wait()
	assert.Nil(t, err, "%v", err)
}

func TestWaitSerialChannel(t *testing.T) {
	_, f, err := os.Pipe()
	assert.Nil(t, err, "%v", err)
	defer f.Close()

	c := &serialChannel{serialConn: f}

	err = c.wait()
	assert.Nil(t, err, "%v", err)
}

func TestListenSerialChannel(t *testing.T) {
	_, f, err := os.Pipe()
	assert.Nil(t, err, "%v", err)

	c := &serialChannel{serialConn: f}

	_, err = c.listen()
	assert.Nil(t, err, "%v", err)
}

func TestTeardownSerialChannel(t *testing.T) {
	_, f, err := os.Pipe()
	assert.Nil(t, err, "%v", err)

	c := &serialChannel{serialConn: f}

	err = c.teardown()
	assert.Nil(t, err, "%v", err)
}

func TestNewChannel(t *testing.T) {
	assert := assert.New(t)

	orgChannelExistMaxTries := channelExistMaxTries
	orgChannelExistWaitTime := channelExistWaitTime
	orgVSockDevPath := vSockDevPath
	orgVirtIOPath := virtIOPath
	orgIsAFVSockSupportedFunc := isAFVSockSupportedFunc
	channelExistMaxTries = 1
	channelExistWaitTime = 0
	vSockDevPath = "/abc/xyz/123"
	virtIOPath = "/abc/xyz/123"
	isAFVSockSupportedFunc = func() (bool, error) { return false, errors.New("vsock") }
	defer func() {
		channelExistMaxTries = orgChannelExistMaxTries
		channelExistWaitTime = orgChannelExistWaitTime
		vSockDevPath = orgVSockDevPath
		virtIOPath = orgVirtIOPath
		isAFVSockSupportedFunc = orgIsAFVSockSupportedFunc
	}()

	c, err := newChannel()
	assert.Error(err)
	assert.Nil(c)

	vSockDevPath = "/dev/null"
	c, err = newChannel()
	assert.Error(err)
	assert.Nil(c)

	isAFVSockSupportedFunc = func() (bool, error) { return true, nil }
	c, err = newChannel()
	assert.NoError(err)
	_, ok := c.(*vSockChannel)
	assert.True(ok)

	vSockDevPath = "/abc/xyz/123"
	virtIOPath, err = ioutil.TempDir("", "virtio")
	assert.NoError(err)
	portPath := filepath.Join(virtIOPath, "port")
	err = os.Mkdir(portPath, 0777)
	assert.NoError(err)
	defer os.Remove(portPath)
	err = ioutil.WriteFile(filepath.Join(portPath, "name"), []byte(serialChannelName), 0777)
	assert.NoError(err)
	c, err = newChannel()
	assert.NoError(err)
	_, ok = c.(*serialChannel)
	assert.True(ok)
}
