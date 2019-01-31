//
// Copyright (c) 2018-2019 Intel Corporation
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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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
	f, _, err := os.Pipe()
	assert.Nil(t, err, "%v", err)

	c := &serialChannel{serialConn: f}

	l, err := c.listen()
	assert.Nil(t, err, "%v", err)
	assert.NotNil(t, l, "listen should not return nil listener")

	err = l.Close()
	assert.Nil(t, err, "%v", err)

	err = c.teardown()
	assert.Error(t, err, "connection should be already closed")
}

func TestTeardownSerialChannel(t *testing.T) {
	_, f, err := os.Pipe()
	assert.Nil(t, err, "%v", err)

	c := &serialChannel{serialConn: f}

	err = c.teardown()
	assert.Nil(t, err, "%v", err)
}

func TestTeardownSerialChannelTimeout(t *testing.T) {
	_, f, err := os.Pipe()
	assert.Nil(t, err, "%v", err)
	channelCloseTimeout = 1 * time.Microsecond

	c := &serialChannel{
		serialConn: f,
		waitCh:     make(chan struct{}),
	}

	err = c.teardown()
	assert.NotNil(t, err, "channel close should timeout")
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

	c, err := newChannel(context.Background())
	assert.Error(err)
	assert.Nil(c)

	vSockDevPath = "/dev/null"
	c, err = newChannel(context.Background())
	assert.Error(err)
	assert.Nil(c)

	isAFVSockSupportedFunc = func() (bool, error) { return true, nil }
	c, err = newChannel(context.Background())
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
	c, err = newChannel(context.Background())
	assert.NoError(err)
	_, ok = c.(*serialChannel)
	assert.True(ok)
}
