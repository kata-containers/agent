//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"io/ioutil"
	"os"
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
