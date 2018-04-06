//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMockReaperInit(t *testing.T) {
	m := &mockreaper{}
	m.init()
}

func TestMockReaperGetExitCodeCh(t *testing.T) {
	assert := assert.New(t)
	m := &mockreaper{}
	c, e := m.getExitCodeCh(0)
	assert.Nil(c)
	assert.NoError(e)
}

func TestMockReaperSetExitCodeCh(t *testing.T) {
	m := &mockreaper{}
	m.setExitCodeCh(0, nil)
}

func TestMockReaperDeleteExitCodeCh(t *testing.T) {
	m := &mockreaper{}
	m.deleteExitCodeCh(0)
}

func TestMockReaperReap(t *testing.T) {
	assert := assert.New(t)
	m := &mockreaper{}
	err := m.reap()
	assert.NoError(err)
}

func TestMockReaperStart(t *testing.T) {
	assert := assert.New(t)
	m := &mockreaper{}
	c, e := m.start(nil)
	assert.Nil(c)
	assert.NoError(e)
}

func TestMockReaperWait(t *testing.T) {
	assert := assert.New(t)
	m := &mockreaper{}
	e, err := m.wait(nil, &reaperOSProcess{})
	assert.Equal(0, e)
	assert.NoError(err)
}

func TestMockReaperLock(t *testing.T) {
	m := &mockreaper{}
	m.lock()
}

func TestMockReaperUnlock(t *testing.T) {
	m := &mockreaper{}
	m.unlock()
}
