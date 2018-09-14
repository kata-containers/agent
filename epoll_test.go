// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestNewEpoller(t *testing.T) {
	assert := assert.New(t)

	epoller, err := newEpoller()
	assert.NoError(err)

	closeEpoller(epoller)

}

func closeEpoller(ep *epoller) {
	ep.sockW.Close()
	ep.sockR.Close()
	unix.Close(ep.fd)
}

func TestAddEpoller(t *testing.T) {
	assert := assert.New(t)

	epoller, _ := newEpoller()
	assert.NotNil(epoller)
	defer closeEpoller(epoller)

	rSock, wSock, err := os.Pipe()
	assert.NoError(err)
	defer rSock.Close()
	defer wSock.Close()

	err = epoller.add(rSock)

	assert.NoError(err)
}

func TestRunEpoller(t *testing.T) {
	assert := assert.New(t)
	wg := sync.WaitGroup{}

	epoller, _ := newEpoller()
	assert.NotNil(epoller)
	defer closeEpoller(epoller)

	content := []byte("temporary file's content")
	rSock, wSock, err := os.Pipe()
	assert.NoError(err)
	defer rSock.Close()
	defer wSock.Close()

	err = epoller.add(rSock)
	assert.NoError(err)

	wg.Add(1)
	go func() {
		wg.Done()
		wSock.Write(content)
	}()

	wg.Wait()
	f, err := epoller.run()
	assert.NoError(err)

	assert.Equal(f.Fd(), rSock.Fd())
	closeEpoller(epoller)
}
