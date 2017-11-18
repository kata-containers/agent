//
// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	grpc "google.golang.org/grpc"
)

type process struct {
	process     libcontainer.Process
	stdin       *os.File
	stdout      *os.File
	stderr      *os.File
	seqStdio    uint64
	seqStderr   uint64
	consoleSock *os.File
	termMaster  *os.File
}

type container struct {
	container     libcontainer.Container
	config        configs.Config
	processes     map[string]*process
	pod           *pod
	processesLock sync.RWMutex
	wgProcesses   sync.WaitGroup
}

type pod struct {
	id           string
	running      bool
	containers   map[string]*container
	channel      channel
	stdinLock    sync.Mutex
	ttyLock      sync.Mutex
	podLock      sync.RWMutex
	wg           sync.WaitGroup
	grpcListener net.Listener
}

func (p *pod) initChannel() error {
	c, err := newChannel()
	if err != nil {
		return err
	}

	p.channel = c

	return p.channel.setup()
}

func (p *pod) startGRPC() error {
	l, err := p.channel.listen()
	if err != nil {
		return err
	}

	p.grpcListener = l

	grpcServer := grpc.NewServer()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		grpcServer.Serve(l)
	}()

	return nil
}

func (p *pod) teardown() error {
	if err := p.grpcListener.Close(); err != nil {
		return err
	}

	return p.channel.teardown()
}

func main() {
	var err error

	defer func() {
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(exitFailure)
		}

		os.Exit(exitSuccess)
	}()

	// Initialize unique pod structure.
	p := &pod{
		containers: make(map[string]*container),
		running:    false,
	}

	// Check for vsock vs serial. This will fill the pod structure with
	// information about the channel.
	if err = p.initChannel(); err != nil {
		return
	}

	// Start gRPC server.
	if err = p.startGRPC(); err != nil {
		return
	}

	p.wg.Wait()

	// Tear down properly.
	if err = p.teardown(); err != nil {
		return
	}
}
