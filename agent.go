//
// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/sirupsen/logrus"
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

var agentLog = logrus.WithFields(logrus.Fields{
	"name": agentName,
	"pid":  os.Getpid(),
})

// Version is the agent version. This variable is populated at build time.
var Version = "unknown"

func (p *pod) initLogger() error {
	agentLog.Logger.Formatter = &logrus.TextFormatter{TimestampFormat: time.RFC3339Nano}

	config := newConfig(defaultLogLevel)
	if err := config.getConfig(kernelCmdlineFile); err != nil {
		agentLog.WithError(err).Warn("Failed to get config from kernel cmdline")
	}
	config.applyConfig()

	agentLog.WithField("version", Version).Info()

	return nil
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
			agentLog.Error(err)
			os.Exit(exitFailure)
		}

		os.Exit(exitSuccess)
	}()

	// Initialize unique pod structure.
	p := &pod{
		containers: make(map[string]*container),
		running:    false,
	}

	if err = p.initLogger(); err != nil {
		return
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
