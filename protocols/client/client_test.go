// Copyright 2017 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// gRPC client wrapper UT

package client

import (
	"net"
	"os"
	"testing"

	"google.golang.org/grpc"

	"github.com/kata-project/agent/protocols/mockserver"
)

const mockSockAddr = "/tmp/agentserver.sock"
const unixMockAddr = "unix://" + mockSockAddr
const badMockAddr = "vsock://" + mockSockAddr

func startMockServer(t *testing.T) (*grpc.Server, chan error, error) {
	os.Remove(mockSockAddr)

	l, err := net.Listen("unix", mockSockAddr)
	if err != nil {
		t.Fatalf("Listen on %s failed: %s", mockSockAddr, err)
	}

	mock := mockserver.NewMockServer()

	stopWait := make(chan error, 1)
	go func() {
		mock.Serve(l)
		stopWait <- nil
	}()

	return mock, stopWait, nil
}

func TestNewAgentClient(t *testing.T) {
	mock, waitCh, err := startMockServer(t)
	if err != nil {
		t.Fatalf("failed to start mock server: %s", err)
	}

	cliFunc := func(sock string, success bool) {
		cli, err := NewAgentClient(sock)
		if success && err != nil {
			t.Fatalf("Failed to create new agent client: %s", err)
		} else if !success && err == nil {
			t.Fatalf("Unexpected success with sock address: %s", sock)
		}
		if err == nil {
			cli.Close()
		}
	}

	cliFunc(mockSockAddr, true)
	cliFunc(unixMockAddr, true)
	cliFunc(badMockAddr, false)

	// wait mock server to stop
	mock.Stop()
	err = <-waitCh
	if err != nil {
		t.Fatalf("mock server failed: %s", err)
	}
}
