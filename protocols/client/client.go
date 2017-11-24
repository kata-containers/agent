// Copyright 2017 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// gRPC client wrapper

package client

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
	"google.golang.org/grpc"

	agentgrpc "github.com/kata-project/agent/protocols/grpc"
)

const (
	UNIX_SOCKET_PREFIX  = "unix://"
	VSOCK_SOCKET_PREFIX = "vsock://"
)

type AgentClient struct {
	agentgrpc.HyperstartServiceClient
	conn *grpc.ClientConn
}

type dialer func(string, time.Duration) (net.Conn, error)

// Supported sock address formats are:
//   - unix://<unix socket path>
//   - vsock://<cid>:<port>
//   - <unix socket path>
func NewAgentClient(sock string) (*AgentClient, error) {
	dialOpts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithTimeout(5 * time.Second)}
	dialOpts = append(dialOpts, grpc.WithDialer(agentDialer(sock)))
	conn, err := grpc.Dial(sock, dialOpts...)
	if err != nil {
		return nil, err
	}

	return &AgentClient{
		HyperstartServiceClient: agentgrpc.NewHyperstartServiceClient(conn),
		conn: conn,
	}, nil
}

func (c *AgentClient) Close() error {
	return c.conn.Close()
}

func agentDialer(addr string) dialer {
	switch {
	case strings.HasPrefix(addr, VSOCK_SOCKET_PREFIX):
		return vsockDialer
	case strings.HasPrefix(addr, UNIX_SOCKET_PREFIX):
		fallthrough
	default:
		return unixDialer
	}
}

func unixDialer(addr string, timeout time.Duration) (net.Conn, error) {
	if strings.HasPrefix(addr, UNIX_SOCKET_PREFIX) {
		addr = addr[len(UNIX_SOCKET_PREFIX):]
	}
	return net.DialTimeout("unix", addr, timeout)
}

func vsockDialer(addr string, timeout time.Duration) (net.Conn, error) {
	if strings.HasPrefix(addr, VSOCK_SOCKET_PREFIX) {
		addr = addr[len(VSOCK_SOCKET_PREFIX):]
	}

	invalidVsockMsgErr := fmt.Errorf("invalid vsock destination: %s", VSOCK_SOCKET_PREFIX+addr)
	seq := strings.Split(addr, ":")
	if len(seq) != 2 {
		return nil, invalidVsockMsgErr
	}
	cid, err := strconv.ParseUint(seq[0], 10, 32)
	if err != nil {
		return nil, invalidVsockMsgErr
	}
	port, err := strconv.ParseUint(seq[1], 10, 32)
	if err != nil {
		return nil, invalidVsockMsgErr
	}

	return vsock.Dial(uint32(cid), uint32(port))
}
