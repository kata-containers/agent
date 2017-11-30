// Copyright 2017 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// gRPC mock server

package mockserver

import (
	"errors"
	"fmt"

	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "github.com/kata-project/agent/protocols/grpc"
)

type pod struct {
	containers map[string]*container
}

type container struct {
	id   string
	init string // init process name
	proc map[string]*process
}

type process struct {
	id   string
	proc *pb.Process
}

type mockServer struct {
	pod *pod
}

func NewMockServer() *grpc.Server {
	mock := &mockServer{}
	serv := grpc.NewServer()
	pb.RegisterHyperstartServiceServer(serv, mock)

	return serv
}

func validateOCISpec(spec *pb.Spec) error {
	if spec == nil || spec.Process == nil {
		return errors.New("invalid container spec")
	}
	return nil
}

func (m *mockServer) checkExist(containerId, processId string, createContainer, checkProcess, createProcess bool) error {
	if m.pod == nil {
		return errors.New("pod not created")
	}
	if containerId == "" {
		return errors.New("container ID must be set")
	}
	if checkProcess && processId == "" {
		return errors.New("process ID must be set")
	}

	// Check container existence
	if createContainer {
		if m.pod.containers[containerId] != nil {
			return fmt.Errorf("container ID %s already taken", containerId)
		}
		return nil
	} else if m.pod.containers[containerId] == nil {
		return fmt.Errorf("container %s does not exist", containerId)
	}

	// Check process existence
	if processId != "" {
		c := m.pod.containers[containerId]
		if createProcess && c.proc[processId] != nil {
			return fmt.Errorf("process ID %s already taken", processId)
		}
		if !createProcess && c.proc[processId] == nil {
			return fmt.Errorf("process %s does not exist", processId)
		}
	}

	return nil
}

func (m *mockServer) processExist(containerId, processId string) error {
	return m.checkExist(containerId, processId, false, true, false)
}

func (m *mockServer) processNonExist(containerId, processId string) error {
	return m.checkExist(containerId, processId, false, true, true)
}

func (m *mockServer) containerExist(containerId string) error {
	return m.checkExist(containerId, "", false, false, false)
}

func (m *mockServer) containerNonExist(containerId string) error {
	return m.checkExist(containerId, "", true, false, false)
}

func (m *mockServer) podExist() error {
	if m.pod == nil {
		return errors.New("pod not created")
	}
	return nil
}

func (m *mockServer) CreateContainer(ctx context.Context, req *pb.CreateContainerRequest) (*google_protobuf.Empty, error) {
	if err := m.containerNonExist(req.ContainerId); err != nil {
		return nil, err
	}

	if err := validateOCISpec(req.OCI); err != nil {
		return nil, err
	}

	c := &container{
		id:   req.ContainerId,
		proc: make(map[string]*process),
	}
	c.init = "init"
	p := &process{
		id:   c.init,
		proc: req.OCI.Process,
	}
	c.proc[c.init] = p
	m.pod.containers[req.ContainerId] = c

	return &google_protobuf.Empty{}, nil
}

func (m *mockServer) StartContainer(ctx context.Context, req *pb.StartContainerRequest) (*google_protobuf.Empty, error) {
	if err := m.containerNonExist(req.ContainerId); err != nil {
		return nil, err
	}

	return &google_protobuf.Empty{}, nil
}

func (m *mockServer) ExecProcess(ctx context.Context, req *pb.ExecProcessRequest) (*google_protobuf.Empty, error) {
	if err := m.processNonExist(req.ContainerId, req.ProcessId); err != nil {
		return nil, err
	}

	c := m.pod.containers[req.ContainerId]
	c.proc[req.ProcessId] = &process{
		id:   req.ProcessId,
		proc: req.Process,
	}
	return &google_protobuf.Empty{}, nil
}

func (m *mockServer) SignalProcess(ctx context.Context, req *pb.SignalProcessRequest) (*google_protobuf.Empty, error) {
	if err := m.processExist(req.ContainerId, req.ProcessId); err != nil {
		return nil, err
	}

	return &google_protobuf.Empty{}, nil
}

func (m *mockServer) WaitProcess(ctx context.Context, req *pb.WaitProcessRequest) (*pb.WaitProcessResponse, error) {
	if err := m.processExist(req.ContainerId, req.ProcessId); err != nil {
		return nil, err
	}

	// remove process once it is waited
	c := m.pod.containers[req.ContainerId]
	c.proc[req.ProcessId] = nil

	return &pb.WaitProcessResponse{Status: 0}, nil
}

func (m *mockServer) WriteStdin(ctx context.Context, req *pb.WriteStreamRequest) (*pb.WriteStreamResponse, error) {
	if err := m.processExist(req.ContainerId, req.ProcessId); err != nil {
		return nil, err
	}

	return &pb.WriteStreamResponse{Len: uint32(len(req.Data))}, nil
}

func (m *mockServer) ReadStdout(ctx context.Context, req *pb.ReadStreamRequest) (*pb.ReadStreamResponse, error) {
	if err := m.processExist(req.ContainerId, req.ProcessId); err != nil {
		return nil, err
	}

	return &pb.ReadStreamResponse{}, nil
}

func (m *mockServer) ReadStderr(ctx context.Context, req *pb.ReadStreamRequest) (*pb.ReadStreamResponse, error) {
	if err := m.processExist(req.ContainerId, req.ProcessId); err != nil {
		return nil, err
	}

	return &pb.ReadStreamResponse{}, nil
}

func (m *mockServer) CloseStdin(ctx context.Context, req *pb.CloseStdinRequest) (*google_protobuf.Empty, error) {
	if err := m.processExist(req.ContainerId, req.ProcessId); err != nil {
		return nil, err
	}

	return &google_protobuf.Empty{}, nil
}

func (m *mockServer) TtyWinResize(ctx context.Context, req *pb.TtyWinResizeRequest) (*google_protobuf.Empty, error) {
	if err := m.processExist(req.ContainerId, req.ProcessId); err != nil {
		return nil, err
	}

	return &google_protobuf.Empty{}, nil
}

func (m *mockServer) CreateSandbox(ctx context.Context, req *pb.CreateSandboxRequest) (*google_protobuf.Empty, error) {
	if m.pod != nil {
		return nil, errors.New("pod already created")
	}
	m.pod = &pod{
		containers: make(map[string]*container),
	}
	return &google_protobuf.Empty{}, nil
}

func (m *mockServer) DestroySandbox(ctx context.Context, req *pb.DestroySandboxRequest) (*google_protobuf.Empty, error) {
	if err := m.podExist(); err != nil {
		return nil, err
	}

	m.pod = nil
	return &google_protobuf.Empty{}, nil
}

func (m *mockServer) UpdateInterface(ctx context.Context, req *pb.UpdateInterfaceRequest) (*google_protobuf.Empty, error) {
	if err := m.podExist(); err != nil {
		return nil, err
	}

	return &google_protobuf.Empty{}, nil
}

func (m *mockServer) AddRoute(ctx context.Context, req *pb.AddRouteRequest) (*google_protobuf.Empty, error) {
	if err := m.podExist(); err != nil {
		return nil, err
	}

	return &google_protobuf.Empty{}, nil
}

func (m *mockServer) OnlineCPUMem(ctx context.Context, req *pb.OnlineCPUMemRequest) (*google_protobuf.Empty, error) {
	if err := m.podExist(); err != nil {
		return nil, err
	}

	return &google_protobuf.Empty{}, nil
}
