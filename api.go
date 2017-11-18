//
// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

// Serial channel
const (
	serialChannelName = "agent.channel.0"
	virtIOPath        = "/sys/class/virtio-ports"
	devRootPath       = "/dev"
)

// VSock
const (
	vSockDevPath = "/dev/vsock"
	vSockPort    = 1024
)

// Global
const (
	exitSuccess  = 0
	exitFailure  = 1
	fileMode0750 = 0750
)
