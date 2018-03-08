//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kata-containers/agent/pkg/uevent"
	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
)

const (
	driver9pType  = "9p"
	driverBlkType = "blk"
)

type deviceHandler func(device pb.Device, spec *pb.Spec) error

var deviceHandlerList = map[string]deviceHandler{
	driverBlkType: virtioBlkDeviceHandler,
}

func virtioBlkDeviceHandler(device pb.Device, spec *pb.Spec) error {
	// First need to make sure the expected device shows up properly,
	// and then we need to retrieve its device info (such as major and
	// minor numbers), useful to update the device provided
	// through the OCI specification.
	if err := waitForDevice(device.VmPath); err != nil {
		return err
	}

	// If no ContainerPath is provided, we won't be able to match and
	// update the device in the OCI spec device list. This is an error.
	if device.ContainerPath == "" {
		return grpcStatus.Errorf(codes.Internal,
			"ContainerPath cannot be empty")
	}

	// At this point in the code, we assume the specification will be
	// updated, meaning we should make sure we have valid pointers here.
	if spec.Linux == nil || len(spec.Linux.Devices) == 0 {
		return grpcStatus.Errorf(codes.Internal,
			"No devices found from the spec, cannot update")
	}

	stat := syscall.Stat_t{}
	if err := syscall.Stat(device.VmPath, &stat); err != nil {
		return err
	}

	dev := uint64(stat.Rdev)

	major := int64(unix.Major(dev))
	minor := int64(unix.Minor(dev))

	agentLog.WithFields(logrus.Fields{
		"device-path":  device.VmPath,
		"device-major": major,
		"device-minor": minor,
	}).Info("handling block device")

	// Update the spec
	updated := false
	for idx, d := range spec.Linux.Devices {
		if d.Path == device.ContainerPath {
			agentLog.WithFields(logrus.Fields{
				"device-path":        device.VmPath,
				"host-device-major":  spec.Linux.Devices[idx].Major,
				"host-device-minor":  spec.Linux.Devices[idx].Minor,
				"guest-device-major": major,
				"guest-device-minor": minor,
			}).Info("updating block device major/minor into the spec")
			spec.Linux.Devices[idx].Major = major
			spec.Linux.Devices[idx].Minor = minor
			updated = true
			break
		}
	}

	if !updated {
		return grpcStatus.Errorf(codes.Internal,
			"Should have found a matching device %s in the spec",
			device.VmPath)
	}

	return nil
}

func waitForDevice(devicePath string) error {
	deviceName := strings.TrimPrefix(devicePath, devPrefix)

	if _, err := os.Stat(devicePath); err == nil {
		return nil
	}

	uEvHandler, err := uevent.NewHandler()
	if err != nil {
		return err
	}
	defer uEvHandler.Close()

	fieldLogger := agentLog.WithField("device", deviceName)

	// Check if the device already exists.
	if _, err := os.Stat(devicePath); err == nil {
		fieldLogger.Info("Device already hotplugged, quit listening")
		return nil
	}

	fieldLogger.Info("Started listening for uevents for device hotplug")

	// Channel to signal when desired uevent has been received.
	done := make(chan bool)

	go func() {
		// This loop will be either ended if the hotplugged device is
		// found by listening to the netlink socket, or it will end
		// after the function returns and the uevent handler is closed.
		for {
			uEv, err := uEvHandler.Read()
			if err != nil {
				fieldLogger.Error(err)
				continue
			}

			fieldLogger = fieldLogger.WithFields(logrus.Fields{
				"uevent-action":    uEv.Action,
				"uevent-devpath":   uEv.DevPath,
				"uevent-subsystem": uEv.SubSystem,
				"uevent-seqnum":    uEv.SeqNum,
			})

			fieldLogger.Info("Got uevent")

			if uEv.Action == "add" &&
				filepath.Base(uEv.DevPath) == deviceName {
				fieldLogger.Info("Hotplug event received")
				break
			}
		}

		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Duration(timeoutHotplug) * time.Second):
		return grpcStatus.Errorf(codes.DeadlineExceeded,
			"Timeout reached after %ds waiting for device %s",
			timeoutHotplug, deviceName)
	}

	return nil
}

func addDevices(devices []*pb.Device, spec *pb.Spec) error {
	for _, device := range devices {
		if device == nil {
			continue
		}

		devHandler, ok := deviceHandlerList[device.Type]
		if !ok {
			return grpcStatus.Errorf(codes.InvalidArgument,
				"Unknown device type %q", device.Type)
		}

		if err := devHandler(*device, spec); err != nil {
			return err
		}
	}

	return nil
}
