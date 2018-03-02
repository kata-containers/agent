//
// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	pb "github.com/kata-containers/agent/protocols/grpc"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
)

const (
	type9pFs       = "9p"
	devPrefix      = "/dev/"
	timeoutHotplug = 3
	mountPerm      = os.FileMode(0755)
)

var flagList = map[string]int{
	"acl":         unix.MS_POSIXACL,
	"bind":        unix.MS_BIND,
	"defaults":    0,
	"dirsync":     unix.MS_DIRSYNC,
	"iversion":    unix.MS_I_VERSION,
	"lazytime":    unix.MS_LAZYTIME,
	"mand":        unix.MS_MANDLOCK,
	"noatime":     unix.MS_NOATIME,
	"nodev":       unix.MS_NODEV,
	"nodiratime":  unix.MS_NODIRATIME,
	"noexec":      unix.MS_NOEXEC,
	"nosuid":      unix.MS_NOSUID,
	"rbind":       unix.MS_BIND | unix.MS_REC,
	"relatime":    unix.MS_RELATIME,
	"remount":     unix.MS_REMOUNT,
	"ro":          unix.MS_RDONLY,
	"silent":      unix.MS_SILENT,
	"strictatime": unix.MS_STRICTATIME,
	"sync":        unix.MS_SYNCHRONOUS,
	"private":     unix.MS_PRIVATE,
	"shared":      unix.MS_SHARED,
	"slave":       unix.MS_SLAVE,
	"unbindable":  unix.MS_UNBINDABLE,
	"rprivate":    unix.MS_PRIVATE | unix.MS_REC,
	"rshared":     unix.MS_SHARED | unix.MS_REC,
	"rslave":      unix.MS_SLAVE | unix.MS_REC,
	"runbindable": unix.MS_UNBINDABLE | unix.MS_REC,
}

func createDestinationDir(dest string) error {
	targetPath, _ := filepath.Split(dest)

	return os.MkdirAll(targetPath, mountPerm)
}

// mount mounts a source in to a destination. This will do some bookkeeping:
// * evaluate all symlinks
// * ensure the source exists
func mount(source, destination, fsType string, flags int, options string) error {
	var absSource string

	if fsType != type9pFs {
		var err error

		absSource, err = filepath.EvalSymlinks(source)
		if err != nil {
			return grpcStatus.Errorf(codes.Internal, "Could not resolve symlink for source %v", source)
		}

		if err := ensureDestinationExists(absSource, destination, fsType); err != nil {
			return grpcStatus.Errorf(codes.Internal, "Could not create destination mount point: %v: %v",
				destination, err)
		}
	} else {
		if err := createDestinationDir(destination); err != nil {
			return err
		}
		absSource = source
	}

	if err := syscall.Mount(absSource, destination,
		fsType, uintptr(flags), options); err != nil {
		return grpcStatus.Errorf(codes.Internal, "Could not bind mount %v to %v: %v",
			absSource, destination, err)
	}

	return nil
}

// ensureDestinationExists will recursively create a given mountpoint. If directories
// are created, their permissions are initialized to mountPerm
func ensureDestinationExists(source, destination string, fsType string) error {
	fileInfo, err := os.Stat(source)
	if err != nil {
		return grpcStatus.Errorf(codes.Internal, "could not stat source location: %v",
			source)
	}

	if err := createDestinationDir(destination); err != nil {
		return grpcStatus.Errorf(codes.Internal, "could not create parent directory: %v",
			destination)
	}

	if fsType != "bind" || fileInfo.IsDir() {
		if err := os.Mkdir(destination, mountPerm); !os.IsExist(err) {
			return err
		}
	} else {
		file, err := os.OpenFile(destination, os.O_CREATE, mountPerm)
		if err != nil {
			return err
		}

		file.Close()
	}
	return nil
}

func parseMountFlagsAndOptions(optionList []string) (int, string, error) {
	var (
		flags   int
		options []string
	)

	for _, opt := range optionList {
		flag, ok := flagList[opt]
		if ok {
			flags |= flag
			continue
		}

		options = append(options, opt)
	}

	return flags, strings.Join(options, ","), nil
}

func addMounts(mounts []*pb.Storage) ([]string, error) {
	var mountList []string

	for _, mnt := range mounts {
		if mnt == nil {
			continue
		}

		flags, options, err := parseMountFlagsAndOptions(mnt.Options)
		if err != nil {
			return nil, err
		}

		if err := mount(mnt.Source, mnt.MountPoint, mnt.Fstype,
			flags, options); err != nil {
			return nil, err
		}

		// Prepend mount point to mount list.
		mountList = append([]string{mnt.MountPoint}, mountList...)
	}

	return mountList, nil
}

func removeMounts(mounts []string) error {
	for _, mount := range mounts {
		if err := syscall.Unmount(mount, 0); err != nil {
			return err
		}
	}

	return nil
}
