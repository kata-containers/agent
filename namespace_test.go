//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestSetupPersistentNs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test disabled as it requires root privileges")
	}

	ipcDirPath, err := ioutil.TempDir("", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(ipcDirPath)

	persistentNsDir = ipcDirPath
	ns, err := setupPersistentNs(nsTypeIPC)
	assert.Nil(t, err, "setupPersistentNs failed for IPC namespace: %v", err)

	assert.NotNil(t, ns.path, "Path empty for persistent IPC namespace")
	err = unix.Unmount(ns.path, unix.MNT_DETACH)
	if err != nil {
		t.Fatal(err)
	}

	utsDirPath, err := ioutil.TempDir("", "uts")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(utsDirPath)

	persistentNsDir = utsDirPath
	ns, err = setupPersistentNs(nsTypeUTS)
	assert.Nil(t, err, "setupPersistentNs failed for UTS namespace: %v", err)

	assert.NotNil(t, ns.path, "Path empty for persistent UTS namespace")
	err = unix.Unmount(ns.path, unix.MNT_DETACH)
	if err != nil {
		t.Fatal(err)
	}
}
