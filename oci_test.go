//
// Copyright (c) 2018 NVIDIA CORPORATION
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
)

func TestChangeToBundlePath(t *testing.T) {
	assert := assert.New(t)

	originalCwd, err := os.Getwd()
	assert.NoError(err)
	defer os.Chdir(originalCwd)

	bundlePath, err := ioutil.TempDir("", "bundle")
	assert.NoError(err)
	defer os.RemoveAll(bundlePath)

	rootfsPath := path.Join(bundlePath, "rootfs")
	err = os.Mkdir(rootfsPath, 0750)
	assert.NoError(err)

	spec := &specs.Spec{}
	spec.Root = &specs.Root{
		Path:     "",
		Readonly: false,
	}

	_, err = changeToBundlePath(spec)
	assert.Error(err)

	// Write the spec file to create a valid OCI bundle
	spec.Root.Path = rootfsPath
	err = writeSpecToFile(spec)
	assert.NoError(err)

	cwd, err := changeToBundlePath(spec)
	assert.NoError(err)
	assert.Equal(cwd, originalCwd)

	cwd, err = os.Getwd()
	assert.NoError(err)
	assert.Equal(bundlePath, cwd)
}

func TestWriteSpecToFile(t *testing.T) {
	assert := assert.New(t)

	bundlePath, err := ioutil.TempDir("", "bundle")
	assert.NoError(err)
	defer os.RemoveAll(bundlePath)

	originalCwd, err := os.Getwd()
	assert.NoError(err)
	defer os.Chdir(originalCwd)

	err = os.Chdir(bundlePath)
	assert.NoError(err)

	rootfsPath := path.Join(bundlePath, "rootfs")
	spec := &specs.Spec{
		Root: &specs.Root{
			Path:     rootfsPath,
			Readonly: false,
		},
	}
	err = writeSpecToFile(spec)
	assert.NoError(err)

	file, err := os.Open(path.Join(bundlePath, ociConfigFile))
	assert.NoError(err)
	defer file.Close()

	stat, err := file.Stat()
	assert.NoError(err)

	assert.True(stat.Size() > 0)
}
