// Copyright 2017 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitLogger(t *testing.T) {
	s := &sandbox{
		containers: make(map[string]*container),
		running:    false,
		subreaper: &reaper{
			exitCodeChans: make(map[int]chan int),
		},
	}
	err := s.initLogger()
	assert.Nil(t, err, "failed to sandbox initLogger: %s", err)
}
