//  Copyright (c) 2019 Intel Corporation
//
//  SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAvailableCpusetList(t *testing.T) {
	fakeGuestCpuset := "0-3"
	getCpusetGuest = func() (string, error) {
		return fakeGuestCpuset, nil
	}

	type testCase struct {
		input          string
		expectedOutput string
	}

	cases := []testCase{
		{"0", "0"},
		{"0,1", "0,1"},
		{"0,1,2", "0,1,2"},
		{"0,1,2,3", "0,1,2,3"},
		{"0,1,2,3,4", fakeGuestCpuset},
		{"0-3", "0-3"},
		{"0-3,4", fakeGuestCpuset},
		{"0-4", fakeGuestCpuset},
		{"1", "1"},
		{"1,3", "1,3"},
		{"2-3", "2-3"},
		{"2-4", fakeGuestCpuset},
	}

	for _, c := range cases {
		out, err := getAvailableCpusetList(c.input)
		assert.Nil(t, err, "Failed to calculate : %v", err)
		assert.Equal(t, out, c.expectedOutput)
	}
}
