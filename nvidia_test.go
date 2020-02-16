//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"os/exec"
	"reflect"
	"testing"
)

func TestRunGetOutputLines(t *testing.T) {
	type args struct {
		cmd *exec.Cmd
	}
	tests := []struct {
		name            string
		args            args
		wantOutputLines []string
		wantErr         bool
	}{
		{
			name:            "successfulCase",
			args:            args{cmd: exec.Command("echo", "-e", "abc\ndef")},
			wantOutputLines: []string{"abc", "def"},
			wantErr:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOutputLines, err := runGetOutputLines(tt.args.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("runGetOutputLines() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOutputLines, tt.wantOutputLines) {
				t.Errorf("runGetOutputLines() gotOutputLines = %v, want %v", gotOutputLines, tt.wantOutputLines)
			}
		})
	}
}
