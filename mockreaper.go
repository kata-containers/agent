//
// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import "os/exec"

type mockreaper struct {
}

func (r *mockreaper) init() {
}

func (r *mockreaper) getExitCodeCh(pid int) (chan<- int, error) {
	return nil, nil
}

func (r *mockreaper) setExitCodeCh(pid int, exitCodeCh chan<- int) {
}

func (r *mockreaper) deleteExitCodeCh(pid int) {
}

func (r *mockreaper) reap() error {
	return nil
}

func (r *mockreaper) start(c *exec.Cmd) (<-chan int, error) {
	return nil, nil
}

func (r *mockreaper) wait(exitCodeCh <-chan int, proc waitProcess) (int, error) {
	return 0, nil
}

func (r *mockreaper) lock() {
}

func (r *mockreaper) unlock() {
}
