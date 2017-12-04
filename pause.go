//
// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

/*
#cgo CFLAGS: -Wall
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAUSE_BIN "pause-bin"

static void sigdown(int signo) {
	psignal(signo, "shutting down, got signal");
	exit(0);
}

void __attribute__((constructor)) sandbox_pause(int argc, const char **argv) {
	if (argc != 2 || strcmp(argv[1], PAUSE_BIN)) {
		return;
	}

	if (signal(SIGINT, sigdown) == SIG_ERR)
		exit(1);

	if (signal(SIGTERM, sigdown) == SIG_ERR)
		exit(2);

	for (;;) pause();

	fprintf(stderr, "error: infinite loop terminated\n");
	exit(42);
}
*/
import "C"

const (
	pauseBinArg = string(C.PAUSE_BIN)
)
