//
// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

/*
#cgo CFLAGS: -Wall
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define PAUSE_BIN "pause-bin"

void __attribute__((constructor)) sandbox_pause(void) {
	FILE *f;
	int len, do_pause = 0;
	size_t n = 0;
	char *p = NULL;

	f = fopen("/proc/self/cmdline", "r");
	if (f == NULL) {
		perror("failed to open proc");
		exit(-errno);
	}
	while ((len = getdelim(&p, &n, '\0', f)) != -1) {
		if (len == sizeof(PAUSE_BIN) && !strncmp(p, PAUSE_BIN, sizeof(PAUSE_BIN)-1)) {
			do_pause = 1;
			break;
		}
	}
	fclose(f);
	free(p);

	if (do_pause == 0)
		return;

	for (;;) pause();

	fprintf(stderr, "error: infinite loop terminated\n");
	exit(42);
}
*/
import "C"

const (
	pauseBinArg = string(C.PAUSE_BIN)
)
