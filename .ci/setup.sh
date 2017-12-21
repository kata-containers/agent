#!/bin/bash
#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

test_repo="github.com/clearcontainers/tests"

# Clone Tests repository.
go get "$test_repo"

test_repo_dir="${GOPATH}/src/${test_repo}"

# Check the commits in the branch
checkcommits_dir="${test_repo_dir}/cmd/checkcommits"
(cd "${checkcommits_dir}" && make)
checkcommits \
	--need-fixes \
	--need-sign-offs \
	--verbose
