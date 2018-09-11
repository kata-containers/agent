#!/bin/bash
#
# Copyright (c) 2018 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

cidir=$(dirname "$0")
source "${cidir}/lib.sh"

pushd "${tests_repo_dir}"
.ci/run.sh
testcidir=$(dirname "$0")
"${testcidir}/../cmd/container-manager/manage_ctr_mgr.sh" docker configure -r runc -f
popd
make proto
