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

# docker version may need to be upgraded to let make proto go on arm64
arch=$(go env GOARCH)
if [ "$arch" == "arm64" ]; then
	"../agent/.ci/run_arm64.sh"
fi

echo "Starting docker service before making proto"
sudo systemctl start docker

"${testcidir}/../cmd/container-manager/manage_ctr_mgr.sh" docker configure -r runc -f
popd
make proto
