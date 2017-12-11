## Copyright 2017 HyperHQ Inc.
##
## SPDX-License-Identifier: Apache-2.0
##

set -e
test_dirs=$(go list ./... | grep -v vendor)
for testdir in ${test_dirs}; do
    echo start testing $testdir
    go test -v $testdir
done
set +e
