#
# Copyright 2017 HyperHQ Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
protoc -I $GOPATH/src/ --proto_path=protocols/grpc:/usr/local/include --gogo_out=plugins=grpc:protocols/grpc protocols/grpc/agent.proto protocols/grpc/oci.proto
