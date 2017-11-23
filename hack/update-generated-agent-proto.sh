#
# Copyright 2017 HyperHQ Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
protoc --proto_path=protocols/grpc --go_out=plugins=grpc:protocols/grpc protocols/grpc/hyperstart.proto protocols/grpc/oci.proto
