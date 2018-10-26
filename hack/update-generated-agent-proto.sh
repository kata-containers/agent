#
# Copyright 2017 HyperHQ Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

protoc \
	pkg/types/types.proto --gogofast_out=.

protoc \
	-I=$GOPATH/src \
	-I=$GOPATH/src/github.com/gogo/protobuf/protobuf \
	--proto_path=protocols/grpc \
	--gogofast_out=\
Mgithub.com/kata-containers/agent/pkg/types/types.proto=github.com/kata-containers/agent/pkg/types,\
Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/duration.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/struct.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/wrappers.proto=github.com/gogo/protobuf/types,\
Mgoogle/protobuf/empty.proto=github.com/gogo/protobuf/types,\
plugins=grpc:protocols/grpc \
	protocols/grpc/*.proto
