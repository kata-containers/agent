#!/bin/bash
#
# Copyright (c) 2019 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

#---------------------------------------------------------------------
# Description: Redirect Jaeger trace traffic from the guest OS to the
#   Jaeger agent running on the local system.
#
# Notes:
#
# - Designed to be used for Kata Containers agent tracing.
# - Must be run *BEFORE* the Kata Container is created.
# - The "other side" of the VSOCK bridge (inside the virtual
#   machine) is handled by the jaeger-client-socat-redirector.service
#   service.
#---------------------------------------------------------------------

set -x

# Default Jaeger agent UDP port a Jaeger client should send trace traffic to.
#
# See:
#
# - https://jaegertracing.io/docs/getting-started
# - https://jaegertracing.io/docs/architecture
export jaeger_port=6831

# The horrid hex string below represents the VSOCK address with:
#
# - CID 2 (reserved for HOST)
# - port 6831
#
# This hex string is required to be passed to socat(1) since at the time of
# writing socat version 1.7.3.2 does not understand VSOCK sockets
# (but does provide this method to overcome this limitation).
#
# See:
#
# - https://gist.github.com/mcastelino/9a57d00ccf245b98de2129f0efe39857#using-specific-ports
# - http://www.dest-unreach.org/socat/doc/socat-genericsocket.html

export host_vsock_addr="x00x00xafx1ax00x00x02x00x00x00x00x00x00x00"

# Create vsock server that redirects all traffic to UDP:6831 ("jaeger-agent")
exec sudo socat -vx -u \
    "socket-listen:40:0:${host_vsock_addr},reuseaddr,fork" \
    "udp-connect:localhost:${jaeger_port}"
