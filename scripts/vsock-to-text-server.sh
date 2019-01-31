#!/bin/bash
#
# Copyright (c) 2019 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

#---------------------------------------------------------------------
# Description: Display guest OS system journal messages to
#   standard output.
#
# Notes:
#
# - Designed to be used for helping with debugging / development of
#   Kata Containers agent tracing.
# - Must be run *BEFORE* the Kata Container is created.
# - Assumes that a corresponding syslog -> VSOCK socat service will be started
#   inside the VM.
#---------------------------------------------------------------------

set -x

# The horrid hex string below represents the VSOCK address with:
#
# - CID 2 (reserved for HOST)
# - port 5140 (note: 514 is syslog)
#
# This hex string is required to be passed to socat(1) since at the time of
# writing socat version 1.7.3.2 does not understand VSOCK sockets
# (but does provide this method to overcome this limitation).
#
# See:
#
# - https://gist.github.com/mcastelino/9a57d00ccf245b98de2129f0efe39857#using-specific-ports
# - http://www.dest-unreach.org/socat/doc/socat-genericsocket.html

export host_vsock_addr="x00x00x14x14x00x00x02x00x00x00x00x00x00x00"

# Create vsock server that displays all syslog/journald log traffic from
# inside the guest VM.
exec sudo socat -u \
    "socket-listen:40:0:${host_vsock_addr},reuseaddr,fork" \
    "stdout"
