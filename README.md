[![Build Status](https://travis-ci.org/kata-containers/agent.svg?branch=master)](https://travis-ci.org/kata-containers/agent)
[![codecov](https://codecov.io/gh/kata-containers/agent/branch/master/graph/badge.svg)](https://codecov.io/gh/kata-containers/agent)

# Kata Containers Agent

* [Debug mode](#debug-mode)
* [Developer mode](#developer-mode)
* [Enable trace support](#enable-trace-support)
* [Enable debug console](#enable-debug-console)
* [`cpuset` cgroup details](#cpuset-cgroup-details)

This project implements an agent called `kata-agent` that runs inside a virtual machine (VM).

The agent manages container processes inside the VM, on behalf of the
[runtime](https://github.com/kata-containers/runtime) running on the host.

## Debug mode

To enable agent debug output, add the `agent.log=debug` option to the guest kernel command line.

See the [developer guide](https://github.com/kata-containers/documentation/blob/master/Developer-Guide.md#enable-full-debug) for further details.

## Developer mode

Add `agent.devmode` to the guest kernel command line to allow the agent
process to coredump (disabled by default). Specifying this option implicitly
enables [debug mode](#debug-mode).

## Enable trace support

See [the tracing guide](TRACING.md).

## Enable debug console

Add `agent.debug_console` to the guest kernel command line to
allow the agent process to start a debug console. Debug console is only available if `bash`
or `sh` is installed in the rootfs or initrd image. Developers can [connect to the virtual
machine using the debug console](https://github.com/kata-containers/documentation/blob/master/Developer-Guide.md#connect-to-the-virtual-machine-using-the-debug-console)

## `cpuset` cgroup details

See the [cpuset cgroup documentation](documentation/features/cpuset.md).
