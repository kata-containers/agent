[![Build Status](https://travis-ci.org/kata-containers/agent.svg?branch=master)](https://travis-ci.org/kata-containers/agent)
[![codecov](https://codecov.io/gh/kata-containers/agent/branch/master/graph/badge.svg)](https://codecov.io/gh/kata-containers/agent)

# Kata Containers Agent

* [Debug mode](#debug-mode)

This project implements an agent called `kata-agent` that runs inside a virtual machine (VM).

The agent manages container processes inside the VM, on behalf of the
[runtime](https://github.com/kata-containers/runtime) running on the host.

## Debug mode

To enable agent debug output, add the `agent.log=debug` option to the guest kernel command line.

See the [developer guide](https://github.com/kata-containers/documentation/blob/master/Developer-Guide.md#enable-full-debug) for further details.
