[![Build Status](https://travis-ci.org/kata-containers/agent.svg?branch=master)](https://travis-ci.org/kata-containers/agent)
[![codecov](https://codecov.io/gh/kata-containers/agent/branch/master/graph/badge.svg)](https://codecov.io/gh/kata-containers/agent)

# Kata Containers Agent

This project implements an agent called `kata-agent` that runs inside a virtual machine (VM).

The agent manages container processes inside the VM, on behalf of the
[runtime](https://github.com/kata-containers/runtime) running on the host.
