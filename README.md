[![Build Status](https://travis-ci.org/kata-containers/agent.svg?branch=master)](https://travis-ci.org/kata-containers/agent)
[![codecov](https://codecov.io/gh/kata-containers/agent/branch/master/graph/badge.svg)](https://codecov.io/gh/kata-containers/agent)

# Kata Containers Agent

* [Debug mode](#debug-mode)
* [Developer mode](#developer-mode)
* [Enable trace support](#enable-trace-support)
* [Enable debug console](#enable-debug-console)
* [`cpuset` cgroup details](#cpuset-cgroup-details)
* [Hotplug Timeout](#hotplug-timeout)
* [Cgroups V2](#cgroups-v2)

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

### Enable debug console for firecracker

Firecracker doesn't have a UNIX socket connected to `/dev/console`, hence the
kernel command line option `agent.debug_console` will not work for firecracker.
Fortunately, firecracker supports [`hybrid vsocks`][1], and they can be used to
communicate processes in the guest with processes in the host.
The kernel command line option `agent.debug_console_vport` was added to allow
developers specify on which `vsock` port the debugging console should be connected.

In firecracker, the UNIX socket that is connected to the `vsock` end is created at
`/var/lib/vc/firecracker/$CID/root/kata.hvsock`, where `$CID` is the container ID.

Run the following commands to have a debugging console in firecracker.

```sh
$ conf="/usr/share/defaults/kata-containers/configuration.toml"
$ sudo sed -i 's/^kernel_params.*/kernel_params="agent.debug_console_vport=1026"/g' "${conf}"
$ sudo su -c 'cd /var/lib/vc/firecracker/08facf/root/ && socat stdin unix-connect:kata.hvsock'
CONNECT 1026
```

**NOTE:** Ports 1024 and 1025 are reserved for communication with the agent and gathering of agent logs respectively

## `cpuset` cgroup details

See the [cpuset cgroup documentation](documentation/features/cpuset.md).

## Hotplug Timeout

When hot plugging devices into the Kata VM, the agent will wait by default for 3 seconds
for the device to be plugged in and the corresponding add uevent for the device. If the timeout
is reached without the above happening, the hot plug action will fail.

The length of the timeout can be increased by specifying the `agent.hotplug_timeout` to the guest
kernel command line. For example, `agent.hotplug_timeout=10s` will increase the timeout to 10 seconds.
The value of the option is in the [Go duration format][2].

Any invalid values used for `agent.hotplug_timeout` will fall back to the default of 3 seconds.

## Cgroups V2

Same as `systemd`, the `kata-agent` has an option to enable or disable the unified
cgroup hierarchy (cgroups v2) in the guest through the kernel command line.
Set `agent.unified_cgroup_hierarchy` to `1` or `true` to enable cgroups v2. For
example, `agent.unified_cgroup_hierarchy=true` will enable cgroups v2 in the guest.
Set `agent.unified_cgroup_hierarchy` to `0` or `false` to disable cgroups v2. For
example, `agent.unified_cgroup_hierarchy=0` will disable cgroups v2 in the guest.
By default cgroups v2 is disabled.

## Container Pipe Size

The agent will configure a [Pipe][3] for stdio (stdout, stderr, stdin) for each container. By default,
this will use the OS' defaults in terms of pipe capacity. However, some workloads may require a larger pipe 
when writing to stdout/stderr in non-blocking mode.

The pipe's capacity for stdout/stderr can be modified by specifying the `agent.container_pipe_size` flag
to the guest kernel command line. For example, `agent.container_pipe_size=2097152` will set the stdout and stderr
pipes to 2097152 bytes.

[1]: https://github.com/firecracker-microvm/firecracker/blob/master/docs/vsock.md
[2]: https://golang.org/pkg/time/#ParseDuration
[3]: http://man7.org/linux/man-pages/man7/pipe.7.html
