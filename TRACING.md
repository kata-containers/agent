# Agent Tracing

* [Introduction](#introduction)
* [OpenTracing summary](#opentracing-summary)
* [Jaeger tracing architecture](#jaeger-tracing-architecture)
* [Guest to Host communication using VSOCK](#guest-to-host-communication-using-vsock)
* [Agent tracing terminology](#agent-tracing-terminology)
    * [Trace modes](#trace-modes)
    * [Trace types](#trace-types)
* [Agent shutdown behaviour](#agent-shutdown-behaviour)
* [Enabling tracing](#enabling-tracing)
    * [Enabling dynamic tracing](#enabling-dynamic-tracing)
    * [Enabling static tracing](#enabling-static-tracing)
        * [Static tracing options](#static-tracing-options)
* [Running the agent with tracing enabled](#running-the-agent-with-tracing-enabled)
* [Requirements](#requirements)
    * [Host environment](#host-environment)
    * [Guest environment](#guest-environment)
* [Limitations](#limitations)
* [Appendix - Setting up a tracing development environment](#appendix---setting-up-a-tracing-development-environment)
    * [Set up a debug console](#set-up-a-debug-console)
    * [Guest journal redirector](#guest-journal-redirector)
    * [Enable full agent debug](#enable-full-agent-debug)

# Introduction

This document explains agent tracing, which uses 
the [Jaeger](https://jaegertracing.io) implementation of the [OpenTracing](http://opentracing.io) API.

# OpenTracing summary

An OpenTracing-enabled application creates trace "spans". A span must contain
the following attributes:

- A name
- A pair of timestamps (recording the start time and end time of some operation)
- A reference to the span's parent span

All spans need to be *finished*, or *completed*, to allow the OpenTracing
framework to generate the final trace information.

# Jaeger tracing architecture

The `kata-agent` makes use of the Jaeger
[golang client package](https://github.com/jaegertracing/jaeger-client-go/).

The Jaeger architecture means that the Jaeger client code running in the
application reports all span information to a Jaeger agent. This agent
forwards the information on to other components of a Jaeger system.

The Jaeger client package bound into the application sends the trace spans to
the Jaeger agent process using the UDP protocol. This is problematic since it
is not desirable to run a `jaeger-agent` process inside the Virtual Machine (VM):

- Adding extra binaries and an extra service to run the Jaeger agent inside
  the VM increases the size of the guest OS image used to
  create the VM. This is not desirable as the image should be as
  small as possible.

- Adding a Jaeger agent process into the VM would require
  special-case code for handling running the `kata-agent`
  [as the init daemon](https://github.com/kata-containers/osbuilder).

To avoid this complication, agent tracing uses a
[`VSOCK`](https://www.qemu.org/Features/VirtioVsock) communication channel to
allow the `kata-agent` to talk to the Jaeger agent running on the host system
("outside" the VM).

# Guest to Host communication using VSOCK

Since [Jaeger does not yet support VSOCK](https://github.com/jaegertracing/jaeger/issues/1019),
it is necessary to provide a way for the Jaeger client code (running inside the `kata-agent`
in the VM), to connect to the Jaeger agent (running on the host). The default
Jaeger port for such communications is
[UDP port `6831`](https://www.jaegertracing.io/docs/getting-started/).

The required redirection is a achieved using two instances of the `socat(1)` network utility:

- The first instance runs in the guest environment in the VM and forwards all
  Jaeger trace traffic out of the VM using a VSOCK socket.

- The second instance runs in the host environment and forwards all Jaeger
  traffic from the VSOCK socket to the Jaeger agent's UDP port.

Further details:

| Name | Type | Environment | Summary | Details | Explanation |
|-|-|-|-|-|-|
| `jaeger-client-socat-redirector.service` | systemd service | Guest | Guest `UDP:6831` to guest `VSOCK:6831` | Redirects data sent to UDP port `6831` to the host context `VSOCK` socket on port `6831`. | Service that intercepts all Jaeger calls the Kata agent makes and redirects them to the Jaeger agent running in the host environment. |
| `vsock-to-udp-server.sh` | shell script | Host | Host `VSOCK:6831` to host `UDP:6831` | Redirects all host context VSOCK data on port `6831` to the Jaeger agent, which is listening on UDP port `6831`. | Forwards all Jaeger agent calls redirected from the Kata agent to the Jaeger agent. |

> **Note:**
>
> This is a temporary solution until Jaeger supports VSOCK natively.

For tracing to work, the host system must have a Jaeger agent running.

# Agent tracing terminology

## Trace modes

The agent supports two different tracing modes:

| Trace mode | Description | Use-case | VM shutdown controller | Limitations |
|-|-|-|-|-|
| Static | Traces from agent start to agent shutdown. | Obtain holistic view of agent activities. | Agent | Requires systemd - see section [Agent shutdown behaviour](#agent-shutdown-behaviour). |
| Dynamic | Traces begin when the gRPC `StartTracing()` API is called and end when the corresponding `StopTracing()` API is called. | on-demand (partial) tracing. | Runtime | Only "isolated" type supported. |

## Trace types

Each trace mode is sub-divided into two different types:

| Trace type | Description | Use-case | Notes |
|-|-|-|-|
| isolated | The traces only apply to the agent; after the container has been destroyed, the first span will start at agent startup and the last at agent shutdown | Observing agent lifespan. | |
| collated | In this mode, spans are associated with their `kata-runtime` initiated counterparts. | Understanding how the runtime calls the agent. | Requires runtime tracing to be enabled in `configuration.toml` (`enable_tracing=true`). |

# Agent shutdown behaviour
 
As shown in the [trace modes](#trace-modes) section, the different trace modes
change how the VM is shutdown. In normal operation, the `kata-runtime` manages
the VM shutdown. The **only** scenario the agent itself is responsible for
VM shutdown is if static tracing is enabled. In this scenario, the
agent finishes the trace spans and actually exits. The systemd unit that
launches the `kata-agent` detects this and then runs the `ExecStop=` commands,
which shutdown the VM.

> **Note:** This implies that currently systemd is required for static
> tracing. However, it is not a hard requirement. The agent can be modified to
> invoke the `ExecStop=` commands itself to avoid relying on systemd to handle
> VM shutdown.

# Enabling tracing

## Enabling dynamic tracing

Call the gRPC `StartTracing()` API to start tracing and the corresponding `StopTracing()` API to stop tracing.

> **Note:** The dynamic tracing mode will always use an isolated type.

## Enabling static tracing

Static tracing is enabled by adding the `agent.trace` option in the
guest kernels command line.

### Static tracing options

Tracing support in the agent is either disabled, or set to one of the
following:

| Trace type | Trace setting |
|-|-|
| "isolated" | `agent.trace=isolated` (or just `agent.trace`) |
| "collated" | `agent.trace=collated` |

> **Note:**
>
> Agent tracing is separate from the tracing for other Kata Containers
> components. It is not necessary to enable runtime tracing if you want to
> enable agent tracing (or *vice versa*). However, "collated" mode only works
> as documented if runtime tracing is enabled.

# Running the agent with tracing enabled

1. Build a custom non-initrd image using
   [osbuilder](https://github.com/kata-containers/osbuilder).

   - The image **must** include:
     - The `jaeger-client-socat-redirector.service` systemd service
       (see the [Guest to Host communication using VSOCK](#guest-to-host-communication-using-vsock) section).

     - The distribution-specific package including the `socat(1)` utility
       (normally the package is called `socat`).

       The utility is required for the `jaeger-client-socat-redirector.service` service.

   - The image can include:
     - The `kata-journald-host-redirect.service` service.
       (see the [Guest to Host communication using VSOCK](#guest-to-host-communication-using-vsock) section).
     - The `kata-redirect-agent-output-to-journal.conf` systemd snippet
       (see the [Guest to Host communication using VSOCK](#guest-to-host-communication-using-vsock) section).

1. Install the custom image.

1. Configure the runtime to use the custom image by modifying the `image=`
   option in the runtime's `configuration.toml` file.

1. Configure the runtime to set the correct kernel parameters for agent tracing. See:

   - The [Enabling tracing](#enabling-tracing) section.

   - If you also want full debug and guest journal redirection, see the
     [Enable full agent debug](#enable-full-agent-debug) section.

1. Install and run Jaeger on the host.

   The simplest method to start using Jaeger is to follow the instructions to run the
   ["all-in-one" Docker\* image](https://www.jaegertracing.io/docs/1.8/getting-started/#all-in-one).

1. Start the VSOCK Jaeger redirector script on the host:

   ```
   $ sudo scripts/vsock-to-udp-server.sh
   ```

1. Start the journal redirector script on the host (OPTIONAL):

   ```
   $ sudo scripts/vsock-to-text-server.sh
   ```

1. Create a Kata Container.

1. Stop the Kata Container.

1. View the [Jaeger UI](https://www.jaegertracing.io/docs/getting-started).

# Requirements

## Host environment

- Host kernel must support the VSOCK socket type:

  kernel config option: `CONFIG_VHOST_VSOCK`.

- VSOCK kernel module must be loaded:

   ```
   $ sudo modprobe vhost_vsock
   ```

- VSOCK support must be enabled in the `kata-runtime`'s `configuration.toml`
  config file:

  ```
  $ sudo sed 's/#use_vsock =.*/use_vsock = true/g' /usr/share/defaults/kata-containers/configuration.toml
  ```

## Guest environment

- Guest kernel must support the VSOCK socket type:

  kernel config option: `CONFIG_VIRTIO_VSOCKETS`.

# Limitations

- The image configured in the `kata-runtime` `configuration.toml` file must
  be specified using `image=` (`initrd=` is not supported).

  This is because, currently, additional systemd services have to run inside
  the VM in order to proxy the Jaeger trace flows out to the Jaeger collector
  running on the host.

  See the
  [Guest to Host communication using VSOCK](#guest-to-host-communication-using-vsock)
  section for further details.

- Tracing is only completed when the workload and the `kata-agent` have exited 

  Although trace information *can* be inspected before the workload and agent
  have exited, it is incomplete. This is shown as `<trace-without-root-span>`
  in the Jaeger UI.

  If the workload is still running, the trace transaction -- which spans the entire
  runtime of the `kata-agent` -- will not have been completed. To view the complete
  trace details, first stop the Kata Container.

# Appendix - Setting up a tracing development environment

If you want to debug, further develop, or test tracing, use the following
steps.

## Set up a debug console

This allows direct shell access to the container.

See
[the developer guide](https://github.com/kata-containers/documentation/blob/master/Developer-Guide.md#set-up-a-debug-console)
for further details.

## Guest journal redirector

Since agent tracing requires VSOCK, and enabling VSOCK in `configuration.toml`
disables the `kata-proxy` (not required), the Kata Container has no way to
display the guest OS journal messages, which are normally redirected through
the proxy. This makes debugging difficult. To overcome this issue, create
another pair of `socat(1)` instances to redirect the guest OS journal entries
to a `socat(1)` instance running on the host:

| Name | Type | Environment | Summary | Details |
|-|-|-|-|-|
| `kata-journald-host-redirect.service` | systemd service | Guest | Guest `UDP:514` to host `VSOCK:5140` | Redirects data sent to the syslog port to a VSOCK socket port. |
| `kata-redirect-agent-output-to-journal.conf` | systemd snippet | Guest | Capture agent output | Redirects all agent output to the journal, required to observe agent output on host as no `kata-proxy` is running. |
| `vsock-to-udp-server.sh` | shell script | Host | Host `VSOCK:5140` to stdout | Redirects all host context VSOCK data on port `5140` to standard output for easy viewing. |

## Enable full agent debug

The usual
[full debug](https://github.com/kata-containers/documentation/blob/master/Developer-Guide.md#enable-full-debug)
options need to be supplemented with a few systemd(1) options for the journal
redirector to work:

```
kernel_params = "systemd.log_level=debug systemd.journald.forward_to_syslog=1 systemd.journald.forward_to_wall=0 systemd.journald.forward_to_console=0 systemd.log_target=journal ..."
```
