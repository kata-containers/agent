# Cpuset cgroup.

From Kernel documentation:

_" Cpusets provide a mechanism for assigning a set of CPUs and Memory Nodes to
a set of tasks."_

The Kata agent brings compatibility to the cgroup cpuset CPU on the guest side.

The cpuset CPU cgroup will be applied on two events:

- containers creation

- container update

When the runtime requests to apply cpuset cgroup to the agent, the amount of
vCPUs available might not be the same to the required vCPUs in the request.

This is because the request from the agent client (i.e. the Kata runtime)
passes cpusets that are requested to be placed on the host. This isolates the
container workload on some specific host CPUs. The runtime passes the requested
cpuset to the agent, which tries to apply the cgroup cpuset on the guest.

The runtime only calculates and hot-plugs the CPUs based on the container
period and quota. This is why the VM will not have the same amount of CPUs as
the host.

Example:

```sh
$ docker run -ti --cpus 2 --cpuset 0,1 busybox
```
 
This should result with the container limited to the time of 2 CPUs, but is
only allowed to be scheduled on CPUs 0 and 1.

The following is an example of a similar case with a valid traditional container:

```sh
$ docker run -ti --cpus 2 --cpuset 2,3,4 busybox
```

Here, the container is limited to 2 CPUs and can be scheduled on CPU 2, 3, and
4.

The Kata runtime only hotplugs 2 CPUs, making it impossible to request that the
guest kernel schedules the workload on vCPU 3 and 4.

## cpuset best effort application.

The Kata agent evaluates the request to see if it is possible to apply the
cpuset request onto the guest.

- If the CPUSs requested are not available in the guest, the request is ignored.
- If the CPUs requested are available, the request is applied by the agent.

