//
// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/kata-containers/agent/pkg/uevent"
	pb "github.com/kata-containers/agent/protocols/grpc"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/configs"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
)

const meminfo = "/proc/meminfo"

type process struct {
	id          string
	process     libcontainer.Process
	stdin       *os.File
	stdout      *os.File
	stderr      *os.File
	consoleSock *os.File
	termMaster  *os.File
	exitCodeCh  chan int
}

type container struct {
	sync.RWMutex

	id          string
	initProcess *process
	container   libcontainer.Container
	config      configs.Config
	processes   map[string]*process
	mounts      []string
}

type sandbox struct {
	sync.RWMutex

	id              string
	running         bool
	noPivotRoot     bool
	enableGrpcTrace bool
	containers      map[string]*container
	channel         channel
	network         network
	wg              sync.WaitGroup
	sharedPidNs     namespace
	mounts          []string
	subreaper       reaper
	server          *grpc.Server
	pciDeviceMap    map[string]string
	deviceWatchers  map[string](chan string)
}

type namespace struct {
	path       string
	init       *os.Process
	exitCodeCh <-chan int
}

var agentFields = logrus.Fields{
	"name":   agentName,
	"pid":    os.Getpid(),
	"source": "agent",
}

var agentLog = logrus.WithFields(agentFields)

// version is the agent version. This variable is populated at build time.
var version = "unknown"

// This is the list of file descriptors we can properly close after the process
// has been started. When the new process is exec(), those file descriptors are
// duplicated and it is our responsibility to close them since we have opened
// them.
func (p *process) closePostStartFDs() {
	if p.process.Stdin != nil {
		p.process.Stdin.(*os.File).Close()
	}

	if p.process.Stdout != nil {
		p.process.Stdout.(*os.File).Close()
	}

	if p.process.Stderr != nil {
		p.process.Stderr.(*os.File).Close()
	}

	if p.process.ConsoleSocket != nil {
		p.process.ConsoleSocket.Close()
	}

	if p.consoleSock != nil {
		p.consoleSock.Close()
	}
}

// This is the list of file descriptors we can properly close after the process
// has exited. These are the remaining file descriptors that we have opened and
// are no longer needed.
func (p *process) closePostExitFDs() {
	if p.termMaster != nil {
		p.termMaster.Close()
	}

	if p.stdin != nil {
		p.stdin.Close()
	}

	if p.stdout != nil {
		p.stdout.Close()
	}

	if p.stderr != nil {
		p.stderr.Close()
	}
}

func (c *container) setProcess(process *process) {
	c.Lock()
	c.processes[process.id] = process
	c.Unlock()
}

func (c *container) deleteProcess(execID string) {
	c.Lock()
	delete(c.processes, execID)
	c.Unlock()
}

func (c *container) removeContainer() error {
	// This will terminates all processes related to this container, and
	// destroy the container right after. But this will error in case the
	// container in not in the right state.
	if err := c.container.Destroy(); err != nil {
		return err
	}

	return removeMounts(c.mounts)
}

func (c *container) getProcess(execID string) (*process, error) {
	c.RLock()
	defer c.RUnlock()

	proc, exist := c.processes[execID]
	if !exist {
		return nil, grpcStatus.Errorf(codes.NotFound, "Process %s not found (container %s)", execID, c.id)
	}

	return proc, nil
}

func (s *sandbox) getContainer(id string) (*container, error) {
	s.RLock()
	defer s.RUnlock()

	ctr, exist := s.containers[id]
	if !exist {
		return nil, grpcStatus.Errorf(codes.NotFound, "Container %s not found", id)
	}

	return ctr, nil
}

func (s *sandbox) setContainer(id string, ctr *container) {
	s.Lock()
	s.containers[id] = ctr
	s.Unlock()
}

func (s *sandbox) deleteContainer(id string) {
	s.Lock()
	delete(s.containers, id)
	s.Unlock()
}

func (s *sandbox) getProcess(cid, execID string) (*process, *container, error) {
	if s.running == false {
		return nil, nil, grpcStatus.Error(codes.FailedPrecondition, "Sandbox not started")
	}

	ctr, err := s.getContainer(cid)
	if err != nil {
		return nil, nil, err
	}

	// A container being in stopped state is not a valid reason for not
	// accepting a call to getProcess(). Indeed, we want to make sure a
	// shim can connect after the process has already terminated. Some
	// processes have a very short lifetime and the shim might end up
	// calling into WaitProcess() after this happened. This does not mean
	// we cannot retrieve the output and the exit code from the shim.
	proc, err := ctr.getProcess(execID)
	if err != nil {
		return nil, nil, err
	}

	return proc, ctr, nil
}

func (s *sandbox) readStdio(cid, execID string, length int, stdout bool) ([]byte, error) {
	proc, _, err := s.getProcess(cid, execID)
	if err != nil {
		return nil, err
	}

	var file *os.File
	if proc.termMaster != nil {
		file = proc.termMaster
	} else {
		if stdout {
			file = proc.stdout
		} else {
			file = proc.stderr
		}
	}

	buf := make([]byte, length)

	bytesRead, err := file.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:bytesRead], nil
}

// setupSharedPidNs will reexec this binary in order to execute the C routine
// defined into pause.go file. The pauseBinArg is very important since that is
// the flag allowing the C function to determine it should run the "pause".
// This pause binary will ensure that we always have the init process of the
// new PID namespace running into the namespace, preventing the namespace to
// be destroyed if other processes are terminated.
func (s *sandbox) setupSharedPidNs() error {
	cmd := &exec.Cmd{
		Path: selfBinPath,
		Args: []string{os.Args[0], pauseBinArg},
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID,
	}

	exitCodeCh, err := s.subreaper.start(cmd)
	if err != nil {
		return err
	}

	// Save info about this namespace inside sandbox structure.
	s.sharedPidNs = namespace{
		path:       fmt.Sprintf("/proc/%d/ns/pid", cmd.Process.Pid),
		init:       cmd.Process,
		exitCodeCh: exitCodeCh,
	}

	return nil
}

func (s *sandbox) teardownSharedPidNs() error {
	if s.sharedPidNs.path == "" {
		// Nothing needs to be done because we are not in a case
		// where a PID namespace is shared across containers.
		return nil
	}

	// Terminates the "init" process of the PID namespace.
	if err := s.sharedPidNs.init.Kill(); err != nil {
		return err
	}

	// Using helper function wait() to deal with the subreaper.
	osProcess := (*reaperOSProcess)(s.sharedPidNs.init)
	if _, err := s.subreaper.wait(s.sharedPidNs.exitCodeCh, osProcess); err != nil {
		return err
	}

	// Empty the sandbox structure.
	s.sharedPidNs = namespace{}

	return nil
}

func (s *sandbox) listenToUdevEvents() {
	fieldLogger := agentLog.WithField("subsystem", "udevlistener")

	uEvHandler, err := uevent.NewHandler()
	if err != nil {
		fieldLogger.Warnf("Error starting uevent listening loop %s", err)
		return
	}
	defer uEvHandler.Close()

	for {
		uEv, err := uEvHandler.Read()
		if err != nil {
			fieldLogger.Error(err)
			continue
		}

		fieldLogger = fieldLogger.WithFields(logrus.Fields{
			"uevent-action":    uEv.Action,
			"uevent-devpath":   uEv.DevPath,
			"uevent-subsystem": uEv.SubSystem,
			"uevent-seqnum":    uEv.SeqNum,
			"uevent-devname":   uEv.DevName,
		})

		// Check if device hotplug event results in a device node being created.
		if uEv.DevName != "" && uEv.Action == "add" && strings.HasPrefix(uEv.DevPath, rootBusPath) {
			// Lock is needed to safey read and modify the pciDeviceMap and deviceWatchers.
			// This makes sure that watchers do not access the map while it is being updated.
			s.Lock()

			// Add the device node name to the pci device map.
			s.pciDeviceMap[uEv.DevPath] = uEv.DevName

			// Notify watchers that are interested in the udev event.
			// Close the channel after watcher has been notified.
			for devPCIAddress, ch := range s.deviceWatchers {
				if ch != nil && strings.HasPrefix(uEv.DevPath, filepath.Join(rootBusPath, devPCIAddress)) {
					ch <- uEv.DevName
					close(ch)
					delete(s.deviceWatchers, uEv.DevName)
				}
			}

			s.Unlock()
		}
	}
}

// This loop is meant to be run inside a separate Go routine.
func (s *sandbox) signalHandlerLoop(sigCh chan os.Signal) {
	for sig := range sigCh {
		logger := agentLog.WithField("signal", sig)

		switch sig {
		case unix.SIGCHLD:
			if err := s.subreaper.reap(); err != nil {
				logger.WithError(err).Error("failed to reap")
				return
			}
		default:
			logger.Info("ignoring unexpected signal")
		}
	}
}

func (s *sandbox) setupSignalHandler() error {
	// Set agent as subreaper
	err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(1), 0, 0, 0)
	if err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 512)
	signal.Notify(sigCh, unix.SIGCHLD)

	go s.signalHandlerLoop(sigCh)

	return nil
}

// getMemory returns a string containing the total amount of memory reported
// by the kernel. The string includes a suffix denoting the units the memory
// is measured in.
func getMemory() (string, error) {
	bytes, err := ioutil.ReadFile(meminfo)
	if err != nil {
		return "", err
	}

	lines := string(bytes)

	for _, line := range strings.Split(lines, "\n") {
		if !strings.HasPrefix(line, "MemTotal") {
			continue
		}

		expectedFields := 2

		fields := strings.Split(line, ":")
		count := len(fields)

		if count != expectedFields {
			return "", fmt.Errorf("expected %d fields, got %d in line %q", expectedFields, count, line)
		}

		if fields[1] == "" {
			return "", fmt.Errorf("cannot determine total memory from line %q", line)
		}

		memTotal := strings.TrimSpace(fields[1])

		return memTotal, nil
	}

	return "", fmt.Errorf("no lines in file %q", meminfo)
}

func getAnnounceFields() (logrus.Fields, error) {
	var deviceHandlers []string
	var storageHandlers []string

	for handler := range deviceHandlerList {
		deviceHandlers = append(deviceHandlers, handler)
	}

	for handler := range storageHandlerList {
		storageHandlers = append(storageHandlers, handler)
	}

	memTotal, err := getMemory()
	if err != nil {
		return logrus.Fields{}, err
	}

	return logrus.Fields{
		"version":          version,
		"device-handlers":  strings.Join(deviceHandlers, ","),
		"storage-handlers": strings.Join(storageHandlers, ","),
		"system-memory":    memTotal,
	}, nil
}

// announce logs details of the agents version and capabilities.
func announce() error {
	announceFields, err := getAnnounceFields()
	if err != nil {
		return err
	}

	if os.Getpid() == 1 {
		var values []string

		for k, v := range agentFields {
			values = append(values, fmt.Sprintf("%s=%q", k, v))
		}

		for k, v := range announceFields {
			values = append(values, fmt.Sprintf("%s=%q", k, v))
		}

		fmt.Printf("announce: %s\n", strings.Join(values, ","))
	} else {
		agentLog.WithFields(announceFields).Info("announce")
	}

	return nil
}

func (s *sandbox) initLogger() error {
	agentLog.Logger.Formatter = &logrus.TextFormatter{DisableColors: true, TimestampFormat: time.RFC3339Nano}

	config := newConfig(defaultLogLevel)
	if err := config.getConfig(kernelCmdlineFile); err != nil {
		agentLog.WithError(err).Warn("Failed to get config from kernel cmdline")
	}
	config.applyConfig(s)

	return announce()
}

func (s *sandbox) initChannel() error {
	c, err := newChannel()
	if err != nil {
		return err
	}

	s.channel = c

	return nil
}

func grpcTracer(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	message := req.(proto.Message)
	agentLog.WithFields(logrus.Fields{
		"request": info.FullMethod,
		"req":     message.String()}).Debug("new request")

	start := time.Now()
	resp, err = handler(ctx, req)
	elapsed := time.Now().Sub(start)

	message = resp.(proto.Message)
	logger := agentLog.WithFields(logrus.Fields{
		"request":  info.FullMethod,
		"duration": elapsed.String(),
		"resp":     message.String()})
	if err != nil {
		logger = logger.WithError(err)
	}
	logger.Debug("request end")

	return resp, err
}

func (s *sandbox) startGRPC() {
	grpcImpl := &agentGRPC{
		sandbox: s,
		version: version,
	}

	var grpcServer *grpc.Server
	if s.enableGrpcTrace {
		agentLog.Info("Enable grpc tracing")
		opt := grpc.UnaryInterceptor(grpcTracer)
		grpcServer = grpc.NewServer(opt)
	} else {
		grpcServer = grpc.NewServer()
	}

	pb.RegisterAgentServiceServer(grpcServer, grpcImpl)
	pb.RegisterHealthServer(grpcServer, grpcImpl)
	s.server = grpcServer

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		var err error
		for err == nil || err == io.EOF {
			agentLog.Info("agent grpc server starts")

			err = s.channel.setup()
			if err != nil {
				agentLog.WithError(err).Warn("Failed to setup agent grpc channel")
				return
			}

			err = s.channel.wait()
			if err != nil {
				agentLog.WithError(err).Warn("Failed to wait agent grpc channel ready")
				return
			}

			var l net.Listener
			l, err = s.channel.listen()
			if err != nil {
				agentLog.WithError(err).Warn("Failed to create agent grpc listener")
				return
			}

			// l is closed when Serve() returns
			err = grpcServer.Serve(l)
			if err != nil {
				agentLog.WithError(err).Warn("agent grpc server quits")
			}

			errT := s.channel.teardown()
			if errT != nil {
				agentLog.WithError(errT).Warn("agent grpc channel teardown failed")
			}
		}
	}()
}

func (s *sandbox) stopGRPC() {
	if s.server != nil {
		s.server.Stop()
		s.server = nil
	}
}

type initMount struct {
	fstype, src, dest string
	options           []string
}

var initRootfsMounts = []initMount{
	{"proc", "proc", "/proc", []string{"nosuid", "nodev", "noexec"}},
	{"sysfs", "sysfs", "/sys", []string{"nosuid", "nodev", "noexec"}},
	{"devtmpfs", "dev", "/dev", []string{"nosuid"}},
	{"tmpfs", "tmpfs", "/dev/shm", []string{"nosuid", "nodev"}},
	{"devpts", "devpts", "/dev/pts", []string{"nosuid", "noexec"}},
	// mounts for cgroup, copied from rh7
	{"tmpfs", "tmpfs", "/sys/fs/cgroup", []string{"nosuid", "nodev", "noexec", "mode=755"}},
	{"cgroup", "cgroup", "/sys/fs/cgroup/devices", []string{"nosuid", "nodev", "noexec", "relatime", "devices"}},
	{"cgroup", "cgroup", "/sys/fs/cgroup/cpu,cpuacct", []string{"nosuid", "nodev", "noexec", "relatime", "cpuacct", "cpu"}},
	{"cgroup", "cgroup", "/sys/fs/cgroup/pids", []string{"nosuid", "nodev", "noexec", "relatime", "pids"}},
	{"cgroup", "cgroup", "/sys/fs/cgroup/net_cls,net_prio", []string{"nosuid", "nodev", "noexec", "relatime", "net_prio", "net_cls"}},
	{"cgroup", "cgroup", "/sys/fs/cgroup/blkio", []string{"nosuid", "nodev", "noexec", "relatime", "blkio"}},
	{"cgroup", "cgroup", "/sys/fs/cgroup/freezer", []string{"nosuid", "nodev", "noexec", "relatime", "freezer"}},
	{"cgroup", "cgroup", "/sys/fs/cgroup/cpuset", []string{"nosuid", "nodev", "noexec", "relatime", "cpuset"}},
	{"cgroup", "cgroup", "/sys/fs/cgroup/memory", []string{"nosuid", "nodev", "noexec", "relatime", "memory"}},
	{"cgroup", "cgroup", "/sys/fs/cgroup/perf_event", []string{"nosuid", "nodev", "noexec", "relatime", "perf_event"}},
	//{"cgroup", "cgroup", "/sys/fs/cgroup/hugetlb", []string{"nosuid", "nodev", "noexec", "relatime", "hugetlb"}},
	{"bind", "/sys/fs/cgroup/cpu,cpuacct", "/sys/fs/cgroup/cpu", []string{"bind"}},
	{"bind", "/sys/fs/cgroup/cpu,cpuacct", "/sys/fs/cgroup/cpuacct", []string{"bind"}},
	{"bind", "/sys/fs/cgroup/net_cls,net_prio", "/sys/fs/cgroup/net_cls", []string{"bind"}},
	{"bind", "/sys/fs/cgroup/net_cls,net_prio", "/sys/fs/cgroup/net_prio", []string{"bind"}},
	{"tmpfs", "tmpfs", "/sys/fs/cgroup", []string{"remount", "ro", "nosuid", "nodev", "noexec", "mode=755"}},
}

// initAgentAsInit will do the initializations such as setting up the rootfs
// when this agent has been run as the init process.
func initAgentAsInit() error {
	for _, m := range initRootfsMounts {
		if err := os.MkdirAll(m.dest, os.FileMode(0755)); err != nil {
			return err
		}
		if flags, options, err := parseMountFlagsAndOptions(m.options); err != nil {
			return grpcStatus.Errorf(codes.Internal, "Could parseMountFlagsAndOptions(%v)", m.options)
		} else if err = syscall.Mount(m.src, m.dest, m.fstype, uintptr(flags), options); err != nil {
			return grpcStatus.Errorf(codes.Internal, "Could not mount %v to %v: %v", m.src, m.dest, err)
		}
	}
	if err := syscall.Unlink("/dev/ptmx"); err != nil {
		return err
	}
	if err := syscall.Symlink("/dev/pts/ptmx", "/dev/ptmx"); err != nil {
		return err
	}
	syscall.Setsid()
	syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), syscall.TIOCSCTTY, 1)
	os.Setenv("PATH", "/bin:/sbin/:/usr/bin/:/usr/sbin/")

	return announce()
}

func init() {
	// Force full stacktrace on internal error
	debug.SetTraceback("system")

	if len(os.Args) > 1 && os.Args[1] == "init" {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
		factory, _ := libcontainer.New("")
		if err := factory.StartInitialization(); err != nil {
			agentLog.WithError(err).Error("init failed")
		}
		panic("--this line should have never been executed, congratulations--")
	}
}

func main() {
	var err error
	var showVersion bool

	flag.BoolVar(&showVersion, "version", false, "display program version and exit")

	flag.Parse()

	if showVersion {
		fmt.Printf("%v version %v\n", agentName, version)
		os.Exit(0)
	}

	// Check if this agent has been run as the init process.
	if os.Getpid() == 1 {
		if err = initAgentAsInit(); err != nil {
			panic(fmt.Sprintf("initAgentAsInit() error: %s", err))
		}
	}

	defer func() {
		if err != nil {
			agentLog.Error(err)
			os.Exit(exitFailure)
		}

		os.Exit(exitSuccess)
	}()

	r := &agentReaper{}
	r.init()

	// Initialize unique sandbox structure.
	s := &sandbox{
		containers: make(map[string]*container),
		running:    false,
		// pivot_root won't work for init, see
		// Documention/filesystem/ramfs-rootfs-initramfs.txt
		noPivotRoot:    os.Getpid() == 1,
		subreaper:      r,
		pciDeviceMap:   make(map[string]string),
		deviceWatchers: make(map[string](chan string)),
	}

	if err = s.initLogger(); err != nil {
		agentLog.WithError(err).Error("failed to setup logger")
		return
	}

	if err = s.setupSignalHandler(); err != nil {
		agentLog.WithError(err).Error("failed to setup signal handler")
		return
	}

	// Check for vsock vs serial. This will fill the sandbox structure with
	// information about the channel.
	if err = s.initChannel(); err != nil {
		agentLog.WithError(err).Error("failed to setup channels")
		return
	}

	// Start gRPC server.
	s.startGRPC()

	go s.listenToUdevEvents()

	s.wg.Wait()
}
