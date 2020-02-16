//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"bufio"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
)

const ldconfPath = "/etc/ld.so.conf"

func setupNvidiaDriver(containerRootfs string) (err error) {
	bins, libs, err := getNvidiaFiles()
	if err != nil {
		return
	}

	// mount driver binaries
	for _, binFile := range bins {
		if err = mount(binFile, filepath.Join(containerRootfs, binFile), "bind", unix.MS_BIND|unix.MS_REC|unix.MS_RDONLY, "rbind"); err != nil {
			return
		}
	}

	// mount driver libraries
	libDirsMap := make(map[string]interface{})
	for _, libFile := range libs {
		if err = mount(libFile, filepath.Join(containerRootfs, libFile), "bind", unix.MS_BIND|unix.MS_REC|unix.MS_RDONLY, "rbind"); err != nil {
			return
		}
		libDir := filepath.Dir(libFile)
		libDirsMap[libDir] = nil
	}

	// configure dynamic linker run-time bindings
	ldArgs := []string{"-r", containerRootfs}
	for dir := range libDirsMap {
		ldArgs = append(ldArgs, filepath.Join(containerRootfs, dir))
	}
	ldCmd := exec.Command("ldconfig", ldArgs...)
	err = ldCmd.Run()
	if err != nil {
		return
	}
	// write libdirs to ld.so.conf
	confFile, err := os.OpenFile(filepath.Join(containerRootfs, ldconfPath), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer confFile.Close()
	for dir := range libDirsMap {
		if _, err = fmt.Fprintln(confFile, dir); err != nil {
			return
		}
	}

	return nil
}

func getNvidiaFiles() (bins []string, libs []string, err error) {
	// "--load-kmods": Load kernel modules
	// "info": Report information about the driver and devices
	infoCmd := exec.Command("nvidia-container-cli", "--load-kmods", "info")
	if err = infoCmd.Run(); err != nil {
		return
	}

	// List driver binaries
	lbinCmd := exec.Command("nvidia-container-cli", "list", "--binaries")
	if bins, err = runGetOutputLines(lbinCmd); err != nil {
		return
	}

	//  List driver libraries
	llibCmd := exec.Command("nvidia-container-cli", "list", "--libraries")
	if libs, err = runGetOutputLines(llibCmd); err != nil {
		return
	}

	return
}

func runGetOutputLines(cmd *exec.Cmd) (outputLines []string, err error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err = cmd.Start(); err != nil {
		return
	}

	outputBuf := bufio.NewReader(stdout)
	var line []byte
	for {
		line, _, err = outputBuf.ReadLine()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return
		}
		outputLines = append(outputLines, string(line))
	}

	if err = cmd.Wait(); err != nil {
		return
	}

	return
}
