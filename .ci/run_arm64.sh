#!/bin/bash
#
# Copyright (c) 2020 Arm Ltd Corporation
#
# SPDX-License-Identifier: Apache-2.0

source "${tests_repo_dir}/.ci/lib.sh"

arch=$(go env GOARCH)
install_docker_ubuntu() {
        pkg_name="docker-ce"
        repo_url="https://download.docker.com/linux/ubuntu"
        curl -L "${repo_url}/gpg" | sudo apt-key add -
        sudo -E add-apt-repository "deb [arch=${arch}] ${repo_url} $(lsb_release -cs) stable"
        sudo -E apt-get update
        docker_version_full=$(apt-cache madison $pkg_name | grep "$docker_version" | awk '{print $3}' | head -1)
        sudo -E apt-get -y install "${pkg_name}=${docker_version_full}"
}

# make proto will fail on arm64 when use docker 18.06 and using docker 19.03
# can avoid this failure. For now this change is only for ubuntu as we know little
# about the other cases.
main() {
	ID=$(cat /etc/os-release | grep "^ID=" | cut -f 2 -d "=")
        if [ "$ID" != "ubuntu" ]; then
		echo "docker upgrade is only done for ubuntu"
                exit 0
        fi
        current_docker_version=$(docker version | awk '/Engine/{getline; print $2 }')
        current_docker_version=${current_docker_version%.*}
        docker_version=$(get_version "externals.docker.architecture.aarch64.agent.version")
        docker_version=${docker_version/v}
        docker_version=${docker_version/-*}
        if [[ `echo "$current_docker_version < $docker_version" | bc` -eq 1 ]]; then
                command -v docker >/dev/null 2>&1 && "./cmd/container-manager/manage_ctr_mgr.sh" docker remove
                echo "reinstall docker $docker_version for arm64"
                install_docker_ubuntu $docker_version
        fi
}

main
