# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

TARGET = kata-agent
SOURCES := $(shell find . 2>&1 | grep -E '.*\.go$$')

DESTDIR :=
PREFIX := /usr
BINDIR := $(PREFIX)/bin
# Define if agent will be installed as init
INIT := no
# Path to systemd unit directory if installed as not init.
UNIT_DIR := /usr/lib/systemd/system

GENERATED_FILES :=
# Define if agent will be built by seccomp tag
SECCOMP := no

ifeq ($(INIT),no)
# Unit file to start kata agent in systemd systems
UNIT_FILES = kata-agent.service
GENERATED_FILES := $(UNIT_FILES)
# Target to be reached in systemd services
UNIT_FILES += kata-containers.target
endif

VERSION_FILE := ./VERSION
VERSION := $(shell grep -v ^\# $(VERSION_FILE))
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT_NO_SHORT := $(shell git rev-parse --short HEAD 2> /dev/null || true)
COMMIT := $(if $(shell git status --porcelain --untracked-files=no),${COMMIT_NO}-dirty,${COMMIT_NO})
VERSION_COMMIT := $(if $(COMMIT),$(VERSION)-$(COMMIT),$(VERSION))
ARCH := $(shell go env GOARCH)
ifeq ($(SECCOMP),yes)
BUILDTAGS := seccomp
endif
# go build common flags
BUILDFLAGS := -buildmode=pie

# args for building agent image
BUILDARGS := $(if $(http_proxy), --build-arg http_proxy=$(http_proxy))
BUILDARGS += $(if $(https_proxy), --build-arg https_proxy=$(https_proxy))
BUILDARGS += $(if $(ARCH), --build-arg arch=$(ARCH))
AGENT_IMAGE := katacontainers/agent-dev
AGENT_TAG := $(if $(COMMIT_NO_SHORT),$(COMMIT_NO_SHORT),dev)

$(TARGET): $(GENERATED_FILES) $(SOURCES) $(VERSION_FILE)
	go build $(BUILDFLAGS) -tags "$(BUILDTAGS)" -o $@ \
		-ldflags "-X main.version=$(VERSION_COMMIT) -X main.seccompSupport=$(SECCOMP)"

install:
	install -D $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
ifeq ($(INIT),no)
	@echo "Installing systemd unit files..."
	$(foreach f,$(UNIT_FILES),$(call INSTALL_FILE,$f,$(UNIT_DIR)))
endif

build-image:
	# build an docker image for development
	docker build ${BUILDARGS} -t ${AGENT_IMAGE}:${AGENT_TAG} .

proto: build-image
	docker run -i -v ${PWD}:/go/src/github.com/kata-containers/agent ${AGENT_IMAGE}:${AGENT_TAG} ./hack/update-generated-agent-proto.sh

.PHONY: clean test
clean:
	rm -f $(TARGET) $(GENERATED_FILES)

test:
	bash .ci/go-test.sh

check: check-go-static

check-go-static:
	bash .ci/static-checks.sh

define INSTALL_FILE
	install -D -m 644 $1 $(DESTDIR)$2/$1 || exit 1;
endef

$(GENERATED_FILES): %: %.in
	@mkdir -p `dirname $@`
	@sed \
		-e 's|[@]bindir[@]|$(BINDIR)|g' \
		-e 's|[@]kata-agent[@]|$(TARGET)|g' \
		"$<" > "$@"
