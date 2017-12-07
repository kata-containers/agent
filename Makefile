TARGET = kata-agent

DESTDIR :=
PREFIX := /usr
BINDIR := $(PREFIX)/bin
# Define if agent will be installed as init
INIT := no
# Path to systemd unit directory if installed as not init.
UNIT_DIR := /usr/lib/systemd/system

GENERATED_FILES :=

ifeq ($(INIT),no)
# Unit file to start kata agent in systemd systems
UNIT_FILES = kata-agent.service
GENERATED_FILES := $(UNIT_FILES)
# Target to be reached in systemd services
UNIT_FILES += kata-containers.target
endif

$(TARGET): $(GENERATED_FILES)
	go build -o $@

install:
	install -D $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
ifeq ($(INIT),no)
	@echo "Installing systemd unit files..."
	$(foreach f,$(UNIT_FILES),$(call INSTALL_FILE,$f,$(UNIT_DIR)))
endif

.PHONY: clean test go-test
clean:
	rm -f $(TARGET) $(GENERATED_FILES)

test: go-test

go-test:
	bash hack/go-test.sh

define INSTALL_FILE
	install -D -m 644 $1 $(DESTDIR)$2/$1 || exit 1;
endef

$(GENERATED_FILES): %: %.in
	@mkdir -p `dirname $@`
	@sed \
		-e 's|[@]bindir[@]|$(BINDIR)|g' \
		-e 's|[@]kata-agent[@]|$(TARGET)|g' \
		"$<" > "$@"
