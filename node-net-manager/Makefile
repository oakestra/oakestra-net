VERSION := $(shell git describe --tags --abbrev=0)
LDFLAGS := -X 'NetManager/cmd.Version=$(VERSION)'
NET_MANAGER := NetManager
ARCH ?= amd64
DETECTED_ARCH := $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64\|armv8/arm64/')

.PHONY: all arm64 amd64 clean install check-arch check-systemd run start stop detect-arch build-and-run dev

all: amd64

detect-arch:
	@echo "Detected architecture: $(DETECTED_ARCH)"
	@if [ "$(DETECTED_ARCH)" != "amd64" ] && [ "$(DETECTED_ARCH)" != "arm64" ]; then \
		echo "Unsupported architecture: $(DETECTED_ARCH)"; \
		echo "Defaulting to amd64"; \
		echo "To specify architecture manually, use: make ARCH=<architecture> [target]"; \
		echo "supported architectures: amd64, arm64"; \
	fi

arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o bin/arm64-$(NET_MANAGER) $(NET_MANAGER).go

amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o bin/amd64-$(NET_MANAGER) $(NET_MANAGER).go

clean:
	rm -f bin/arm64-$(NET_MANAGER) bin/amd64-$(NET_MANAGER)

check-arch:
	@if [ "$(ARCH)" != "amd64" ] && [ "$(ARCH)" != "arm64" ]; then \
		echo "Architecture not set correctly"; \
		echo "Usage: make install ARCH=<architecture>"; \
		echo "supported architectures: amd64, arm64"; \
		exit 1; \
	fi

check-systemd:
	@if ! systemd --version > /dev/null 2>&1 && ! /usr/lib/systemd/systemd --version > /dev/null 2>&1; then \
		echo "Systemd not present on this machine"; \
		exit 1; \
	fi

install: check-arch check-systemd
	sudo mkdir -p /etc/netmanager
	sudo mkdir -p /var/log/oakestra
	sudo systemctl stop netmanager || true
	sudo cp bin/$(ARCH)-$(NET_MANAGER) /bin/$(NET_MANAGER)
	if [ ! -e /etc/netmanager/netcfg.json ]; then \
		sudo cp config/tuncfg.json /etc/netmanager/tuncfg.json; \
		sudo cp config/netcfg.json /etc/netmanager/netcfg.json; \
	fi
	if [ -e netmanager.service ]; then \
		sudo cp netmanager.service /etc/systemd/system/netmanager.service; \
	else \
		sudo cp build/netmanager.service /etc/systemd/system/netmanager.service; \
	fi
	sudo systemctl daemon-reload
	sudo chmod 755 /bin/$(NET_MANAGER)
	@echo "Done, installation successful"

run: detect-arch
	@echo "Starting $(NET_MANAGER)..."
	sudo /bin/$(NET_MANAGER)

build-and-run: detect-arch
	@echo "Building $(NET_MANAGER) for $(DETECTED_ARCH)..."
	@$(MAKE) $(DETECTED_ARCH)
	@echo "Starting $(NET_MANAGER)..."
	sudo bin/$(DETECTED_ARCH)-$(NET_MANAGER)

start: check-systemd
	@echo "Starting netmanager service..."
	sudo systemctl start netmanager
	@echo "Service started. Check status with: systemctl status netmanager"
	@systemctl status netmanager --no-pager

stop: check-systemd
	@echo "Stopping netmanager service..."
	sudo systemctl stop netmanager || true
	@echo "Service stopped" 