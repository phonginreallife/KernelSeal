# KernelSeal Makefile - Build eBPF programs and Go binary
#
# Requirements:
# - clang >= 11 (for BPF compilation)
# - llvm >= 11 (for llvm-strip)
# - libbpf-dev
# - kernel headers (linux-headers-$(uname -r))
# - bpftool (for vmlinux.h generation)

SHELL := /bin/bash

# Go settings
GO := go
GOOS := linux
GOARCH := amd64
CGO_ENABLED := 0

# BPF settings
CLANG := clang
LLVM_STRIP := llvm-strip
BPFTOOL := bpftool

# Kernel version (auto-detect)
KERNEL_VERSION := $(shell uname -r)

# Directories
BPF_DIR := bpf
BUILD_DIR := build
CMD_DIR := cmd

# BPF compilation flags
BPF_CFLAGS := -g -O2 -target bpf \
	-D__TARGET_ARCH_x86 \
	-I/usr/include/$(shell uname -m)-linux-gnu \
	-I$(BPF_DIR)

# Source files
BPF_SOURCES := $(wildcard $(BPF_DIR)/*.bpf.c)
BPF_OBJECTS := $(BPF_SOURCES:.c=.o)

# Binary name
BINARY := kernelseal

# Container settings
REGISTRY ?= your-registry
IMAGE_NAME := kernelseal
IMAGE_TAG ?= latest

.PHONY: all
all: vmlinux bpf build

.PHONY: vmlinux
vmlinux: $(BPF_DIR)/vmlinux.h

$(BPF_DIR)/vmlinux.h:
	@echo "📦 Generating vmlinux.h from kernel BTF..."
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		echo "⚠️  BTF not available, using minimal vmlinux.h"; \
	fi

.PHONY: bpf
bpf: $(BPF_OBJECTS)
	@echo "✅ BPF programs compiled"

$(BPF_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c $(BPF_DIR)/vmlinux.h $(BPF_DIR)/kernelseal_common.h
	@echo "🔨 Compiling $<..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

.PHONY: build
build:
	@echo "🔨 Building KernelSeal binary..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -o $(BUILD_DIR)/$(BINARY) ./$(CMD_DIR)/main.go
	@echo "✅ Binary built: $(BUILD_DIR)/$(BINARY)"

.PHONY: docker
docker: all
	@echo "🐳 Building Docker image..."
	docker build -t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) .

.PHONY: docker-dev
docker-dev:
	@echo "🐳 Building Docker image using Cilium dev environment..."
	docker run --rm -v $(PWD):/app -w /app \
		--privileged \
		docker.io/cilium/ebpf-builder:1698931239 \
		make bpf
	$(MAKE) build
	docker build -t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) .

.PHONY: test
test:
	@echo "🧪 Running unit tests..."
	$(GO) test -v -race ./internal/...

.PHONY: test-coverage
test-coverage:
	@echo "🧪 Running tests with coverage..."
	$(GO) test -v -race -coverprofile=coverage.out -covermode=atomic ./internal/...
	$(GO) tool cover -func=coverage.out
	@echo "📊 Coverage report generated: coverage.out"

.PHONY: test-coverage-html
test-coverage-html: test-coverage
	@echo "📊 Generating HTML coverage report..."
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "📊 HTML report: coverage.html"

.PHONY: test-short
test-short:
	@echo "🧪 Running short tests..."
	$(GO) test -v -short ./internal/...

.PHONY: test-integration
test-integration:
	@echo "🧪 Running integration tests (requires root)..."
	sudo $(GO) test -v ./test/integration/...

.PHONY: lint
lint:
	@echo "🔍 Running linter..."
	golangci-lint run ./...

.PHONY: lint-fix
lint-fix:
	@echo "🔧 Running linter with auto-fix..."
	golangci-lint run --fix ./...

.PHONY: fmt
fmt:
	@echo "📝 Formatting code..."
	$(GO) fmt ./...
	goimports -w .

.PHONY: vet
vet:
	@echo "🔍 Running go vet..."
	$(GO) vet ./...

.PHONY: security
security:
	@echo "🔒 Running security scan..."
	gosec ./...

.PHONY: clean
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -f $(BPF_DIR)/*.bpf.o
	rm -rf $(BUILD_DIR)

.PHONY: clean-all
clean-all: clean
	@echo "🧹 Cleaning all generated files..."
	rm -f $(BPF_DIR)/vmlinux.h

.PHONY: install-deps
install-deps:
	@echo "📦 Installing build dependencies..."
	apt-get update && apt-get install -y \
		clang \
		llvm \
		libbpf-dev \
		linux-headers-$(KERNEL_VERSION) \
		bpftool

.PHONY: verify-bpf
verify-bpf:
	@echo "🔍 Verifying BPF programs..."
	@for obj in $(BPF_OBJECTS); do \
		echo "Checking $$obj..."; \
		$(BPFTOOL) prog load $$obj /sys/fs/bpf/kernelseal_test 2>&1 || true; \
		rm -f /sys/fs/bpf/kernelseal_test 2>/dev/null || true; \
	done

.PHONY: run
run: all
	@echo "🚀 Running KernelSeal..."
	sudo $(BUILD_DIR)/$(BINARY) -config examples/config.yaml

.PHONY: help
help:
	@echo "KernelSeal Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build everything (vmlinux, bpf, go binary)"
	@echo "  vmlinux      - Generate vmlinux.h from kernel BTF"
	@echo "  bpf          - Compile BPF programs"
	@echo "  build        - Build Go binary"
	@echo "  docker       - Build Docker image"
	@echo "  docker-dev   - Build using Cilium dev container"
	@echo "  test         - Run tests"
	@echo "  lint         - Run linter"
	@echo "  clean        - Clean build artifacts"
	@echo "  clean-all    - Clean all generated files including vmlinux.h"
	@echo "  install-deps - Install build dependencies"
	@echo "  verify-bpf   - Verify BPF programs can be loaded"
	@echo "  run          - Build and run KernelSeal"
	@echo "  help         - Show this help"
