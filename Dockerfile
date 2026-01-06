# KernelSeal Multi-stage Dockerfile
# Builds both the BPF programs and Go binary
# hadolint global ignore=DL3008

# Stage 1: Build BPF programs
FROM ubuntu:22.04 AS bpf-builder

# Install BPF build dependencies
# hadolint ignore=DL3009
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    make \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY bpf/ ./bpf/
COPY Makefile ./

# Generate vmlinux.h if not present and build BPF programs
RUN make bpf || echo "BPF build skipped - will use pre-built objects"

# Stage 2: Build Go binary
FROM golang:1.25-alpine AS go-builder
WORKDIR /app

# Install build dependencies
# hadolint ignore=DL3018
RUN apk add --no-cache git

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=0.1.0" \
    -o kernelseal ./cmd/main.go

# Stage 3: Final runtime image
FROM debian:bookworm-slim

# Security: Run apt with minimal privileges and clean up
# hadolint ignore=DL3009
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Security: Create non-root user (KernelSeal needs root for BPF, but prepare for future)
RUN groupadd -r kernelseal && useradd -r -g kernelseal -s /sbin/nologin kernelseal

# Create necessary directories with proper permissions
RUN mkdir -p /etc/kernelseal /var/log/kernelseal /run/kernelseal/secrets /bpf \
    && chown -R kernelseal:kernelseal /var/log/kernelseal /run/kernelseal \
    && chmod 750 /var/log/kernelseal /run/kernelseal /run/kernelseal/secrets

# Copy BPF objects (read-only)
COPY --from=bpf-builder --chown=root:root /app/bpf/*.bpf.o /bpf/
RUN chmod 444 /bpf/*.bpf.o

# Copy binary (read-only, executable)
COPY --from=go-builder --chown=root:root /app/kernelseal /usr/local/bin/kernelseal
RUN chmod 555 /usr/local/bin/kernelseal

# Copy default config (read-only)
COPY --chown=root:kernelseal examples/config.yaml /etc/kernelseal/config.yaml
RUN chmod 440 /etc/kernelseal/config.yaml

# Security labels
LABEL org.opencontainers.image.title="KernelSeal Security Sidecar" \
      org.opencontainers.image.description="Kubernetes sidecar for eBPF-based secret protection" \
      org.opencontainers.image.vendor="KernelSeal" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/YOUR_ORG/kernelseal" \
      security.privileged="true" \
      security.capabilities="BPF,SYS_ADMIN,SYS_PTRACE"

# Set working directory
WORKDIR /

# Health check - use shell form for proper exit handling
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD /usr/local/bin/kernelseal -version || exit 1

# Note: KernelSeal requires root for BPF operations
# USER kernelseal  # Uncomment when running non-BPF components

# Default command
ENTRYPOINT ["/usr/local/bin/kernelseal"]
CMD ["-config=/etc/kernelseal/config.yaml", "-exec-monitor=/bpf/exec_monitor.bpf.o", "-lsm=/bpf/lsm_file_protect.bpf.o"]
