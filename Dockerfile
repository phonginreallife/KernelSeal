# X00 Multi-stage Dockerfile
# Builds both the BPF programs and Go binary

# Stage 1: Build BPF programs using Cilium's eBPF builder
FROM docker.io/cilium/ebpf-builder:1698931239 AS bpf-builder
WORKDIR /app
COPY bpf/ ./bpf/
COPY Makefile ./

# Build BPF programs
RUN make bpf

# Stage 2: Build Go binary
FROM golang:1.22-alpine AS go-builder
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=0.1.0" \
    -o x00 ./cmd/main.go

# Stage 3: Final runtime image
# Using distroless for minimal attack surface
FROM gcr.io/distroless/base-debian12:nonroot AS runtime-base

# Alternative: If distroless doesn't work, use slim debian
FROM debian:bookworm-slim AS runtime

# Security: Run apt with minimal privileges and clean up
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates=20230311 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && rm -rf /var/cache/apt/archives/*

# Security: Create non-root user (X00 needs root for BPF, but prepare for future)
RUN groupadd -r x00 && useradd -r -g x00 -s /sbin/nologin x00

# Create necessary directories with proper permissions
RUN mkdir -p /etc/x00 /var/log/x00 /run/x00/secrets /bpf \
    && chown -R x00:x00 /var/log/x00 /run/x00 \
    && chmod 750 /var/log/x00 /run/x00 /run/x00/secrets

# Copy BPF objects (read-only)
COPY --from=bpf-builder --chown=root:root /app/bpf/*.bpf.o /bpf/
RUN chmod 444 /bpf/*.bpf.o

# Copy binary (read-only, executable)
COPY --from=go-builder --chown=root:root /app/x00 /usr/local/bin/x00
RUN chmod 555 /usr/local/bin/x00

# Copy default config (read-only)
COPY --chown=root:x00 examples/config.yaml /etc/x00/config.yaml
RUN chmod 440 /etc/x00/config.yaml

# Security labels
LABEL org.opencontainers.image.title="X00 Security Sidecar" \
      org.opencontainers.image.description="Kubernetes sidecar for eBPF-based secret protection" \
      org.opencontainers.image.vendor="X00" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/YOUR_ORG/x00" \
      security.privileged="true" \
      security.capabilities="BPF,SYS_ADMIN,SYS_PTRACE"

# Set working directory
WORKDIR /

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/x00", "-version"] || exit 1

# Note: X00 requires root for BPF operations
# USER x00  # Uncomment when running non-BPF components

# Default command
ENTRYPOINT ["/usr/local/bin/x00"]
CMD ["-config=/etc/x00/config.yaml", "-exec-monitor=/bpf/exec_monitor.bpf.o", "-lsm=/bpf/lsm_file_protect.bpf.o"]
