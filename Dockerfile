# Copyright (c) 2025 AccelByte Inc. All Rights Reserved.
# This is licensed software from AccelByte Inc, for limitations
# and restrictions contact your company contract manager.

FROM --platform=$BUILDPLATFORM ubuntu:22.04 AS proto-builder

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Set the value for the target OS and architecture.
ARG TARGETOS
ARG TARGETARCH
ARG GOOS=$TARGETOS
ARG GOARCH=$TARGETARCH

ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH=$GOPATH/bin/${TARGETOS}_${TARGETARCH}:$GOPATH/bin:$GOROOT/bin:$PATH

ARG PROTOC_VERSION=21.9
ARG GO_VERSION=1.24.10
ARG HOST_OS

# Configure apt and install packages
RUN apt-get update \
    && apt-get -y install --no-install-recommends \
    #
    # Install essential development tools
    build-essential \
    ca-certificates \
    git \
    unzip \
    wget \
    #
    # Detect architecture for downloads
    && ARCH_SUFFIX=$(case "$(uname -m)" in \
        x86_64) echo "x86_64" ;; \
        aarch64) echo "aarch_64" ;; \
        *) echo "x86_64" ;; \
       esac) \
    && GOARCH_SUFFIX=$(case "$(uname -m)" in \
        x86_64) echo "amd64" ;; \
        aarch64) echo "arm64" ;; \
        *) echo "amd64" ;; \
       esac) \
    && OS_SUFFIX=$(case "${HOST_OS:-$(uname -s)}" in \
        Linux) echo "linux" ;; \
        Darwin) echo "darwin" ;; \
        CYGWIN*|MINGW*|MSYS*) echo "windows" ;; \
        *) echo "linux" ;; \
        esac) \
    # Install Protocol Buffers compiler
    && wget -O protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-${ARCH_SUFFIX}.zip \
    && unzip protoc.zip -d /usr/local \
    && rm protoc.zip \
    && chmod +x /usr/local/bin/protoc \
    #
    # Install Go
    && wget -O go.tar.gz https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH_SUFFIX}.tar.gz \
    && tar -C /usr/local -xzf go.tar.gz \
    && rm go.tar.gz \
    #
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Set working directory.
WORKDIR /build

# Install protoc Go tools and plugins
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest \
    && go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest \
    && go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest

# Copy proto sources and generator script
COPY proto.sh .
COPY pkg/proto/ pkg/proto/

# Generate protobuf files.
RUN chmod +x proto.sh && \
    ./proto.sh

# Copy and download the dependencies for application.
COPY go.mod go.sum ./
RUN go mod download

# Copy application code.
COPY . .

# Build the Go application binary for the target OS and architecture.
RUN go build -v -modcacherw -o /app/service

# Set working directory.
WORKDIR /app

COPY third_party third_party

# Move generated apidocs to final location (they're already in /build/gateway/apidocs from proto.sh)
RUN mkdir -p gateway && \
    cp -r /build/gateway/apidocs gateway/ || true

# Plugin Arch gRPC Server Port.
EXPOSE 6565

# gRPC Gateway Port.
EXPOSE 8000

# Prometheus /metrics Web Server Port.
EXPOSE 8080

# Switch back to dialog for any ad-hoc use of apt-get
ENV DEBIAN_FRONTEND=dialog

# Entrypoint.
CMD [ "/app/service" ]
