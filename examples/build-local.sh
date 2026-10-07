#!/usr/bin/env sh
# Builds the collector on this machine, then packages it into a Docker image.
# Use this when the Docker build can't reach the Go module proxy, e.g. behind a
# TLS-inspecting corporate proxy. Run from the repository root:
#   ./examples/build-local.sh
# Override the target CPU (e.g. for an amd64 cluster from an Apple Silicon Mac):
#   ARCH=amd64 ./examples/build-local.sh
set -eu

ARCH="${ARCH:-$(docker version --format '{{.Server.Arch}}')}"
IMAGE="${IMAGE:-otelcol-presidio}"

echo "Installing OCB v0.161.0"
go install go.opentelemetry.io/collector/cmd/builder@v0.161.0

echo "Building collector for linux/${ARCH}"
GOOS=linux GOARCH="${ARCH}" CGO_ENABLED=0 \
  "$(go env GOPATH)/bin/builder" --config examples/builder-config.yaml

echo "Packaging ${IMAGE} for linux/${ARCH}"
docker build --platform "linux/${ARCH}" -t "${IMAGE}" -f examples/Dockerfile.prebuilt .
