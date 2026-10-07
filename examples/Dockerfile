# Builds the custom collector from the repository root:
#   docker build -t otelcol-presidio -f examples/Dockerfile .
#
# Behind a TLS-inspecting corporate proxy (Zscaler, Netskope, ...)?
# Put your company's root CA in examples/certs/ as a PEM file ending in .crt.
# Using an internal Go module proxy (Artifactory, Nexus, Athens)?
#   docker build --build-arg GOPROXY=https://your-proxy/... -t otelcol-presidio -f examples/Dockerfile .
FROM golang:1.26 AS build

COPY examples/certs/ /usr/local/share/ca-certificates/
RUN update-ca-certificates

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} CGO_ENABLED=0

WORKDIR /src
COPY . .
RUN go install go.opentelemetry.io/collector/cmd/builder@v0.161.0 \
 && builder --config examples/builder-config.yaml

FROM gcr.io/distroless/static-debian12
# Same trust store as the build stage, so exports to Langfuse also work
# through the proxy or to endpoints signed by an internal CA.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/_build/otelcol-presidio /otelcol-presidio
ENTRYPOINT ["/otelcol-presidio"]
