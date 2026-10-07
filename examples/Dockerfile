# Builds the custom collector from the repository root:
#   docker build -t otelcol-presidio -f examples/Dockerfile .
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN go install go.opentelemetry.io/collector/cmd/builder@v0.161.0 \
 && builder --config examples/builder-config.yaml

FROM gcr.io/distroless/static-debian12
COPY --from=build /src/_build/otelcol-presidio /otelcol-presidio
ENTRYPOINT ["/otelcol-presidio"]
