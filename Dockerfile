# The build stage runs on the builder's own platform and cross-compiles for the
# target, so a multi-platform build never emulates the Go toolchain.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
# VERSION labels llmproxy_build_info; without it the module's build information does.
ARG VERSION
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/gateway ./cmd/gateway

FROM alpine:3.24
RUN adduser -D -u 10001 app \
 && mkdir -p /var/lib/llmproxy/runtime /var/lib/llmproxy/auths \
 && chown -R app /var/lib/llmproxy
COPY --from=build /out/gateway /usr/local/bin/gateway
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gateway"]
