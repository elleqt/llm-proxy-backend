FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# VERSION labels llmproxy_build_info; without it the module's build information does.
ARG VERSION
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /out/gateway ./cmd/gateway

FROM alpine:3.22
RUN adduser -D -u 10001 app \
 && mkdir -p /var/lib/llmproxy/runtime /var/lib/llmproxy/auths \
 && chown -R app /var/lib/llmproxy
COPY --from=build /out/gateway /usr/local/bin/gateway
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gateway"]
