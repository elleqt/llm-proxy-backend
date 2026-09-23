.PHONY: test generate build
test:
	go test ./... -race
generate:
	go run github.com/vektra/mockery/v3@v3.8.0
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 -config internal/iface/http/api/codegen.yaml api/openapi.yaml
build:
	go build ./...
