.PHONY: test generate build lint golangci-lint

GOLANGCI_LINT_VERSION := 2.14.0
GOLANGCI_LINT_BIN := ./bin/golangci-lint

test:
	go test ./... -race
generate:
	go run github.com/vektra/mockery/v3@v3.8.0
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 -config internal/iface/http/api/codegen.yaml api/openapi.yaml
build:
	go build ./...

# Installed into ./bin rather than run through `go run pkg@version` like the
# generators: golangci-lint is too slow to rebuild on every run.
golangci-lint:
	@if [ ! -x "$(GOLANGCI_LINT_BIN)" ] || \
		[ "$$($(GOLANGCI_LINT_BIN) --version | awk '{print $$4}')" != "$(GOLANGCI_LINT_VERSION)" ]; then \
		echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."; \
		mkdir -p ./bin; \
		GOBIN=$$(pwd)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$(GOLANGCI_LINT_VERSION); \
	fi

# `make lint fix=1` applies autofixes; CI passes --new-from-rev through LINT_FLAGS.
lint: golangci-lint
	@if [ -n "$(fix)" ]; then \
		echo "Running golangci-lint with --fix"; \
		$(GOLANGCI_LINT_BIN) run ./... $(LINT_FLAGS) --fix; \
	else \
		echo "Running golangci-lint"; \
		$(GOLANGCI_LINT_BIN) run ./... $(LINT_FLAGS); \
	fi
