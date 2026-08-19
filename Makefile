GO ?= go
GOLANGCI_LINT ?= $(HOME)/go/bin/golangci-lint
GOIMPORTS ?= $(HOME)/go/bin/goimports
GOPLS ?= $(HOME)/go/bin/gopls
STATICCHECK ?= $(HOME)/go/bin/staticcheck

.PHONY: build format-check generate gopls lint test test-race verify verify-generated vet

build:
	$(GO) build ./...

test:
	$(GO) test ./... -count=1

test-race:
	$(GO) test ./... -race -count=1

vet:
	$(GO) vet ./...

format-check:
	test -z "$$(gofmt -l $$(git ls-files '*.go'))"
	test -z "$$($(GOIMPORTS) -l $$(git ls-files '*.go'))"

lint:
	$(STATICCHECK) ./...
	$(GOLANGCI_LINT) run --config configs/golangci.yml ./...

gopls:
	git ls-files -z '*.go' ':!testdata/repositories/**' | xargs -0 $(GOPLS) check

generate:
	$(GO) run ./cmd/github-ci generate --root .

verify-generated:
	$(GO) run ./cmd/github-ci verify-generated --root .

verify: format-check verify-generated build test test-race vet lint gopls
