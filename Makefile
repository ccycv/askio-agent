.PHONY: build test fmt lint

build:
	go build -o ./bin/askio-monitor ./cmd/askio-monitor

test:
	go test ./...

fmt:
	gofmt -w .

lint:
	@echo "(no linter configured)"
