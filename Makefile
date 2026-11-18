.PHONY: build test race vet fmt fmt-check lint release release-docker verify-release reproducibility-check

VERSION_PKG := github.com/askio-cloud/askio-monitor/internal/version
VERSION := $(shell cat VERSION)
DEV_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)$(shell test -z "$$(git status --porcelain 2>/dev/null)" || echo -dirty)
RELEASE_ARTIFACT := bin/askio-monitor-linux-amd64

# Development build for the host platform, with version information. Not a
# release: use `make release` for the reproducible Linux amd64 candidate.
build:
	go build -trimpath -ldflags "-X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(DEV_COMMIT)" -o ./bin/askio-monitor ./cmd/askio-monitor

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	./scripts/check-gofmt.sh

lint:
	@echo "(no linter configured)"

# Reproducible Linux amd64 release candidate plus provenance manifest in bin/.
# Requires a clean tree and the pinned toolchain (go1.22.12). See docs/RELEASE.md.
release:
	./scripts/release-build.sh

# The same build inside the digest-pinned golang builder image (bin/docker/).
release-docker:
	./scripts/release-build-docker.sh

verify-release:
	./scripts/verify-release.sh --source . $(RELEASE_ARTIFACT)

# Two more clean builds from `git archive HEAD`; all three must be identical.
reproducibility-check:
	./scripts/check-reproducible.sh $(RELEASE_ARTIFACT)
