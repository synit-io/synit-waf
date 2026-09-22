# Synit WAF Makefile
#
# The repository holds three Go modules: the WAF (root) and the two optional
# services under services/. Targets that say "all modules" run in each.

SHELL := /bin/bash
.PHONY: all build vet test test-services test-e2e-host test-e2e-docker lint release-notes \
        notices notices-check validate-examples check-links docker-build clean

all: build

## --- Build ---

# The exact tag on a tagged commit (v1.0.0), otherwise the last tag plus the
# distance and commit (v1.0.0-3-gabc1234), or the commit alone when the
# repository has no tag. "-dirty" is appended for uncommitted changes.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X 'github.com/synit-io/synit-waf/internal/waf.Version=$(VERSION)'

SERVICE_MODULES := services/ai-logs-receiver services/synit-llm-guard
EXAMPLE_CONFIGS := assets/config.sample.yml $(sort $(wildcard assets/examples/*.yml))

build:
	@echo "Building bin/synit-waf ($(VERSION))"
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/synit-waf ./cmd/synit-waf

## --- Verification ---

vet:
	go vet ./...
	@for module in $(SERVICE_MODULES); do \
		echo "go vet ($$module)"; (cd "$$module" && go vet ./...) || exit 1; \
	done

test:
	go test -race ./internal/... ./cmd/...

test-services:
	@for module in $(SERVICE_MODULES); do \
		echo "go test ($$module)"; (cd "$$module" && go test -race ./...) || exit 1; \
	done

test-e2e-host:
	./scripts/run-e2e.sh

test-e2e-docker:
	./scripts/run-docker-e2e.sh

## --- Release ---

# Preview the release notes the workflow generates for TAG (default: the
# current HEAD as a temporary tag). The commit history is the changelog.
release-notes:
	@if [ -n "$(TAG)" ]; then ./scripts/release-notes.sh "$(TAG)"; \
	else git tag -f release-notes-preview HEAD >/dev/null && ./scripts/release-notes.sh release-notes-preview; git tag -d release-notes-preview >/dev/null; fi

lint:
	golangci-lint run
	@for module in $(SERVICE_MODULES); do \
		echo "golangci-lint ($$module)"; (cd "$$module" && golangci-lint run) || exit 1; \
	done

# Regenerate third_party/ and the per-service copies.
notices:
	go run ./tools/thirdparty

# Fail when the committed notices differ from the generated output or a
# dependency carries a GPL, AGPL, or LGPL licence.
notices-check:
	go run ./tools/thirdparty -check

# Every sample and example configuration must pass -validate-config.
validate-examples: build
	@for config in $(EXAMPLE_CONFIGS); do \
		printf '%s: ' "$$config"; ./bin/synit-waf -validate-config -config "$$config" || exit 1; \
	done

# Relative links and heading anchors in every Markdown file of the repository.
define CHECK_LINKS_PY
import os, re, sys
root = os.getcwd()
skip = {".git", "node_modules", "third_party", "bin", "dist"}
link = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
def slug(heading):
    heading = re.sub(r"[^\w\- ]", "", heading.strip().lower())
    return heading.replace(" ", "-")
anchors = {}
def headings(path):
    if path not in anchors:
        found, fenced = set(), False
        for line in open(path, encoding="utf-8"):
            if line.startswith("```"):
                fenced = not fenced
                continue
            match = None if fenced else re.match(r"#{1,6}\s+(.*)", line)
            if match:
                found.add(slug(match.group(1)))
        anchors[path] = found
    return anchors[path]
broken = 0
for dirpath, dirs, files in os.walk(root):
    dirs[:] = sorted(d for d in dirs if d not in skip)
    for name in sorted(files):
        if not name.endswith(".md"):
            continue
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root)
        text = re.sub(r"```.*?```", "", open(path, encoding="utf-8").read(), flags=re.S)
        for match in link.finditer(text):
            target = match.group(1)
            if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith("//"):
                continue
            file_part, _, anchor = target.partition("#")
            dest = path if file_part == "" else os.path.normpath(os.path.join(dirpath, file_part))
            if not os.path.exists(dest):
                print(f"{rel}: missing target {target}")
                broken += 1
            elif anchor and dest.endswith(".md") and slug(anchor) not in headings(dest):
                print(f"{rel}: missing anchor {target}")
                broken += 1
print(f"markdown links checked, {broken} broken")
sys.exit(1 if broken else 0)
endef
export CHECK_LINKS_PY

check-links:
	@python3 -c "$$CHECK_LINKS_PY"

## --- Docker ---

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t synit-waf:local .

## --- Cleanup ---

clean:
	rm -rf bin dist test/e2e/docker-test-data
	go clean -testcache
