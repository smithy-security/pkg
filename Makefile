PHONY: test

# List of directories to run tests on
GO_PACKAGES := $(shell find . -name '*_test.go' -exec dirname {} \; | sort -u)

# Target to run `go test` on all directories
test:
	@for package in $(GO_PACKAGES); do \
		echo "Running tests in $$package"; \
		(cd $$package && go test ./... -count=10 -race)  || exit 1; \
	done
