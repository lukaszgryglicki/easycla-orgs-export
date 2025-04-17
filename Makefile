# Project variables
BINARY_NAME := easycla-orgs-export
MAIN := easycla-orgs-export.go

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	go build -o $(BINARY_NAME) $(MAIN)

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY_NAME)

# Format code
.PHONY: fmt
fmt:
	go fmt ./...

# Run static checks
.PHONY: lint
lint:
	go vet ./...

# Tidy up dependencies
.PHONY: tidy
tidy:
	go mod tidy

