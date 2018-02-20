# Name of the resulting binary
BINARY := enforcer

# List of dependencies, separated by spaces
DEPENDENCIES := github.com/gorilla/mux


PKGS := $(shell go list ./...)
TESTS := $(shell go list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./...)
GOLINT := $(GOPATH)/bin/golint
DEPS := $(foreach dep,$(DEPENDENCIES),$(GOPATH)/src/$(dep))
CMD_PATH := cmd


all: build test vet lint

build: $(DEPS)
	cd $(CMD_PATH) && go build -v -o $(BINARY)

test:
	go test $(TESTS)

lint: $(GOLINT)
	golint $(PKGS)

vet:
	go vet $(PKGS)

install:
	cd $(CMD_PATH) && go build -v -i -o $(GOPATH)/bin/$(BINARY)

clean:
	go clean $(PKGS)
	rm -f $(CMD_PATH)/$(BINARY)

uninstall:
	go clean -i $(PKGS)
	rm -f $(GOPATH)/bin/$(BINARY)

$(GOLINT):
	go get -v github.com/golang/lint/golint

$(DEPS):
	go get -v $(subst $(GOPATH)/src/,,$@)

.PHONY: all build test lint vet install clean uninstall
