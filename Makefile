
# Image URL to use all building/pushing image targets
REPO    ?= ghcr.io/webmeshproj/webmesh-cni
VERSION ?= latest
IMG     ?= $(REPO):$(VERSION)

# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.28.0

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

## Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.13.0
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

generate: ## Run code generators, including DeepCopy methods and manifests.
	go generate ./...

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

## Location to install dependencies to

K8S_VERSION := 1.28
SETUP := go run sigs.k8s.io/controller-runtime/tools/setup-envtest@latest use $(K8S_VERSION) -p path
setup-envtest: ## Setup envtest. This is automatically run by the test target.
	$(SETUP) 1> /dev/null

RICHGO       ?= go run github.com/kyoh86/richgo@v0.3.12
TEST_TIMEOUT ?= 300s
TEST_ARGS    ?= -v -cover -covermode=atomic -coverprofile=cover.out -timeout=$(TEST_TIMEOUT)
test: generate setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(SETUP))" CRD_PATHS="$(CURDIR)/deploy/crds" \
		$(RICHGO) test $(TEST_ARGS) ./...
	go tool cover -func=cover.out

LINT_TIMEOUT := 10m
lint: ## Run linters.
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run --timeout=$(LINT_TIMEOUT)

CI_TARGETS := fmt vet lint test
ifeq ($(CI),true)
	CI_TARGETS := vet test
endif
ci-test: $(CI_TARGETS) ## Run all CI tests.

##@ Build

PARALLEL   ?= $(shell nproc)
GORELEASER ?= go run github.com/goreleaser/goreleaser@latest
BUILD_ARGS ?= --skip=validate --clean --parallelism=$(PARALLEL)

build: ## Build cni binaries for the current architecture.
	$(GORELEASER) build --snapshot --single-target $(BUILD_ARGS)

DOCKER ?= docker
docker: build ## Build docker image for the current architecture.
	$(DOCKER) build -t $(IMG) .

##@ Distribution

.PHONY: dist
dist: ## Build cni binaries for all supported architectures.
	$(GORELEASER) build --snapshot $(BUILD_ARGS)

snapshot: ## Same as dist, but with running all release steps except for signing.
	$(GORELEASER) release --snapshot --skip=sign $(BUILD_ARGS)

RAW_REPO_URL ?= https://github.com/webmeshproj/webmesh-cni/raw/main
STORAGE_PROVIDER_BUNDLE := https://github.com/webmeshproj/storage-provider-k8s/raw/main/deploy/bundle.yaml
BUNDLE_DIR ?= deploy
BUNDLE ?= $(BUNDLE_DIR)/bundle.yaml
bundle: generate ## Bundle creates a distribution bundle manifest.
	mkdir -p $(BUNDLE_DIR)
	rm -f $(BUNDLE)
	@echo "+ Loading storage provider assets from $(STORAGE_PROVIDER_BUNDLE)"
	@echo "---" >> $(BUNDLE)
	@echo "# BEGIN: $(STORAGE_PROVIDER_BUNDLE)" >> $(BUNDLE)
	@echo "---" >> $(BUNDLE)
	@curl -JL --silent $(STORAGE_PROVIDER_BUNDLE) >> $(BUNDLE)
	@echo "---" >> $(BUNDLE)
	@echo "# END: $(STORAGE_PROVIDER_BUNDLE)" >> $(BUNDLE)
	@echo "+ Appending WebMesh CNI assets to $(BUNDLE)"
	@echo "---" >> $(BUNDLE)
	@echo "# Source: $(RAW_REPO_URL)/$(BUNDLE)" >> $(BUNDLE)
	@for i in `find deploy/ -mindepth 2 -type f -not -name bundle.yaml` ; do \
		echo "---" >> $(BUNDLE) ; \
		echo "# Source: $$i" >> $(BUNDLE) ; \
		cat $$i | sed --posix -s -u 1,1d >> $(BUNDLE) ; \
	done
	@echo "+ Setting bundle image to $(IMG)"
	@sed -i 's^$(REPO):latest^$(IMG)^g' $(BUNDLE)

##@ Local Development

KIND    ?= kind
KUBECTL ?= kubectl

CLUSTER_NAME  ?= webmesh-cni
CNI_NAMESPACE ?= kube-system
KIND_CONFIG   ?= deploy/kindconfig.yaml
KIND_CONTEXT  := kind-$(CLUSTER_NAME)

test-cluster: ## Create a test cluster using kind.
	$(KIND) create cluster --name $(CLUSTER_NAME) --config $(KIND_CONFIG)
	$(KUBECTL) config set-context $(KIND_CONTEXT) --namespace=$(CNI_NAMESPACE)

load: docker ## Load the docker image into the test kind cluster.
	$(KIND) load docker-image $(IMG) --name $(CLUSTER_NAME)

install: bundle ## Install the WebMesh CNI into the test kind cluster.
	$(KUBECTL) --context $(KIND_CONTEXT) apply -f $(BUNDLE)

remove-cluster: ## Remove the test kind cluster.
	$(KIND) delete cluster --name $(CLUSTER_NAME)

debug-box:
	$(KUBECTL) --context $(KIND_CONTEXT) run -it --rm --restart=Never --image=alpine -- sh

clean: remove-kind ## Remove all local binaries, test clusters, and release assets.
	rm -rf dist cover.out
