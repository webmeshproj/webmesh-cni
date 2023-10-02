
# Image URL to use all building/pushing image targets
REPO    ?= github.com/webmesh/webmesh-cni
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

# Role name to be used in the ClusterRole and ClusterRoleBinding objects.
ROLE_NAME ?= webmesh-cni-role

.PHONY: manifests
manifests: ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) crd webhook paths="./..." output:crd:artifacts:config=deploy/crd
	$(CONTROLLER_GEN) rbac:roleName=$(ROLE_NAME) webhook paths="./..." output:rbac:artifacts:config=deploy/rbac

.PHONY: generate
HEADER_FILE := api/v1/boilerplate.go.txt
generate: ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="$(HEADER_FILE)" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test ./... -coverprofile cover.out

LINT_TIMEOUT := 10m
lint: ## Run linters.
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest run --timeout=$(LINT_TIMEOUT)

##@ Build

PARALLEL   ?= $(shell nproc)
GORELEASER ?= go run github.com/goreleaser/goreleaser@latest
BUILD_ARGS ?= --clean --parallelism=$(PARALLEL)

build: generate ## Build cni binaries for the current architecture.
	$(GORELEASER) build --snapshot --single-target $(BUILD_ARGS)

.PHONY: dist
dist: generate ## Build cni binaries for all supported architectures.
	$(GORELEASER) build $(BUILD_ARGS)

snapshot: ## Same as dist, but without running the release hooks.
	$(GORELEASER) build --snapshot $(BUILD_ARGS)

DOCKER ?= docker
docker: build ## Build docker image for the current architecture.
	$(DOCKER) build -t $(IMG) .

##@ Distribute

STORAGE_PROVIDER_BUNDLE := https://github.com/webmeshproj/storage-provider-k8s/raw/main/deploy/bundle.yaml
BUNDLE ?= $(CURDIR)/deploy/bundle.yaml
bundle: manifests ## Bundle creates a distribution bundle manifest.
	@echo "+ Loading storage provider assets from $(STORAGE_PROVIDER_BUNDLE)"
	@echo "# Source: $(STORAGE_PROVIDER_BUNDLE)" > $(BUNDLE)
	curl -JL $(STORAGE_PROVIDER_BUNDLE) >> $(BUNDLE)
	@echo "# END: $(STORAGE_PROVIDER_BUNDLE)" >> $(BUNDLE)
	@echo "+ Appending WebMesh CNI assets to $(BUNDLE)"
	@echo "---" >> $(BUNDLE)
	@echo "# Source: $(BUNDLE)" >> $(BUNDLE)
	@for i in `find deploy/ -type f -not -name bundle.yaml` ; do \
		echo "---" >> $(BUNDLE) ; \
		echo "# Source: $$i" >> $(BUNDLE) ; \
		cat $$i | sed --posix -s -u 1,1d >> $(BUNDLE) ; \
	done

##@ Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUBECTL ?= kubectl
ENVTEST ?= $(LOCALBIN)/setup-envtest

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	test -s $(LOCALBIN)/setup-envtest || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

##@ Local Development

K3D ?= k3d
CLUSTER_NAME ?= webmesh-cni

test-cluster:
	$(K3D) cluster create $(CLUSTER_NAME) \
		--k3s-arg '--flannel-backend=none@server:*' \
		--k3s-arg "--disable-network-policy@server:*" \
		--volume '$(BUNDLE):/var/lib/rancher/k3s/server/manifests/webmesh.yaml@server:*' \

build-and-load: docker
	$(K3D) image import $(IMG) --cluster $(CLUSTER_NAME)

test-cluster-calico:
	$(K3D) cluster create $(CLUSTER_NAME) \
		--k3s-arg '--flannel-backend=none@server:*' \
		--k3s-arg "--disable-network-policy@server:*" \
		--volume '$(CURDIR)/config/ref/calico.yaml:/var/lib/rancher/k3s/server/manifests/calico.yaml@server:*' \

remove-cluster:
	$(K3D) cluster delete $(CLUSTER_NAME)
