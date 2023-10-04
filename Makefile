
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
LOCALBIN := $(CURDIR)/bin

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
	$(CONTROLLER_GEN) crd webhook paths="./..." output:crd:artifacts:config=deploy/crds
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

K8S_VERSION := 1.28
SETUP := go run sigs.k8s.io/controller-runtime/tools/setup-envtest@latest use $(K8S_VERSION) --bin-dir $(LOCALBIN) -p path
setup-envtest: ## Setup envtest. This is automatically run by the test target.
	$(SETUP) 1> /dev/null

RICHGO       ?= go run github.com/kyoh86/richgo@v0.3.12
TEST_TIMEOUT ?= 300s
TEST_ARGS    ?= -v -cover -covermode=atomic -coverprofile=cover.out -timeout=$(TEST_TIMEOUT)
test: manifests generate setup-envtest ## Run tests.
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

RAW_REPO_URL ?= https://github.com/webmeshproj/webmesh-cni/raw/main
STORAGE_PROVIDER_BUNDLE := https://github.com/webmeshproj/storage-provider-k8s/raw/main/deploy/bundle.yaml
BUNDLE ?= deploy/bundle.yaml
bundle: manifests ## Bundle creates a distribution bundle manifest.
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

K3D  ?= k3d
KIND ?= kind

CLUSTER_NAME  ?= webmesh-cni
CNI_NAMESPACE ?= kube-system

test-k3d: ## Create a test cluster with the WebMesh CNI installed.
	$(K3D) cluster create $(CLUSTER_NAME) \
		--k3s-arg '--flannel-backend=none@server:*' \
		--k3s-arg "--disable-network-policy@server:*" \
		--k3s-arg "--disable=traefik,servicelb,local-storage,metrics-server@server:*" \
		--k3s-arg '--cluster-cidr=10.42.0.0/16,2001:cafe:42:0::/56@server:*' \
		--k3s-arg '--service-cidr=10.43.0.0/16,2001:cafe:43:0::/112@server:*' \
		--k3s-arg '--node-ip=0.0.0.0,::@server:*' \
		--k3s-arg '--kube-proxy-arg=ipvs-strict-arp@server:*' \
		--volume '/lib/modules:/lib/modules@server:*' \
		--volume '/dev/net/tun:/dev/net/tun@server:*' \
		--volume '$(CURDIR)/$(BUNDLE):/var/lib/rancher/k3s/server/manifests/webmesh.yaml@server:*'

KIND_CONFIG ?= deploy/kindconfig.yaml
test-kind:
	$(KIND) create cluster --name $(CLUSTER_NAME) --config $(KIND_CONFIG)
	
load-k3d: docker ## Load the docker image into the test cluster.
	$(K3D) image import $(IMG) --cluster $(CLUSTER_NAME)

test-k3d-calico: ## Create a test cluster with Calico installed. This is used for testing the storage provider.
	curl -JL -o $(LOCALBIN)/calico.yaml https://k3d.io/v5.3.0/usage/advanced/calico.yaml
	$(K3D) cluster create $(CLUSTER_NAME) \
		--k3s-arg '--flannel-backend=none@server:*' \
		--k3s-arg "--disable-network-policy@server:*" \
		--volume '$(LOCALBIN)/calico.yaml:/var/lib/rancher/k3s/server/manifests/calico.yaml@server:*'

remove-k3d: ## Remove the test cluster.
	$(K3D) cluster delete $(CLUSTER_NAME)

remove-kind:
	$(KIND) delete cluster --name $(CLUSTER_NAME)

clean: ## Remove all local binaries and release assets.
	rm -rf $(LOCALBIN) dist
