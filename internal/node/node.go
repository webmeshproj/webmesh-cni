/*
Copyright 2023 Avi Zimmerman <avi.zimmerman@gmail.com>.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package node

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/webmeshproj/webmesh/pkg/meshnode"
	meshstorage "github.com/webmeshproj/webmesh/pkg/storage"
	mesherrors "github.com/webmeshproj/webmesh/pkg/storage/errors"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/webmeshproj/webmesh-cni/internal/ipam"
)

// Host is a representation of the host node running the CNI plugin
// and allocating addresses for containers. This is the node that all
// containers on the system peer with for access to the rest of the
// cluster and/or the internet.
type Host interface {
	// Bootstrap attempts to bootstrap the underlying storage provider and
	// network state. If the storage is already bootstrapped, it will read
	// in the existing state. This must be called before starting the node.
	Bootstrap(ctx context.Context) error
	// Start starts the host node. Bootstrap must be called first to read in
	// the network state.
	Start(ctx context.Context, cfg *rest.Config) error
	// Stop stops the host node.
	Stop(ctx context.Context) error
	// IPAM returns the IPv4 address allocator. This will be nil until
	// Start is called.
	IPAM() ipam.Allocator
	// Node returns the underlying mesh node. This will be nil until
	// Start is called.
	Node() meshnode.Node
}

// NewHostNode creates a new host node.
func NewHostNode(storage meshstorage.Provider, opts Config) Host {
	node := &hostNode{
		storage: storage,
		config:  opts,
	}
	return node
}

// hostNode implements the Host interface.
type hostNode struct {
	storage      meshstorage.Provider
	config       Config
	bootstrapped bool
	started      bool
	networkV4    netip.Prefix
	networkV6    netip.Prefix
	meshDomain   string
	node         meshnode.Node
	ipam         ipam.Allocator
	mu           sync.Mutex
}

// Node returns the underlying mesh node.
func (h *hostNode) Node() meshnode.Node {
	return h.node
}

// IPAM returns the IPv4 address allocator.
func (h *hostNode) IPAM() ipam.Allocator {
	return h.ipam
}

// Bootstrap attempts to bootstrap the underlying storage provider and network state.
// If the storage is already bootstrapped, it will read in the pre-existing state.
func (h *hostNode) Bootstrap(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.bootstrapped {
		return mesherrors.ErrAlreadyBootstrapped
	}
	log := log.FromContext(ctx).WithName("network-bootstrap")
	log.Info("Checking that the webmesh network is bootstrapped")
	log.V(1).Info("Attempting to bootstrap storage provider")
	err := h.storage.Bootstrap(ctx)
	if err != nil {
		if !mesherrors.Is(err, mesherrors.ErrAlreadyBootstrapped) {
			log.Error(err, "Unable to bootstrap storage provider")
			return fmt.Errorf("failed to bootstrap storage provider: %w", err)
		}
		log.V(1).Info("Storage provider already bootstrapped, making sure network state is boostrapped")
	}
	// Make sure the network state is boostrapped.
	bootstrapOpts := meshstorage.BootstrapOptions{
		MeshDomain:           h.config.Network.ClusterDomain,
		IPv4Network:          h.config.Network.IPv4CIDR,
		Admin:                meshstorage.DefaultMeshAdmin,
		DefaultNetworkPolicy: meshstorage.DefaultNetworkPolicy,
		DisableRBAC:          true, // Make this configurable? But really, just use the RBAC from Kubernetes.
	}
	log.V(1).Info("Attempting to bootstrap network state", "options", bootstrapOpts)
	networkState, err := meshstorage.Bootstrap(ctx, h.storage.MeshDB(), bootstrapOpts)
	if err != nil && !mesherrors.Is(err, mesherrors.ErrAlreadyBootstrapped) {
		log.Error(err, "Unable to bootstrap network state")
		return fmt.Errorf("failed to bootstrap network state: %w", err)
	} else if mesherrors.Is(err, mesherrors.ErrAlreadyBootstrapped) {
		log.V(1).Info("Network already bootstrapped")
	} else {
		log.Info("Network state bootstrapped for the first time")
	}
	h.networkV4 = networkState.NetworkV4
	h.networkV6 = networkState.NetworkV6
	h.meshDomain = networkState.MeshDomain
	h.bootstrapped = true
	return nil
}

// Start starts the host node.
func (h *hostNode) Start(ctx context.Context, cfg *rest.Config) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.bootstrapped {
		return fmt.Errorf("host node must be bootstrapped before it can be started")
	}
	h.started = true
	return nil
}

// Stop stops the host node.
func (h *hostNode) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.started {
		return fmt.Errorf("host node must be started before it can be stopped")
	}
	return nil
}
