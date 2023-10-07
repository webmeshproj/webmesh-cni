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
	"sync/atomic"

	v1 "github.com/webmeshproj/api/v1"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	endpoints "github.com/webmeshproj/webmesh/pkg/meshnet/endpoints"
	meshtransport "github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	netutil "github.com/webmeshproj/webmesh/pkg/meshnet/util"
	meshnode "github.com/webmeshproj/webmesh/pkg/meshnode"
	meshplugins "github.com/webmeshproj/webmesh/pkg/plugins"
	meshstorage "github.com/webmeshproj/webmesh/pkg/storage"
	mesherrors "github.com/webmeshproj/webmesh/pkg/storage/errors"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/webmeshproj/webmesh-cni/internal/ipam"
	cnitypes "github.com/webmeshproj/webmesh-cni/internal/types"
)

// Host is a representation of the host node running the CNI plugin
// and allocating addresses for containers. This is the node that all
// containers on the system peer with for access to the rest of the
// cluster and/or the internet.
type Host interface {
	// ID returns the ID of the host node.
	ID() meshtypes.NodeID
	// Start starts the host node.
	Start(ctx context.Context, cfg *rest.Config) error
	// Started returns true if the host node has been started.
	Started() bool
	// Stop stops the host node. This is also closes the underlying
	// storage provider.
	Stop(ctx context.Context) error
	// IPAM returns the IPv4 address allocator. This will be nil until
	// Start is called.
	IPAM() ipam.Allocator
	// Node returns the underlying mesh node. This will be nil until
	// Start is called.
	Node() meshnode.Node
}

// NewNode is the function for creating a new mesh node. Declared as a variable for testing purposes.
var NewNode = meshnode.NewWithLogger

// NewHostNode creates a new host node.
func NewHostNode(storage meshstorage.Provider, opts Config) Host {
	node := &hostNode{
		nodeID:  meshtypes.NodeID(opts.NodeID),
		storage: storage,
		config:  opts,
	}
	return node
}

// hostNode implements the Host interface.
type hostNode struct {
	nodeID     meshtypes.NodeID
	storage    meshstorage.Provider
	config     Config
	started    atomic.Bool
	networkV4  netip.Prefix
	networkV6  netip.Prefix
	meshDomain string
	node       meshnode.Node
	ipam       ipam.Allocator
	mu         sync.Mutex
}

// ID returns the ID of the host node.
func (h *hostNode) ID() meshtypes.NodeID {
	return h.nodeID
}

// Started returns true if the host node has been started.
func (h *hostNode) Started() bool {
	return h.started.Load()
}

// Node returns the underlying mesh node.
func (h *hostNode) Node() meshnode.Node {
	return h.node
}

// IPAM returns the IPv4 address allocator.
func (h *hostNode) IPAM() ipam.Allocator {
	return h.ipam
}

// Start starts the host node.
func (h *hostNode) Start(ctx context.Context, cfg *rest.Config) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.started.Load() {
		return fmt.Errorf("host node already started")
	}
	log := log.FromContext(ctx).WithName("host-node")
	err := h.bootstrap(ctx)
	if err != nil {
		return fmt.Errorf("failed to bootstrap host node: %w", err)
	}
	log.Info("Setting up host node")
	log.V(1).Info("Starting IPAM allocator")
	h.ipam, err = ipam.NewAllocator(cfg, ipam.Config{
		IPAM: meshplugins.IPAMConfig{
			Storage: h.storage.MeshDB(),
		},
		Lock: ipam.LockConfig{
			ID:                 h.config.NodeID,
			Namespace:          h.config.Namespace,
			LockDuration:       h.config.LockDuration,
			LockAcquireTimeout: h.config.LockAcquireTimeout,
		},
		Network: h.networkV4,
	})
	if err != nil {
		return fmt.Errorf("failed to create IPAM allocator: %w", err)
	}
	// Detect the current endpoints on the machine.
	log.Info("Detecting host endpoints")
	eps, err := endpoints.Detect(ctx, endpoints.DetectOpts{
		DetectPrivate:        true, // Required for finding endpoints for other containers on the local node.
		DetectIPv6:           !h.config.Network.DisableIPv6,
		AllowRemoteDetection: h.config.Network.RemoteEndpointDetection,
		// Make configurable? It will at least need to account for any CNI interfaces
		// from a previous run.
		SkipInterfaces: []string{},
	})
	if err != nil {
		return fmt.Errorf("failed to detect endpoints: %w", err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	encoded, err := key.PublicKey().Encode()
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}
	// We always allocate addresses for ourselves, even if we won't use them.
	log.Info("Allocating a mesh IPv4 address")
	err = h.ipam.Locker().Acquire(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire IPAM lock: %w", err)
	}
	defer h.ipam.Locker().Release(ctx)
	var ipv4Addr, ipv6Addr string
	alloc, err := h.ipam.Allocate(ctx, h.nodeID)
	if err != nil {
		return fmt.Errorf("failed to allocate IPv4 address: %w", err)
	}
	ipv4Addr = alloc.String()
	log.Info("Allocating a mesh IPv6 address")
	ipv6Addr = netutil.AssignToPrefix(h.networkV6, key.PublicKey()).String()
	log.Info("Connecting to the webmesh network")
	hostNode := NewNode(logging.NewLogger(h.config.LogLevel, "json"), meshnode.Config{
		Key:             key,
		NodeID:          h.nodeID.String(),
		ZoneAwarenessID: h.nodeID.String(),
		DisableIPv4:     h.config.Network.DisableIPv4,
		DisableIPv6:     h.config.Network.DisableIPv6,
	})
	connectCtx, cancel := context.WithTimeout(ctx, h.config.ConnectTimeout)
	defer cancel()
	err = hostNode.Connect(connectCtx, meshnode.ConnectOptions{
		StorageProvider: h.storage,
		MaxJoinRetries:  10,
		JoinRoundTripper: meshtransport.JoinRoundTripperFunc(func(ctx context.Context, req *v1.JoinRequest) (*v1.JoinResponse, error) {
			// TODO: Check for pre-existing peers and return them.
			return &v1.JoinResponse{
				AddressIPv4: ipv4Addr,
				AddressIPv6: ipv6Addr,
				NetworkIPv4: h.networkV4.String(),
				NetworkIPv6: h.networkV6.String(),
				MeshDomain:  h.meshDomain,
			}, nil
		}),
		LeaveRoundTripper: meshtransport.LeaveRoundTripperFunc(func(ctx context.Context, req *v1.LeaveRequest) (*v1.LeaveResponse, error) {
			// TODO: Actually leave the cluster.
			return &v1.LeaveResponse{}, nil
		}),
		NetworkOptions: meshnet.Options{
			ListenPort:      h.config.Network.WireGuardPort,
			InterfaceName:   cnitypes.IfNameFromID(h.nodeID.String()),
			ForceReplace:    true,
			MTU:             h.config.Network.MTU,
			ZoneAwarenessID: h.nodeID.String(),
			DisableIPv4:     h.config.Network.DisableIPv4,
			DisableIPv6:     h.config.Network.DisableIPv6,
			// Maybe by configuration?
			RecordMetrics:         false,
			RecordMetricsInterval: 0,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to connect to webmesh network: %w", err)
	}
	select {
	case <-connectCtx.Done():
		return fmt.Errorf("timeout while connecting to webmesh network: %w", connectCtx.Err())
	case <-hostNode.Ready():
	}
	// Register ourselves with the mesh.
	log.Info("Host node is connected, registering endpoints with network")
	wireguardPort, err := hostNode.Network().WireGuard().ListenPort()
	if err != nil {
		defer hostNode.Close(ctx)
		return fmt.Errorf("failed to get wireguard listen port: %w", err)
	}
	var wgeps []string
	for _, ep := range eps.AddrPorts(uint16(wireguardPort)) {
		wgeps = append(wgeps, ep.String())
	}
	peer := meshtypes.MeshNode{
		MeshNode: &v1.MeshNode{
			Id:                 h.nodeID.String(),
			PublicKey:          encoded,
			PrimaryEndpoint:    eps.FirstPublicAddr().String(),
			WireguardEndpoints: wgeps,
			ZoneAwarenessID:    h.nodeID.String(),
			PrivateIPv4:        ipv4Addr,
			PrivateIPv6:        ipv6Addr,
		},
	}
	err = h.storage.MeshDB().Peers().Put(ctx, peer)
	if err != nil {
		defer hostNode.Close(ctx)
		return fmt.Errorf("failed to register with mesh: %w", err)
	}
	// Put a default gateway route for ourselves.
	err = h.storage.MeshDB().Networking().PutRoute(ctx, meshtypes.Route{
		Route: &v1.Route{
			Name: fmt.Sprintf("%s-node-gw", h.nodeID.String()),
			Node: h.nodeID.String(),
			// This should be more configurable.
			DestinationCIDRs: func() []string {
				out := []string{"0.0.0.0/0", "::/0"}
				for _, ep := range eps {
					out = append(out, ep.String())
				}
				return out
			}(),
		},
	})
	if err != nil {
		defer hostNode.Close(ctx)
		return fmt.Errorf("failed to register default gateway route: %w", err)
	}
	h.node = hostNode
	h.started.Store(true)
	return nil
}

// Stop stops the host node.
func (h *hostNode) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	log := log.FromContext(ctx).WithName("host-node")
	if !h.started.Load() {
		return fmt.Errorf("host node must be started before it can be stopped")
	}
	// Try to remove our peer from the mesh.
	err := h.storage.MeshDB().Peers().Delete(ctx, h.nodeID)
	if err != nil {
		log.Error(err, "Failed to remove host webmesh node from network")
	}
	err = h.node.Close(ctx)
	if err != nil {
		log.Error(err, "Failed to close host webmesh node")
	}
	h.started.Store(false)
	return nil
}

// bootstrap attempts to bootstrap the underlying storage provider and network state.
// If the storage is already bootstrapped, it will read in the pre-existing state.
func (h *hostNode) bootstrap(ctx context.Context) error {
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
	return nil
}
