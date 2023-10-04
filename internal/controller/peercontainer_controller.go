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

package controller

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"github.com/webmeshproj/storage-provider-k8s/provider"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnet/endpoints"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	netutil "github.com/webmeshproj/webmesh/pkg/meshnet/util"
	meshnode "github.com/webmeshproj/webmesh/pkg/meshnode"
	meshipam "github.com/webmeshproj/webmesh/pkg/plugins/builtins/ipam"
	meshstorage "github.com/webmeshproj/webmesh/pkg/storage"
	mesherrors "github.com/webmeshproj/webmesh/pkg/storage/errors"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
)

// PeerContainerReconciler reconciles a PeerContainer object. Reconcile
// attempts will fail until SetNetworkState is called.
type PeerContainerReconciler struct {
	client.Client
	Scheme                  *runtime.Scheme
	Provider                *provider.Provider
	NodeName                string
	ReconcileTimeout        time.Duration
	RemoteEndpointDetection bool

	ready      atomic.Bool
	networkV4  netip.Prefix
	networkV6  netip.Prefix
	meshDomain string
	nodes      map[types.NamespacedName]meshnode.Node
	mu         sync.Mutex
}

// NewNode is the function for creating a new mesh node. Declared as a variable for testing purposes.
var NewNode = meshnode.NewWithLogger

//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/finalizers,verbs=update

// SetupWithManager sets up the controller with the Manager.
func (r *PeerContainerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cniv1.PeerContainer{}).
		Complete(r)
}

// SetNetworkState sets the network configuration to the reconciler to make it ready to reconcile requests.
func (r *PeerContainerReconciler) SetNetworkState(results meshstorage.BootstrapResults) {
	r.meshDomain = results.MeshDomain
	r.networkV4 = results.NetworkV4
	r.networkV6 = results.NetworkV6
	r.nodes = make(map[types.NamespacedName]meshnode.Node)
	r.ready.Store(true)
}

// Reconcile reconciles a PeerContainer.
func (r *PeerContainerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	if !r.ready.Load() {
		log.Info("Controller is not ready yet, requeing reconcile request")
		return ctrl.Result{
			Requeue:      true,
			RequeueAfter: 1 * time.Second,
		}, nil
	}
	if r.ReconcileTimeout > 0 {
		log.V(1).Info("Setting reconcile timeout", "timeout", r.ReconcileTimeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.ReconcileTimeout)
		defer cancel()
	}
	var container cniv1.PeerContainer
	if err := r.Get(ctx, req.NamespacedName, &container); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get container")
		return ctrl.Result{}, err
	}
	if container.Spec.NodeName != r.NodeName {
		// This container is not for this node, so we don't care about it.
		return ctrl.Result{}, nil
	}
	if container.GetDeletionTimestamp() != nil {
		// Stop the mesh node for this container.
		log.Info("Tearing down mesh node for container", "container", req.NamespacedName)
		return ctrl.Result{}, r.teardownPeerContainer(ctx, req, &container)
	}
	// Reconcile the mesh node for this container.
	log.Info("Reconciling mesh node for container", "container", req.NamespacedName)
	return ctrl.Result{}, r.reconcilePeerContainer(ctx, req, &container)
}

// reconcilePeerContainer reconciles the given PeerContainer.
func (r *PeerContainerReconciler) reconcilePeerContainer(ctx context.Context, req ctrl.Request, container *cniv1.PeerContainer) error {
	log := log.FromContext(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()

	// Make sure the finalizer is present first.
	if !controllerutil.ContainsFinalizer(container, cniv1.PeerContainerFinalizer) {
		updated := controllerutil.AddFinalizer(container, cniv1.PeerContainerFinalizer)
		if updated {
			log.Info("Adding finalizer to container", "container", container)
			if err := r.Update(ctx, container); err != nil {
				return fmt.Errorf("failed to add finalizer: %w", err)
			}
			return nil
		}
	}

	// Check if we have registered the node yet
	id := req.NamespacedName
	nodeID := meshtypes.NodeID(container.Spec.NodeID)
	node, ok := r.nodes[id]
	if !ok {
		// We need to create the node.
		log.Info("Mesh node for container not found, we must need to create it", "container", id)
		// Detect the current endpoints on the machine.
		eps, err := endpoints.Detect(ctx, endpoints.DetectOpts{
			DetectPrivate:        true, // Required for finding endpoints for other containers on the local node.
			DetectIPv6:           !container.Spec.DisableIPv6,
			AllowRemoteDetection: r.RemoteEndpointDetection,
			SkipInterfaces: func() []string {
				var out []string
				for _, n := range r.nodes {
					if n.Started() {
						out = append(out, n.Network().WireGuard().Name())
					}
				}
				return out
			}(),
		})
		if err != nil {
			r.setFailedStatus(ctx, container, err)
			return fmt.Errorf("failed to detect endpoints: %w", err)
		}
		// Get the next available wireguard port.
		wireguardPort, err := r.nextAvailableWireGuardPort()
		if err != nil {
			r.setFailedStatus(ctx, container, err)
			return fmt.Errorf("failed to get next available wireguard port: %w", err)
		}
		var wgeps []string
		for _, ep := range eps.AddrPorts(wireguardPort) {
			wgeps = append(wgeps, ep.String())
		}
		key, err := crypto.GenerateKey()
		if err != nil {
			r.setFailedStatus(ctx, container, err)
			return fmt.Errorf("failed to generate key: %w", err)
		}
		encoded, err := key.PublicKey().Encode()
		if err != nil {
			r.setFailedStatus(ctx, container, err)
			return fmt.Errorf("failed to encode public key: %w", err)
		}
		var ipv4addr string
		if !container.Spec.DisableIPv4 {
			// If the container does not have an IPv4 address and we are not disabling
			// IPv4, use the default plugin to allocate one.
			// TODO: We need a better mechanism (likely plugin side) as this relies
			// on read consistency of the database.
			plugin := meshipam.NewWithDB(r.Provider.MeshDB())
			alloc, err := plugin.Allocate(ctx, &v1.AllocateIPRequest{
				NodeID: nodeID.String(),
				Subnet: r.networkV4.String(),
			})
			if err != nil {
				r.setFailedStatus(ctx, container, err)
				return fmt.Errorf("failed to allocate IPv4 address: %w", err)
			}
			ipv4addr = alloc.GetIp()
		}
		// Try to register this node as a peer directly via the API.
		log.Info("Registering peer",
			"nodeID", nodeID,
			"publicKey", encoded,
			"wireguardPort", wireguardPort,
			"wireguardEndpoints", wgeps,
			"ipv4addr", ipv4addr,
			"ipv6addr", netutil.AssignToPrefix(r.networkV6, key.PublicKey()).String(),
		)
		err = r.Provider.MeshDB().Peers().Put(ctx, meshtypes.MeshNode{
			MeshNode: &v1.MeshNode{
				Id:                 nodeID.String(),
				PublicKey:          encoded,
				PrimaryEndpoint:    eps.FirstPublicAddr().String(),
				WireguardEndpoints: wgeps,
				ZoneAwarenessID:    container.Spec.NodeName,
				PrivateIPv4:        ipv4addr,
				PrivateIPv6:        netutil.AssignToPrefix(r.networkV6, key.PublicKey()).String(),
			},
		})
		if err != nil {
			log.Error(err, "Failed to register peer", "container", container)
			r.setFailedStatus(ctx, container, err)
			return fmt.Errorf("failed to register peer: %w", err)
		}
		// Create edges for all other nodes in the same zone.
		log.Info("Determining current local peers")
		peers, err := r.Provider.MeshDB().Peers().List(
			ctx,
			meshstorage.FilterAgainstNode(nodeID),
			meshstorage.FilterByZoneID(container.Spec.NodeName),
		)
		if err != nil {
			log.Error(err, "Failed to list peers", "container", container)
			r.setFailedStatus(ctx, container, err)
			return fmt.Errorf("failed to list peers: %w", err)
		}
		for _, peer := range peers {
			log.Info("Adding edge to peer", "peer", peer)
			if err := r.Provider.MeshDB().Peers().PutEdge(ctx, meshtypes.MeshEdge{MeshEdge: &v1.MeshEdge{
				Source: nodeID.String(),
				Target: peer.NodeID().String(),
			}}); err != nil {
				r.setFailedStatus(ctx, container, err)
				return fmt.Errorf("failed to create edge: %w", err)
			}
		}
		// Create the mesh node.
		r.nodes[id] = NewNode(logging.NewLogger(container.Spec.LogLevel, "json"), meshnode.Config{
			Key:             key,
			NodeID:          nodeID.String(),
			ZoneAwarenessID: container.Spec.NodeName,
			DisableIPv4:     container.Spec.DisableIPv4,
			DisableIPv6:     container.Spec.DisableIPv6,
		})
		// Update the status to created.
		log.Info("Updating container status to created")
		container.Status.InterfaceStatus = cniv1.InterfaceStatusCreated
		container.Status.IPv4Address = ipv4addr
		if err := r.updateContainerStatus(ctx, container); err != nil {
			return fmt.Errorf("failed to update status: %w", err)
		}
		return nil
	}

	// If the node is not started, start it.
	if !node.Started() {
		log.Info("Starting mesh node for container", "container", container)
		peer, err := r.Provider.MeshDB().Peers().Get(ctx, nodeID)
		if err != nil {
			log.Error(err, "Failed to get peer", "container", container)
			r.setFailedStatus(ctx, container, err)
			return fmt.Errorf("failed to get peer for container: %w", err)
		}
		key, err := crypto.DecodePublicKey(peer.PublicKey)
		if err != nil {
			// This should never happen, but if it does, we need to delete the peer
			// from the database.
			log.Error(err, "Failed to decode public key", "container", container)
			delErr := r.Provider.MeshDB().Peers().Delete(ctx, nodeID)
			if delErr != nil {
				log.Error(delErr, "Failed to delete peer", "container", container)
			}
			r.setFailedStatus(ctx, container, err)
			// Create a new node on the next reconcile.
			delete(r.nodes, id)
			return fmt.Errorf("failed to decode public key: %w", err)
		}
		rtt := transport.JoinRoundTripperFunc(func(ctx context.Context, _ *v1.JoinRequest) (*v1.JoinResponse, error) {
			// Build the current network topology and return to the peer. They'll use
			// the storage provider to subscribe to changes.
			log.Info("Returning current network topology to peer", "container", container)
			peers, err := meshnet.WireGuardPeersFor(ctx, r.Provider.MeshDB(), nodeID)
			if err != nil {
				log.Error(err, "Failed to get peers for join response", "container", container)
				return nil, fmt.Errorf("failed to get peers: %w", err)
			}
			return &v1.JoinResponse{
				MeshDomain:  r.meshDomain,
				NetworkIPv4: r.networkV4.String(),
				NetworkIPv6: r.networkV6.String(),
				AddressIPv6: netutil.AssignToPrefix(r.networkV6, key).String(),
				AddressIPv4: container.Status.IPv4Address,
				Peers:       peers,
			}, nil
		})
		err = node.Connect(ctx, meshnode.ConnectOptions{
			StorageProvider:  r.Provider,
			MaxJoinRetries:   10,
			JoinRoundTripper: rtt,
			NetworkOptions: meshnet.Options{
				Modprobe:              true,
				InterfaceName:         container.Spec.IfName,
				ForceReplace:          true,
				ListenPort:            int(peer.WireGuardPort()),
				MTU:                   container.Spec.MTU,
				RecordMetrics:         false, // Maybe by configuration?
				RecordMetricsInterval: 0,
				ZoneAwarenessID:       container.Spec.NodeName,
				DisableIPv4:           container.Spec.DisableIPv4,
				DisableIPv6:           container.Spec.DisableIPv6,
			},
			DirectPeers: func() map[string]v1.ConnectProtocol {
				peers := make(map[string]v1.ConnectProtocol)
				for _, n := range r.nodes {
					if n.ID() == node.ID() {
						continue
					}
					peers[string(n.ID())] = v1.ConnectProtocol_CONNECT_NATIVE
				}
				return peers
			}(),
			PreferIPv6: !container.Spec.DisableIPv6,
		})
		if err != nil {
			log.Error(err, "Failed to connect meshnode", "container", container)
			r.setFailedStatus(ctx, container, err)
			// Create a new node on the next reconcile.
			delete(r.nodes, id)
			return fmt.Errorf("failed to connect node: %w", err)
		}
		// Update the status to starting.
		log.Info("Updating container status to starting")
		container.Status.InterfaceStatus = cniv1.InterfaceStatusStarting
		if err := r.updateContainerStatus(ctx, container); err != nil {
			return fmt.Errorf("failed to update status: %w", err)
		}
		return nil
	}

	log.Info("Waiting for mesh node to start", "container", container)
	select {
	case <-node.Ready():
		hwaddr, _ := node.Network().WireGuard().HardwareAddr()
		log.Info("Node is running",
			"container", container,
			"interfaceName", node.Network().WireGuard().Name(),
			"macAddress", hwaddr.String(),
			"ipv4Address", node.Network().WireGuard().AddressV4().String(),
			"ipv6Address", node.Network().WireGuard().AddressV6().String(),
			"networkV4", node.Network().NetworkV4().String(),
			"networkV6", node.Network().NetworkV6().String(),
		)
		err := r.ensureInterfaceReadyStatus(ctx, container, node)
		if err != nil {
			log.Error(err, "Failed to update container status", "container", container)
			return fmt.Errorf("failed to update container status: %w", err)
		}
	case <-ctx.Done():
		// Update the status to failed.
		log.Error(ctx.Err(), "Timed out waiting for mesh node to start", "container", container)
		r.setFailedStatus(ctx, container, ctx.Err())
		// Don't delete the node, maybe it'll be ready on the next reconcile.
		return ctx.Err()
	}

	// Anything else from here on out is non-fatal from an interface perspective.
	// So we don't touch the status and just log errors.

	// Make sure all MeshEdges are up to date for this node.
	log.Info("Forcing sync of peers and topology")
	peers, err := r.Provider.MeshDB().Peers().List(
		ctx,
		meshstorage.FilterAgainstNode(nodeID),
		meshstorage.FilterByZoneID(container.Spec.NodeName),
	)
	if err != nil {
		log.Error(err, "Failed to list peers", "container", container)
		return fmt.Errorf("failed to list peers: %w", err)
	}
	for _, peer := range peers {
		if err := r.Provider.MeshDB().Peers().PutEdge(ctx, meshtypes.MeshEdge{MeshEdge: &v1.MeshEdge{
			Source: nodeID.String(),
			Target: peer.NodeID().String(),
		}}); err != nil {
			log.Error(err, "Failed to create edge", "container", container)
			return fmt.Errorf("failed to create edge: %w", err)
		}
	}
	// Force a sync of the node.
	err = node.Network().Peers().Sync(ctx)
	if err != nil {
		log.Error(err, "Failed to sync peers", "container", container)
		// We don't return an error because the peer will eventually sync on its own.
	}
	return nil
}

// teardownPeerContainer tears down the given PeerContainer.
func (r *PeerContainerReconciler) teardownPeerContainer(ctx context.Context, req ctrl.Request, container *cniv1.PeerContainer) error {
	log := log.FromContext(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	name := req.NamespacedName
	node, ok := r.nodes[name]
	if !ok {
		log.Info("Mesh node for container not found, we must have already deleted", "container", name)
	} else {
		if err := node.Close(ctx); err != nil {
			log.Error(err, "Failed to stop mesh node for container", "container", name)
		}
		delete(r.nodes, name)
	}
	// Make sure we've deleted the mesh peer from the database.
	if err := r.Provider.MeshDB().Peers().Delete(ctx, meshtypes.NodeID(name.Name)); err != nil {
		if !mesherrors.Is(err, mesherrors.ErrNodeNotFound) {
			log.Error(err, "Failed to delete peer", "container", name)
			return fmt.Errorf("failed to delete peer: %w", err)
		}
	}
	if controllerutil.ContainsFinalizer(container, cniv1.PeerContainerFinalizer) {
		updated := controllerutil.RemoveFinalizer(container, cniv1.PeerContainerFinalizer)
		if updated {
			log.Info("Removing finalizer from container", "container", container)
			if err := r.Update(ctx, container); err != nil {
				return fmt.Errorf("failed to remove finalizer: %w", err)
			}
		}
	}
	return nil
}

func (r *PeerContainerReconciler) ensureInterfaceReadyStatus(ctx context.Context, container *cniv1.PeerContainer, node meshnode.Node) error {
	log := log.FromContext(ctx)
	// Update the status to running and sets its IP address.
	var updateStatus bool
	if container.Status.InterfaceStatus != cniv1.InterfaceStatusRunning {
		// Update the status to running and sets its IP address.
		container.Status.InterfaceStatus = cniv1.InterfaceStatusRunning
		updateStatus = true
	}
	hwaddr, _ := node.Network().WireGuard().HardwareAddr()
	if container.Status.MACAddress != hwaddr.String() {
		container.Status.MACAddress = hwaddr.String()
		updateStatus = true
	}
	if container.Status.IPv4Address != node.Network().WireGuard().AddressV4().String() {
		container.Status.IPv4Address = node.Network().WireGuard().AddressV4().String()
		updateStatus = true
	}
	if container.Status.IPv6Address != node.Network().WireGuard().AddressV6().String() {
		container.Status.IPv6Address = node.Network().WireGuard().AddressV6().String()
		updateStatus = true
	}
	if container.Status.NetworkV4 != node.Network().NetworkV4().String() {
		container.Status.NetworkV4 = node.Network().NetworkV4().String()
		updateStatus = true
	}
	if container.Status.NetworkV6 != node.Network().NetworkV6().String() {
		container.Status.NetworkV6 = node.Network().NetworkV6().String()
		updateStatus = true
	}
	if container.Status.InterfaceName != node.Network().WireGuard().Name() {
		container.Status.InterfaceName = node.Network().WireGuard().Name()
		updateStatus = true
	}
	if container.Status.Error != "" {
		container.Status.Error = ""
		updateStatus = true
	}
	if updateStatus {
		log.Info("Updating container status to running", "status", container.Status)
		return r.updateContainerStatus(ctx, container)
	}
	return nil
}

func (r *PeerContainerReconciler) setFailedStatus(ctx context.Context, container *cniv1.PeerContainer, reason error) {
	container.Status.InterfaceStatus = cniv1.InterfaceStatusFailed
	container.Status.Error = reason.Error()
	err := r.updateContainerStatus(ctx, container)
	if err != nil {
		log.FromContext(ctx).Error(err, "Failed to update container status", "container", container)
	}
}

func (r *PeerContainerReconciler) updateContainerStatus(ctx context.Context, container *cniv1.PeerContainer) error {
	container.SetManagedFields(nil)
	err := r.Status().Patch(ctx,
		container,
		client.Apply,
		client.ForceOwnership,
		client.FieldOwner(cniv1.FieldOwner),
	)
	if err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}
	return nil
}

func (r *PeerContainerReconciler) nextAvailableWireGuardPort() (uint16, error) {
	const startPort uint16 = 51820
	const endPort uint16 = 65535
	// Fast path if there are no nodes.
	if len(r.nodes) == 0 {
		return startPort, nil
	}
Ports:
	for i := startPort; i <= endPort; i++ {
	Nodes:
		for _, node := range r.nodes {
			if !node.Started() {
				continue Nodes
			}
			lport, err := node.Network().WireGuard().ListenPort()
			if err != nil {
				return 0, err
			}
			if uint16(lport) == i {
				continue Ports
			}
		}
		return i, nil
	}
	return 0, fmt.Errorf("no available ports")
}
