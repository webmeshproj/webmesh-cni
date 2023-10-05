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
	meshplugins "github.com/webmeshproj/webmesh/pkg/plugins"
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
	ipam       *meshplugins.BuiltinIPAM
	nodes      map[types.NamespacedName]meshnode.Node
	mu         sync.Mutex
}

// NewNode is the function for creating a new mesh node. Declared as a variable for testing purposes.
var NewNode = meshnode.NewWithLogger

//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/finalizers,verbs=update

//go:generate sh -x -c "go run sigs.k8s.io/controller-tools/cmd/controller-gen@latest rbac:roleName=webmesh-cni-role webhook paths='./...' output:rbac:artifacts:config=../../deploy/rbac"

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
	r.ipam = meshplugins.NewBuiltinIPAM(meshplugins.IPAMConfig{Storage: r.Provider.MeshDB()})
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
		key, err := crypto.GenerateKey()
		if err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
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
		if err := r.updateContainerStatus(ctx, container); err != nil {
			return fmt.Errorf("failed to update status: %w", err)
		}
		return nil
	}

	// If the node is not started, start it.
	if !node.Started() {
		log.Info("Starting mesh node for container", "container", container)
		rtt := transport.JoinRoundTripperFunc(func(ctx context.Context, _ *v1.JoinRequest) (*v1.JoinResponse, error) {
			// Get the next available IPv4 address if requested.
			var ipv4addr string
			if !container.Spec.DisableIPv4 {
				// If the container does not have an IPv4 address and we are not disabling
				// IPv4, use the default plugin to allocate one.
				// TODO: We need a better mechanism (likely plugin side) as this relies
				// on read consistency of the database.
				alloc, err := r.ipam.Allocate(ctx, &v1.AllocateIPRequest{
					NodeID: nodeID.String(),
					Subnet: r.networkV4.String(),
				})
				if err != nil {
					return nil, fmt.Errorf("failed to allocate IPv4 address: %w", err)
				}
				ipv4addr = alloc.GetIp()
			}
			return &v1.JoinResponse{
				MeshDomain: r.meshDomain,
				// We always return both networks regardless of IP preferences.
				NetworkIPv4: r.networkV4.String(),
				NetworkIPv6: r.networkV6.String(),
				// We only return addresses if they are enabled.
				AddressIPv6: func() string {
					if container.Spec.DisableIPv6 {
						return ""
					}
					return netutil.AssignToPrefix(r.networkV6, node.Key().PublicKey()).String()
				}(),
				AddressIPv4: ipv4addr,
			}, nil
		})
		err := node.Connect(ctx, meshnode.ConnectOptions{
			StorageProvider:  r.Provider,
			MaxJoinRetries:   10,
			JoinRoundTripper: rtt,
			NetworkOptions: meshnet.Options{
				NetNs:         container.Spec.Netns,
				InterfaceName: container.Spec.IfName,
				ForceReplace:  true,
				MTU:           container.Spec.MTU,

				ZoneAwarenessID: container.Spec.NodeName,
				DisableIPv4:     container.Spec.DisableIPv4,
				DisableIPv6:     container.Spec.DisableIPv6,
				// Maybe by configuration?
				RecordMetrics:         false,
				RecordMetricsInterval: 0,
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

	log.Info("Waiting for mesh node to be ready", "container", container)

	select {
	case <-node.Ready():
		hwaddr, _ := node.Network().WireGuard().HardwareAddr()
		log.Info("Node is running",
			"container", container,
			"interfaceName", node.Network().WireGuard().Name(),
			"macAddress", hwaddr.String(),
			"ipv4Address", validOrNone(node.Network().WireGuard().AddressV4()),
			"ipv4Address", validOrNone(node.Network().WireGuard().AddressV6()),
			"networkV4", validOrNone(node.Network().NetworkV4()),
			"networkV6", validOrNone(node.Network().NetworkV6()),
		)
		err := r.ensureInterfaceReadyStatus(ctx, container, node)
		if err != nil {
			log.Error(err, "Failed to update container status", "container", container)
			return fmt.Errorf("failed to update container status: %w", err)
		}
	case <-ctx.Done():
		// Update the status to failed.
		log.Error(ctx.Err(), "Timed out waiting for mesh node to start", "container", container)
		// Don't delete the node or set it to failed yet, maybe it'll be ready on the next reconcile.
		return ctx.Err()
	}

	// Register the node to the storage provider.

	wireguardPort, err := node.Network().WireGuard().ListenPort()
	if err != nil {
		// Something went terribly wrong, we need to recreate the node.
		defer func() {
			if err := node.Close(ctx); err != nil {
				log.Error(err, "Failed to stop mesh node for container", "container", container)
			}
		}()
		delete(r.nodes, id)
		r.setFailedStatus(ctx, container, err)
		return fmt.Errorf("failed to get wireguard port: %w", err)
	}
	encoded, err := node.Key().PublicKey().Encode()
	if err != nil {
		// Something went terribly wrong, we need to recreate the node.
		defer func() {
			if err := node.Close(ctx); err != nil {
				log.Error(err, "Failed to stop mesh node for container", "container", container)
			}
		}()
		delete(r.nodes, id)
		r.setFailedStatus(ctx, container, err)
		return fmt.Errorf("failed to encode public key: %w", err)
	}
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
		// Try again on the next reconcile.
		return fmt.Errorf("failed to detect endpoints: %w", err)
	}
	var wgeps []string
	for _, ep := range eps.AddrPorts(uint16(wireguardPort)) {
		wgeps = append(wgeps, ep.String())
	}
	// Try to register this node as a peer directly via the API.
	log.Info("Registering peer",
		"nodeID", nodeID,
		"publicKey", encoded,
		"wireguardPort", wireguardPort,
		"wireguardEndpoints", wgeps,
		"ipv4addr", validOrNone(node.Network().WireGuard().AddressV4()),
		"ipv6addr", validOrNone(node.Network().WireGuard().AddressV6()),
	)
	err = r.Provider.MeshDB().Peers().Put(ctx, meshtypes.MeshNode{
		MeshNode: &v1.MeshNode{
			Id:                 nodeID.String(),
			PublicKey:          encoded,
			PrimaryEndpoint:    eps.FirstPublicAddr().String(),
			WireguardEndpoints: wgeps,
			ZoneAwarenessID:    container.Spec.NodeName,
			PrivateIPv4:        validOrEmpty(node.Network().WireGuard().AddressV4()),
			PrivateIPv6:        validOrEmpty(node.Network().WireGuard().AddressV6()),
		},
	})
	if err != nil {
		// Try again on the next reconcile.
		log.Error(err, "Failed to register peer", "container", container)
		return fmt.Errorf("failed to register peer: %w", err)
	}
	// Make sure all MeshEdges are up to date for this node.
	log.Info("Forcing sync of peers and topology")
	peers, err := r.Provider.MeshDB().Peers().List(
		ctx,
		meshstorage.FilterAgainstNode(nodeID),
		meshstorage.FilterByZoneID(container.Spec.NodeName),
	)
	if err != nil {
		// Try again on the next reconcile.
		log.Error(err, "Failed to list peers", "container", container)
		return fmt.Errorf("failed to list peers: %w", err)
	}
	for _, peer := range peers {
		if err := r.Provider.MeshDB().Peers().PutEdge(ctx, meshtypes.MeshEdge{MeshEdge: &v1.MeshEdge{
			Source: nodeID.String(),
			Target: peer.NodeID().String(),
		}}); err != nil {
			// Try again on the next reconcile.
			log.Error(err, "Failed to create edge", "container", container)
			return fmt.Errorf("failed to create edge: %w", err)
		}
	}
	// Force a sync of the node.
	err = node.Network().Peers().Sync(ctx)
	if err != nil {
		log.Error(err, "Failed to sysnc peers", "container", container)
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
	origStatus := container.Status
	addrV4 := validOrEmpty(node.Network().WireGuard().AddressV4())
	addrV6 := validOrEmpty(node.Network().WireGuard().AddressV6())
	netv4 := validOrEmpty(node.Network().NetworkV4())
	netv6 := validOrEmpty(node.Network().NetworkV6())
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

	if container.Status.IPv4Address != addrV4 {
		container.Status.IPv4Address = addrV4
		updateStatus = true
	}

	if container.Status.IPv6Address != addrV6 {
		container.Status.IPv6Address = addrV6
		updateStatus = true
	}
	if container.Status.NetworkV4 != netv4 {
		container.Status.NetworkV4 = netv4
		updateStatus = true
	}
	if container.Status.NetworkV6 != netv6 {
		container.Status.NetworkV6 = netv6
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
		log.Info("Updating container interface status",
			"newStatus", container.Status,
			"oldStatus", origStatus,
		)
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

func validOrEmpty(prefix netip.Prefix) string {
	if prefix.IsValid() {
		return prefix.String()
	}
	return ""
}

func validOrNone(prefix netip.Prefix) string {
	if prefix.IsValid() {
		return prefix.String()
	}
	return "none"
}
