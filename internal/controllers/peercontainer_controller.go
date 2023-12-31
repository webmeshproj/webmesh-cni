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

package controllers

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/go/v1"
	"github.com/webmeshproj/storage-provider-k8s/provider"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnet/endpoints"
	netutil "github.com/webmeshproj/webmesh/pkg/meshnet/netutil"
	meshtransport "github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	meshnode "github.com/webmeshproj/webmesh/pkg/meshnode"
	meshdns "github.com/webmeshproj/webmesh/pkg/services/meshdns"
	meshstorage "github.com/webmeshproj/webmesh/pkg/storage"
	mesherrors "github.com/webmeshproj/webmesh/pkg/storage/errors"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
	"github.com/webmeshproj/webmesh-cni/internal/config"
	"github.com/webmeshproj/webmesh-cni/internal/host"
)

//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/finalizers,verbs=update

// PeerContainerReconciler reconciles a PeerContainer object. Reconcile
// attempts will fail until SetNetworkState is called.
type PeerContainerReconciler struct {
	client.Client
	config.Config
	Provider *provider.Provider
	Host     host.Node

	dns            *meshdns.Server
	containerNodes map[client.ObjectKey]meshnode.Node
	mu             sync.Mutex
}

// SetupWithManager sets up the controller with the Manager.
func (r *PeerContainerReconciler) SetupWithManager(mgr ctrl.Manager) (err error) {
	// Create clients for IPAM locking
	r.containerNodes = make(map[client.ObjectKey]meshnode.Node)
	return ctrl.NewControllerManagedBy(mgr).
		For(&cniv1.PeerContainer{}).
		Complete(r)
}

// SetDNSServer sets the DNS server for the controller.
func (r *PeerContainerReconciler) SetDNSServer(dns *meshdns.Server) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dns = dns
}

// LookupPrivateKey looks up the private key for the given node ID.
func (r *PeerContainerReconciler) LookupPrivateKey(nodeID meshtypes.NodeID) (crypto.PrivateKey, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if nodeID == r.Host.ID() || string(nodeID) == r.Host.Node().Key().ID() {
		return r.Host.Node().Key(), true
	}
	for _, node := range r.containerNodes {
		if node.ID() == nodeID {
			return node.Key(), true
		}
	}
	return nil, false
}

// Shutdown shuts down the controller and all running mesh nodes.
func (r *PeerContainerReconciler) Shutdown(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, node := range r.containerNodes {
		log.FromContext(ctx).V(1).Info("Stopping mesh node for container", "container", id)
		if err := node.Close(ctx); err != nil {
			log.FromContext(ctx).Error(err, "Failed to stop mesh node for container")
		}
		delete(r.containerNodes, id)
	}
}

// Reconcile reconciles a PeerContainer.
func (r *PeerContainerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	log := log.FromContext(ctx)
	if !r.Host.Started() {
		log.Info("Controller is not ready yet, requeing reconcile request")
		return ctrl.Result{
			Requeue:      true,
			RequeueAfter: 1 * time.Second,
		}, nil
	}
	if r.Manager.ReconcileTimeout > 0 {
		log.V(1).Info("Setting reconcile timeout", "timeout", r.Manager.ReconcileTimeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Manager.ReconcileTimeout)
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
	if container.Spec.NodeName != r.Host.ID().String() {
		// This container is not for this node, so we don't care about it.
		log.V(1).Info("Ignoring container for another node")
		return ctrl.Result{}, nil
	}
	// Always ensure the type meta is set
	container.TypeMeta = cniv1.PeerContainerTypeMeta
	if container.GetDeletionTimestamp() != nil {
		// Stop the mesh node for this container.
		log.Info("Tearing down mesh node for container")
		return ctrl.Result{}, r.teardownPeerContainer(ctx, req, &container)
	}
	// Reconcile the mesh node for this container.
	log.Info("Reconciling mesh node for container")
	return ctrl.Result{}, r.reconcilePeerContainer(ctx, req, &container)
}

// NoOpStorageCloser wraps the storage provider with a no-op closer so
// that mesh nodes will not close the storage provider.
type NoOpStorageCloser struct {
	meshstorage.Provider
}

// Close is a no-op.
func (n *NoOpStorageCloser) Close() error {
	return nil
}

// reconcilePeerContainer reconciles the given PeerContainer.
func (r *PeerContainerReconciler) reconcilePeerContainer(ctx context.Context, req ctrl.Request, container *cniv1.PeerContainer) error {
	log := log.FromContext(ctx)

	// Make sure the finalizer is present first.
	if !controllerutil.ContainsFinalizer(container, cniv1.PeerContainerFinalizer) {
		updated := controllerutil.AddFinalizer(container, cniv1.PeerContainerFinalizer)
		if updated {
			log.V(1).Info("Adding finalizer to container")
			if err := r.Update(ctx, container); err != nil {
				return fmt.Errorf("failed to add finalizer: %w", err)
			}
			return nil
		}
	}

	// Check if we have registered the node yet
	node, ok := r.containerNodes[req.NamespacedName]
	if !ok {
		// We need to create the node.
		nodeID := container.Spec.NodeID
		log.Info("Webmesh node for container not found, we must need to create it")
		log.V(1).Info("Creating new webmesh node with container spec", "spec", container.Spec)
		key, err := crypto.GenerateKey()
		if err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}
		var ipv4addr string
		if !container.Spec.DisableIPv4 && container.Status.IPv4Address == "" {
			// If the container does not have an IPv4 address and we are not disabling
			// IPv4, use the default plugin to allocate one.
			err = r.Host.IPAM().Locker().Acquire(ctx)
			if err != nil {
				return fmt.Errorf("failed to acquire IPAM lock: %w", err)
			}
			defer r.Host.IPAM().Locker().Release(ctx)
			alloc, err := r.Host.IPAM().Allocate(ctx, meshtypes.NodeID(nodeID))
			if err != nil {
				return fmt.Errorf("failed to allocate IPv4 address: %w", err)
			}
			ipv4addr = alloc.String()
		}
		// Go ahead and register a Peer for this node.
		encoded, err := key.PublicKey().Encode()
		if err != nil {
			return fmt.Errorf("failed to encode public key: %w", err)
		}
		peer := meshtypes.MeshNode{
			MeshNode: &v1.MeshNode{
				Id:              nodeID,
				PublicKey:       encoded,
				ZoneAwarenessID: container.Spec.NodeName,
				PrivateIPv4:     ipv4addr,
				PrivateIPv6: func() string {
					if container.Spec.DisableIPv6 {
						return ""
					}
					return netutil.AssignToPrefix(r.Host.Node().Network().NetworkV6(), key.PublicKey()).String()
				}(),
			},
		}
		log.Info("Registering peer with meshdb", "peer", peer.MeshNode)
		if err := r.Provider.MeshDB().Peers().Put(ctx, peer); err != nil {
			return fmt.Errorf("failed to register peer: %w", err)
		}
		// Create the mesh node.
		r.containerNodes[req.NamespacedName] = NewNode(logging.NewLogger(container.Spec.LogLevel, "json"), meshnode.Config{
			Key:             key,
			NodeID:          nodeID,
			ZoneAwarenessID: container.Spec.NodeName,
			DisableIPv4:     container.Spec.DisableIPv4,
			DisableIPv6:     container.Spec.DisableIPv6,
		})
		// Update the status to created.
		log.Info("Updating container interface status to created")
		container.Status.InterfaceStatus = cniv1.InterfaceStatusCreated
		if err := r.updateContainerStatus(ctx, container); err != nil {
			return fmt.Errorf("failed to update status: %w", err)
		}
		return nil
	}

	log = log.WithValues("nodeID", node.ID())

	// If the node is not started, start it.
	if !node.Started() {
		log.Info("Starting webmesh node for container")
		rtt := meshtransport.JoinRoundTripperFunc(func(ctx context.Context, _ *v1.JoinRequest) (*v1.JoinResponse, error) {
			// Retrieve the peer we created earlier
			peer, err := r.Provider.MeshDB().Peers().Get(ctx, node.ID())
			if err != nil {
				return nil, fmt.Errorf("failed to get registered peer for container: %w", err)
			}
			// Compute the current topology for the container.
			peers, err := meshnet.WireGuardPeersFor(ctx, r.Provider.MeshDB(), node.ID())
			if err != nil {
				return nil, fmt.Errorf("failed to get peers for container: %w", err)
			}
			return &v1.JoinResponse{
				MeshDomain: r.Host.Node().Domain(),
				// We always return both networks regardless of IP preferences.
				NetworkIPv4: r.Host.Node().Network().NetworkV4().String(),
				NetworkIPv6: r.Host.Node().Network().NetworkV6().String(),
				// Addresses as allocated above.
				AddressIPv4: peer.PrivateIPv4,
				AddressIPv6: peer.PrivateIPv6,
				Peers:       peers,
			}, nil
		})
		err := node.Connect(ctx, meshnode.ConnectOptions{
			StorageProvider:  &NoOpStorageCloser{r.Provider},
			MaxJoinRetries:   10,
			JoinRoundTripper: rtt,
			LeaveRoundTripper: meshtransport.LeaveRoundTripperFunc(func(ctx context.Context, req *v1.LeaveRequest) (*v1.LeaveResponse, error) {
				// No-op, we clean up in the finalizers
				return &v1.LeaveResponse{}, nil
			}),
			NetworkOptions: meshnet.Options{
				NetNs:           container.Spec.Netns,
				InterfaceName:   container.Spec.IfName,
				ForceReplace:    true,
				MTU:             container.Spec.MTU,
				ZoneAwarenessID: container.Spec.NodeName,
				DisableIPv4:     container.Spec.DisableIPv4,
				DisableIPv6:     container.Spec.DisableIPv6,
				// Maybe by configuration?
				RecordMetrics:         false,
				RecordMetricsInterval: 0,
			},
			DirectPeers: func() map[meshtypes.NodeID]v1.ConnectProtocol {
				peers := make(map[meshtypes.NodeID]v1.ConnectProtocol)
				for _, n := range r.containerNodes {
					if n.ID() == node.ID() {
						continue
					}
					peers[n.ID()] = v1.ConnectProtocol_CONNECT_NATIVE
				}
				return peers
			}(),
			PreferIPv6: !container.Spec.DisableIPv6,
		})
		if err != nil {
			log.Error(err, "Failed to connect meshnode to network")
			r.setFailedStatus(ctx, container, err)
			// Create a new node on the next reconcile.
			delete(r.containerNodes, req.NamespacedName)
			return fmt.Errorf("failed to connect node: %w", err)
		}
		// Update the status to starting.
		log.Info("Updating container interface status to starting")
		container.Status.InterfaceStatus = cniv1.InterfaceStatusStarting
		if err := r.updateContainerStatus(ctx, container); err != nil {
			return fmt.Errorf("failed to update status: %w", err)
		}
		return nil
	}

	log.Info("Ensuring the container webmesh node is ready")
	select {
	case <-node.Ready():
		hwaddr, _ := node.Network().WireGuard().HardwareAddr()
		log.Info("Webmesh node for container is running",
			"interfaceName", node.Network().WireGuard().Name(),
			"macAddress", hwaddr.String(),
			"ipv4Address", validOrNone(node.Network().WireGuard().AddressV4()),
			"ipv4Address", validOrNone(node.Network().WireGuard().AddressV6()),
			"networkV4", validOrNone(node.Network().NetworkV4()),
			"networkV6", validOrNone(node.Network().NetworkV6()),
		)
		updated, err := r.ensureInterfaceReadyStatus(ctx, container, node)
		if err != nil {
			log.Error(err, "Failed to update container status")
			return fmt.Errorf("failed to update container status: %w", err)
		}
		if updated {
			// Return and continue on the next reconcile.
			return nil
		}
	case <-ctx.Done():
		// Update the status to failed.
		log.Error(ctx.Err(), "Timed out waiting for mesh node to start")
		// Don't delete the node or set it to failed yet, maybe it'll be ready on the next reconcile.
		return ctx.Err()
	}

	// Register the node to the storage provider.
	wireguardPort, err := node.Network().WireGuard().ListenPort()
	if err != nil {
		// Something went terribly wrong, we need to recreate the node.
		defer func() {
			if err := node.Close(ctx); err != nil {
				log.Error(err, "Failed to stop mesh node for container")
			}
		}()
		delete(r.containerNodes, req.NamespacedName)
		r.setFailedStatus(ctx, container, err)
		return fmt.Errorf("failed to get wireguard port: %w", err)
	}
	encoded, err := node.Key().PublicKey().Encode()
	if err != nil {
		// Something went terribly wrong, we need to recreate the node.
		defer func() {
			if err := node.Close(ctx); err != nil {
				log.Error(err, "Failed to stop mesh node for container")
			}
		}()
		delete(r.containerNodes, req.NamespacedName)
		r.setFailedStatus(ctx, container, err)
		return fmt.Errorf("failed to encode public key: %w", err)
	}
	// Detect the current endpoints on the machine.
	eps, err := endpoints.Detect(ctx, endpoints.DetectOpts{
		DetectPrivate:        true, // Required for finding endpoints for other containers on the local node.
		DetectIPv6:           !container.Spec.DisableIPv6,
		AllowRemoteDetection: r.Manager.RemoteEndpointDetection,
		SkipInterfaces: func() []string {
			var out []string
			for _, n := range r.containerNodes {
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
	// Register the peer's endpoints.
	log.Info("Registering peer endpoints",
		"wireguardPort", wireguardPort,
		"primaryEndpoint", eps.FirstPublicAddr().String(),
		"wireguardEndpoints", wgeps,
	)
	err = r.Provider.MeshDB().Peers().Put(ctx, meshtypes.MeshNode{
		MeshNode: &v1.MeshNode{
			Id:                 node.ID().String(),
			PublicKey:          encoded,
			WireguardEndpoints: wgeps,
			ZoneAwarenessID:    container.Spec.NodeName,
			PrivateIPv4:        validOrEmpty(node.Network().WireGuard().AddressV4()),
			PrivateIPv6:        validOrEmpty(node.Network().WireGuard().AddressV6()),
		},
	})
	if err != nil {
		// Try again on the next reconcile.
		log.Error(err, "Failed to register peer")
		return fmt.Errorf("failed to register peer: %w", err)
	}
	// Make sure all MeshEdges are up to date for this node.
	log.Info("Forcing sync of peers and topology")
	peers, err := r.Provider.MeshDB().Peers().List(
		ctx,
		meshstorage.FilterAgainstNode(node.ID()),
		meshstorage.FilterByZoneID(container.Spec.NodeName),
	)
	if err != nil {
		// Try again on the next reconcile.
		log.Error(err, "Failed to list peers")
		return fmt.Errorf("failed to list peers: %w", err)
	}
	for _, peer := range peers {
		if err := r.Provider.MeshDB().Peers().PutEdge(ctx, meshtypes.MeshEdge{MeshEdge: &v1.MeshEdge{
			Source: node.ID().String(),
			Target: peer.NodeID().String(),
			Weight: 50,
		}}); err != nil {
			// Try again on the next reconcile.
			log.Error(err, "Failed to create edge", "targetNode", peer.NodeID())
			return fmt.Errorf("failed to create edge: %w", err)
		}
	}
	// Force a sync of the node.
	err = node.Network().Peers().Sync(ctx)
	if err != nil {
		log.Error(err, "Failed to sync peers")
		// We don't return an error because the peer will eventually sync on its own.
	}
	return nil
}

// teardownPeerContainer tears down the given PeerContainer.
func (r *PeerContainerReconciler) teardownPeerContainer(ctx context.Context, req ctrl.Request, container *cniv1.PeerContainer) error {
	log := log.FromContext(ctx)
	node, ok := r.containerNodes[req.NamespacedName]
	if !ok {
		log.Info("Mesh node for container not found, we must have already deleted")
	} else {
		if err := node.Close(ctx); err != nil {
			log.Error(err, "Failed to stop mesh node for container")
		}
		delete(r.containerNodes, req.NamespacedName)
	}
	// Make sure we've deleted the mesh peer from the database.
	if err := r.Provider.MeshDB().Peers().Delete(ctx, meshtypes.NodeID(req.Name)); err != nil {
		if !mesherrors.Is(err, mesherrors.ErrNodeNotFound) {
			log.Error(err, "Failed to delete peer from meshdb")
			return fmt.Errorf("failed to delete peer: %w", err)
		}
	}
	if controllerutil.ContainsFinalizer(container, cniv1.PeerContainerFinalizer) {
		updated := controllerutil.RemoveFinalizer(container, cniv1.PeerContainerFinalizer)
		if updated {
			log.Info("Removing finalizer from container")
			if err := r.Update(ctx, container); err != nil {
				return fmt.Errorf("failed to remove finalizer: %w", err)
			}
		}
	}
	return nil
}

func (r *PeerContainerReconciler) ensureInterfaceReadyStatus(ctx context.Context, container *cniv1.PeerContainer, node meshnode.Node) (updated bool, err error) {
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
	if r.dns != nil {
		// Add ourself as a DNS server for the container.
		var addr netip.Addr
		if container.Spec.DisableIPv4 && r.Host.Node().Network().WireGuard().AddressV6().IsValid() {
			addr = r.Host.Node().Network().WireGuard().AddressV6().Addr()
		} else if r.Host.Node().Network().WireGuard().AddressV4().IsValid() {
			// Prefer IPv4 if it's available.
			addr = r.Host.Node().Network().WireGuard().AddressV4().Addr()
		}
		if addr.IsValid() {
			addrport := netip.AddrPortFrom(addr, uint16(r.dns.ListenPort()))
			if len(container.Status.DNSServers) == 0 || container.Status.DNSServers[0] != addrport.String() {
				container.Status.DNSServers = []string{addrport.String()}
				updateStatus = true
			}
		}
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
		return true, r.updateContainerStatus(ctx, container)
	}
	return false, nil
}

func (r *PeerContainerReconciler) setFailedStatus(ctx context.Context, container *cniv1.PeerContainer, reason error) {
	container.Status.InterfaceStatus = cniv1.InterfaceStatusFailed
	container.Status.Error = reason.Error()
	err := r.updateContainerStatus(ctx, container)
	if err != nil {
		log.FromContext(ctx).Error(err, "Failed to update container status")
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
