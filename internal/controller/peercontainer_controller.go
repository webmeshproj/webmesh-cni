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

	v1 "github.com/webmeshproj/api/v1"
	"github.com/webmeshproj/storage-provider-k8s/provider"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnet/endpoints"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	netutil "github.com/webmeshproj/webmesh/pkg/meshnet/util"
	meshnode "github.com/webmeshproj/webmesh/pkg/meshnode"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/ipam"
	meshstorage "github.com/webmeshproj/webmesh/pkg/storage"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
)

// PeerContainerReconciler reconciles a PeerContainer object
type PeerContainerReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	Provider   *provider.Provider
	NetworkV4  netip.Prefix
	NetworkV6  netip.Prefix
	MeshDomain string
	nodes      map[types.NamespacedName]meshnode.Node
	mu         sync.Mutex
}

//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *PeerContainerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	var container cniv1.PeerContainer
	if err := r.Get(ctx, req.NamespacedName, &container); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// Stop the mesh node for this container.
			log.Info("Stopping mesh node for container", "container", req.NamespacedName)
			return ctrl.Result{}, r.teardownPeerContainer(ctx, req.NamespacedName)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Info("Reconciling mesh node for container", "container", req.NamespacedName)
	return ctrl.Result{}, r.reconcilePeerContainer(ctx, &container)
}

// reconcilePeerContainer reconciles the given PeerContainer.
func (r *PeerContainerReconciler) reconcilePeerContainer(ctx context.Context, container *cniv1.PeerContainer) error {
	log := log.FromContext(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nodes == nil {
		r.nodes = make(map[types.NamespacedName]meshnode.Node)
	}
	// Check if we have registered the node yet
	name := types.NamespacedName{Name: container.Spec.NodeName}
	nodeID := meshtypes.NodeID(container.Spec.ContainerID)
	node, ok := r.nodes[name]
	if !ok {
		// We need to create the node.
		log.Info("Mesh node for container not found, we must need to create it", "container", name)
		// Detect the current endpoints on the machine.
		eps, err := endpoints.Detect(ctx, endpoints.DetectOpts{
			DetectIPv6:           true,
			DetectPrivate:        true,
			AllowRemoteDetection: true,
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
		if container.Spec.IPv4Address == "" && !container.Spec.DisableIPv4 {
			// If the container does not have an IPv4 address and we are not disabling
			// IPv4, use the default plugin to allocate one.
			plugin := ipam.NewWithDB(r.Provider.MeshDB())
			alloc, err := plugin.Allocate(ctx, &v1.AllocateIPRequest{
				NodeID: nodeID.String(),
				Subnet: r.NetworkV4.String(),
			})
			if err != nil {
				r.setFailedStatus(ctx, container, err)
				return fmt.Errorf("failed to allocate IPv4 address: %w", err)
			}
			container.Spec.IPv4Address = alloc.GetIp()
		}
		// Try to register this node as a peer directly via the API.
		err = r.Provider.MeshDB().Peers().Put(ctx, meshtypes.MeshNode{
			MeshNode: &v1.MeshNode{
				Id:                 container.Spec.ContainerID,
				PublicKey:          encoded,
				PrimaryEndpoint:    eps.FirstPublicAddr().String(),
				WireguardEndpoints: wgeps,
				ZoneAwarenessID:    container.Spec.NodeName,
				PrivateIPv4:        container.Spec.IPv4Address,
				PrivateIPv6:        netutil.AssignToPrefix(r.NetworkV6, key.PublicKey()).String(),
			},
		})
		if err != nil {
			r.setFailedStatus(ctx, container, err)
			return fmt.Errorf("failed to register peer: %w", err)
		}
		// Create edges for all other nodes in the same zone.
		peers, err := r.Provider.MeshDB().Peers().List(
			ctx,
			meshstorage.NotNodeIDFilter(nodeID),
			meshstorage.ZoneIDFilter(container.Spec.NodeName),
		)
		if err != nil {
			r.setFailedStatus(ctx, container, err)
			return fmt.Errorf("failed to list peers: %w", err)
		}
		for _, peer := range peers {
			if err := r.Provider.MeshDB().Peers().PutEdge(ctx, meshtypes.MeshEdge{MeshEdge: &v1.MeshEdge{
				Source: nodeID.String(),
				Target: peer.NodeID().String(),
			}}); err != nil {
				r.setFailedStatus(ctx, container, err)
				return fmt.Errorf("failed to create edge: %w", err)
			}
		}
		r.nodes[name] = meshnode.NewWithLogger(logging.NewLogger(container.Spec.LogLevel), meshnode.Config{
			Key:             key,
			NodeID:          container.Spec.ContainerID,
			ZoneAwarenessID: container.Spec.NodeName,
			DisableIPv4:     container.Spec.DisableIPv4,
			DisableIPv6:     container.Spec.DisableIPv6,
		})
		// Update the status to created.
		container.Status.Status = cniv1.InterfaceStatusCreated
		if err := r.Status().Update(ctx, container); err != nil {
			return fmt.Errorf("failed to update status: %w", err)
		}
		return nil
	}
	// If the node is not started, start it.
	if !node.Started() {
		peer, err := r.Provider.MeshDB().Peers().Get(ctx, meshtypes.NodeID(container.Spec.ContainerID))
		if err != nil {
			// Try to update the status to failed.
			container.Status.Status = cniv1.InterfaceStatusFailed
			container.Status.Error = err.Error()
			if err := r.Status().Update(ctx, container); err != nil {
				log.Error(err, "Failed to update container status", "container", container)
			}
			r.setFailedStatus(ctx, container, err)
			return fmt.Errorf("failed to get peer: %w", err)
		}
		key, err := crypto.DecodePublicKey(peer.PublicKey)
		if err != nil {
			// Try to update the status to failed.
			container.Status.Status = cniv1.InterfaceStatusFailed
			container.Status.Error = err.Error()
			if err := r.Status().Update(ctx, container); err != nil {
				log.Error(err, "Failed to update container status", "container", container)
			}
			r.setFailedStatus(ctx, container, err)
			return fmt.Errorf("failed to decode public key: %w", err)
		}
		rtt := transport.JoinRoundTripperFunc(func(ctx context.Context, _ *v1.JoinRequest) (*v1.JoinResponse, error) {
			// Build the current network topology and return to the peer. They'll use
			// the storage provider to subscribe to changes.
			peers, err := meshnet.WireGuardPeersFor(ctx, r.Provider.MeshDB(), nodeID)
			if err != nil {
				return nil, fmt.Errorf("failed to get peers: %w", err)
			}
			return &v1.JoinResponse{
				MeshDomain:  r.MeshDomain,
				NetworkIPv4: r.NetworkV4.String(),
				NetworkIPv6: r.NetworkV6.String(),
				AddressIPv6: netutil.AssignToPrefix(r.NetworkV6, key).String(),
				AddressIPv4: container.Spec.IPv4Address,
				Peers:       peers,
			}, nil
		})
		err = node.Connect(ctx, meshnode.ConnectOptions{
			StorageProvider:  r.Provider,
			MaxJoinRetries:   10,
			JoinRoundTripper: rtt,
			NetworkOptions: meshnet.Options{
				NodeID:                meshtypes.NodeID(container.Spec.ContainerID),
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
			return fmt.Errorf("failed to connect node: %w", err)
		}
		// Update the status to starting.
		container.Status.Status = cniv1.InterfaceStatusStarting
		if err := r.Status().Update(ctx, container); err != nil {
			return fmt.Errorf("failed to update status: %w", err)
		}
		return nil
	}
	select {
	case <-node.Ready():
		var updateStatus bool
		ifname := node.Network().WireGuard().Name()
		addrv4 := node.Network().WireGuard().AddressV4().String()
		addrv6 := node.Network().WireGuard().AddressV6().String()
		if container.Status.Status != cniv1.InterfaceStatusRunning {
			// Update the status to running and sets its IP address.
			container.Status.Status = cniv1.InterfaceStatusRunning
			updateStatus = true
		}
		if container.Status.IPv4Address != addrv4 {
			container.Status.IPv4Address = addrv4
			updateStatus = true
		}
		if container.Status.IPv6Address != addrv6 {
			container.Status.IPv6Address = addrv6
			updateStatus = true
		}
		if container.Status.InterfaceName != ifname {
			container.Status.InterfaceName = ifname
			updateStatus = true
		}
		if container.Status.Error != "" {
			container.Status.Error = ""
			updateStatus = true
		}
		if updateStatus {
			if err := r.Status().Update(ctx, container); err != nil {
				return fmt.Errorf("failed to update status: %w", err)
			}
		}
	case <-ctx.Done():
		// Update the status to failed.
		r.setFailedStatus(ctx, container, ctx.Err())
		return ctx.Err()
	}
	// Make sure all MeshEdges are up to date for this node.
	peers, err := r.Provider.MeshDB().Peers().List(
		ctx,
		meshstorage.NotNodeIDFilter(nodeID),
		meshstorage.ZoneIDFilter(container.Spec.NodeName),
	)
	if err != nil {
		return fmt.Errorf("failed to list peers: %w", err)
	}
	for _, peer := range peers {
		if err := r.Provider.MeshDB().Peers().PutEdge(ctx, meshtypes.MeshEdge{MeshEdge: &v1.MeshEdge{
			Source: nodeID.String(),
			Target: peer.NodeID().String(),
		}}); err != nil {
			return fmt.Errorf("failed to create edge: %w", err)
		}
	}
	return nil
}

// teardownPeerContainer tears down the given PeerContainer.
func (r *PeerContainerReconciler) teardownPeerContainer(ctx context.Context, name types.NamespacedName) error {
	log := log.FromContext(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	node, ok := r.nodes[name]
	if !ok {
		log.Info("Mesh node for container not found, we must have already deleted it", "container", name)
	} else {
		if err := node.Close(ctx); err != nil {
			log.Error(err, "Failed to stop mesh node for container", "container", name)
		}
		delete(r.nodes, name)
	}
	// Make sure we've deleted the mesh peer from the database.
	if err := r.Provider.MeshDB().Peers().Delete(ctx, meshtypes.NodeID(name.Name)); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to delete peer: %w", err)
		}
	}
	return nil
}

func (r *PeerContainerReconciler) setFailedStatus(ctx context.Context, container *cniv1.PeerContainer, reason error) {
	container.Status.Status = cniv1.InterfaceStatusFailed
	container.Status.Error = reason.Error()
	if err := r.Status().Update(ctx, container); err != nil {
		log.FromContext(ctx).Error(err, "Failed to update container status", "container", container)
	}
}

func (r *PeerContainerReconciler) nextAvailableWireGuardPort() (uint16, error) {
	const startPort uint16 = 51820
	const endPort uint16 = 65535
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

// SetupWithManager sets up the controller with the Manager.
func (r *PeerContainerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cniv1.PeerContainer{}).
		Complete(r)
}
