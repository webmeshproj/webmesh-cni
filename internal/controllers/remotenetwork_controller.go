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
	"strings"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"github.com/webmeshproj/storage-provider-k8s/provider"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnet/endpoints"
	netutil "github.com/webmeshproj/webmesh/pkg/meshnet/netutil"
	meshsys "github.com/webmeshproj/webmesh/pkg/meshnet/system"
	meshtransport "github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	meshnode "github.com/webmeshproj/webmesh/pkg/meshnode"
	meshplugins "github.com/webmeshproj/webmesh/pkg/plugins"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
	"github.com/webmeshproj/webmesh-cni/internal/config"
	"github.com/webmeshproj/webmesh-cni/internal/host"
	"github.com/webmeshproj/webmesh-cni/internal/ipam"
	"github.com/webmeshproj/webmesh-cni/internal/types"
)

//+kubebuilder:rbac:groups=cni.webmesh.io,resources=remotenetworks,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=remotenetworks/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=remotenetworks/finalizers,verbs=update

// RemoteNetworkReconciler ensures bridge connections to other clusters.
type RemoteNetworkReconciler struct {
	client.Client
	config.Config
	Provider *provider.Provider
	HostNode host.Node
	bridges  map[client.ObjectKey]meshnode.Node
	mu       sync.Mutex
}

// SetupWithManager sets up the controller with the Manager.
func (r *RemoteNetworkReconciler) SetupWithManager(mgr ctrl.Manager) (err error) {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cniv1.RemoteNetwork{}).
		Complete(r)
}

func (r *RemoteNetworkReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	log := log.FromContext(ctx)
	if !r.HostNode.Started() {
		// Request a requeue until the host is started.
		log.Info("Host node not ready yet, requeuing")
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 2}, nil
	}
	if r.bridges == nil {
		r.bridges = make(map[client.ObjectKey]meshnode.Node)
	}
	if r.Manager.ReconcileTimeout > 0 {
		log.V(1).Info("Setting reconcile timeout", "timeout", r.Manager.ReconcileTimeout)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Manager.ReconcileTimeout)
		defer cancel()
	}
	var nw cniv1.RemoteNetwork
	if err := r.Get(ctx, req.NamespacedName, &nw); err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Error(err, "Failed to lookup remote network")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	// Always ensure the type meta is set
	nw.TypeMeta = cniv1.RemoteNetworkTypeMeta
	if nw.GetDeletionTimestamp() != nil {
		// Stop the mesh node for this container.
		log.Info("Tearing down remote network bridge")
		return ctrl.Result{}, r.reconcileRemove(ctx, req.NamespacedName, &nw)
	}
	log.Info("Reconciling remote network bridge")
	err := r.reconcileNetwork(ctx, req.NamespacedName, &nw)
	if err != nil {
		log.Error(err, "Failed to reconcile remote network bridge")
		return ctrl.Result{}, err
	}

	if nw.Spec.AuthMethod != cniv1.RemoteAuthMethodKubernetes {
		// Request a requeue in a minute to ensure the bridge is still running
		// and all node edges are up to date.
		var requeueAfter time.Duration
		if nw.Spec.CheckInterval != nil {
			requeueAfter = nw.Spec.CheckInterval.Duration
		} else {
			requeueAfter = time.Minute
		}
		return ctrl.Result{Requeue: true, RequeueAfter: requeueAfter}, nil
	}
	return ctrl.Result{}, nil
}

func (r *RemoteNetworkReconciler) reconcileNetwork(ctx context.Context, key client.ObjectKey, nw *cniv1.RemoteNetwork) error {
	log := log.FromContext(ctx)
	// Ensure the finalizer on the network.
	if !controllerutil.ContainsFinalizer(nw, cniv1.RemoteNetworkFinalizer) {
		updated := controllerutil.AddFinalizer(nw, cniv1.RemoteNetworkFinalizer)
		if updated {
			log.Info("Adding finalizer to remote network")
			if err := r.Update(ctx, nw); err != nil {
				return fmt.Errorf("failed to add finalizer: %w", err)
			}
			return nil
		}
	}
	// Fetch any credentials if provided.
	var creds map[string][]byte
	if nw.Spec.Credentials != nil {
		var secret corev1.Secret
		if err := r.Get(ctx, client.ObjectKey{
			Name: nw.Spec.Credentials.Name,
			Namespace: func() string {
				if nw.Spec.Credentials.Namespace != "" {
					return nw.Spec.Credentials.Namespace
				}
				return key.Namespace
			}(),
		}, &secret); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return fmt.Errorf("failed to fetch credentials: %w", err)
			}
		}
		creds = secret.Data
	}

	// Ensure the bridge exists.
	bridge, ok := r.bridges[key]
	if !ok {
		// Create the bridge node with the configured attributes.
		log.Info("Webmesh node for bridge not found, we must need to create it")
		nodeID := string(r.HostNode.ID())
		privkey := r.HostNode.Node().Key()
		if nw.Spec.AuthMethod == cniv1.RemoteAuthMethodNative && len(creds) == 0 {
			// If there are no credentials configured, we assume we are using ID auth.
			// So our node ID needs to match the key.
			nodeID = privkey.ID()
		}
		node := NewNode(logging.NewLogger(r.Host.LogLevel, "json"), meshnode.Config{
			Key:             privkey,
			NodeID:          nodeID,
			ZoneAwarenessID: r.Host.NodeID,
			DisableIPv4:     nw.Spec.Network.DisableIPv4,
			DisableIPv6:     nw.Spec.Network.DisableIPv6,
		})
		r.bridges[key] = node
		// Update the status to created.
		log.Info("Updating bridge interface status to created")
		nw.Status.BridgeStatus = cniv1.BridgeStatusCreated
		if err := r.updateBridgeStatus(ctx, nw); err != nil {
			return fmt.Errorf("failed to update bridge status: %w", err)
		}
		return nil
	}

	// Ensure the bridge is running.
	if !bridge.Started() {
		log.Info("Starting webmesh node for remote network bridge")
		var err error
		switch nw.Spec.AuthMethod {
		case cniv1.RemoteAuthMethodNone, cniv1.RemoteAuthMethodNative:
			err = r.connectWithWebmeshAPI(ctx, nw, creds, bridge)
		case cniv1.RemoteAuthMethodKubernetes:
			kubeconfig, ok := creds[cniv1.KubeconfigKey]
			if !ok {
				err = fmt.Errorf("kubeconfig not provided in credentials")
				break
			}
			err = r.connectWithKubeconfig(ctx, nw, kubeconfig, bridge)
		default:
			err = fmt.Errorf("unknown auth method: %s", nw.Spec.AuthMethod)
		}
		if err != nil {
			log.Error(err, "Failed to connect bridge node to remote network")
			r.setFailedStatus(ctx, nw, err)
			// Create a new node on the next reconcile.
			delete(r.bridges, key)
			return fmt.Errorf("failed to connect bridge node: %w", err)
		}
		// Update the status to starting.
		log.Info("Updating bridge interface status to starting")
		nw.Status.BridgeStatus = cniv1.BridgeStatusStarting
		if err := r.updateBridgeStatus(ctx, nw); err != nil {
			return fmt.Errorf("failed to update bridge status: %w", err)
		}
		return nil
	}

	log.Info("Ensuring the bridge node is ready")
	select {
	case <-bridge.Ready():
		hwaddr, _ := bridge.Network().WireGuard().HardwareAddr()
		log.Info("Webmesh node for bridge is running",
			"interfaceName", bridge.Network().WireGuard().Name(),
			"macAddress", hwaddr.String(),
			"ipv4Address", validOrNone(bridge.Network().WireGuard().AddressV4()),
			"ipv4Address", validOrNone(bridge.Network().WireGuard().AddressV6()),
			"networkV4", validOrNone(bridge.Network().NetworkV4()),
			"networkV6", validOrNone(bridge.Network().NetworkV6()),
		)
		err := r.ensureBridgeReadyStatus(ctx, nw, bridge)
		if err != nil {
			log.Error(err, "Failed to update bridge status")
			return fmt.Errorf("failed to update bridge status: %w", err)
		}
	case <-ctx.Done():
		// Update the status to failed.
		log.Error(ctx.Err(), "Timed out waiting for bridge node to start")
		// Don't delete the node or set it to failed yet, maybe it'll be ready on the next reconcile.
		return ctx.Err()
	}

	log.Info("Ensuring local routes to remote network")
	err := r.Provider.MeshDB().Networking().PutRoute(ctx, meshtypes.Route{
		Route: &v1.Route{
			Name: r.localRouteName(nw),
			Node: r.HostNode.ID().String(),
			DestinationCIDRs: func() []string {
				var out []string
				if bridge.Network().NetworkV4().IsValid() {
					out = append(out, bridge.Network().NetworkV4().String())
				}
				if bridge.Network().NetworkV6().IsValid() {
					out = append(out, bridge.Network().NetworkV6().String())
				}
				return out
			}(),
		},
	})
	if err != nil {
		log.Error(err, "Failed to add local routes to remote network")
		return fmt.Errorf("failed to add local routes to remote network: %w", err)
	}
	return bridge.Network().Peers().Sync(ctx)
}

func (r *RemoteNetworkReconciler) connectWithWebmeshAPI(ctx context.Context, nw *cniv1.RemoteNetwork, creds map[string][]byte, bridge meshnode.Node) error {
	return fmt.Errorf("not implemented")
}

func (r *RemoteNetworkReconciler) connectWithKubeconfig(ctx context.Context, nw *cniv1.RemoteNetwork, kubeconfig []byte, bridge meshnode.Node) error {
	log := log.FromContext(ctx)
	// Detect the current endpoints on the machine.
	eps, err := endpoints.Detect(ctx, endpoints.DetectOpts{
		DetectPrivate:        true, // TODO: Not necessarily required in this case.
		DetectIPv6:           !nw.Spec.Network.DisableIPv6,
		AllowRemoteDetection: r.Manager.RemoteEndpointDetection,
		SkipInterfaces: func() []string {
			out := []string{r.HostNode.Node().Network().WireGuard().Name()}
			for _, n := range r.bridges {
				if n.Started() {
					out = append(out, n.Network().WireGuard().Name())
				}
			}
			return out
		}(),
	})
	if err != nil {
		return fmt.Errorf("failed to detect endpoints: %w", err)
	}
	// Create a connection to the remote cluster storage
	cfg, err := types.NewRestConfigFromBytes(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create client from kubeconfig: %w", err)
	}
	namespace := func() string {
		if nw.Spec.RemoteNamespace != "" {
			return nw.Spec.RemoteNamespace
		}
		return r.Host.Namespace
	}()
	db, err := provider.NewObserverWithConfig(cfg, provider.Options{
		NodeID:    bridge.ID().String(),
		Namespace: namespace,
	})
	if err != nil {
		return fmt.Errorf("failed to create meshdb observer: %w", err)
	}
	err = db.StartManaged(context.Background())
	if err != nil {
		return fmt.Errorf("failed to start meshdb observer: %w", err)
	}
	handleErr := func(cause error) error {
		if err := db.Close(); err != nil {
			log.Error(err, "Failed to stop meshdb observer")
		}
		return cause
	}
	// Retrieve the state of the remote network.
	remoteState, err := db.MeshDB().MeshState().GetMeshState(ctx)
	if err != nil {
		return fmt.Errorf("failed to get remote mesh state: %w", err)
	}
	// Create a peer for ourselves on the remote network.
	var ipv4addr string
	if !nw.Spec.Network.DisableIPv4 {
		// Make sure we get an IPv4 allocation on the remote network.
		ipam, err := ipam.NewAllocator(cfg, ipam.Config{
			IPAM: meshplugins.IPAMConfig{},
			Lock: ipam.LockConfig{
				ID:                 r.Host.NodeID,
				Namespace:          namespace,
				LockDuration:       r.Host.LockDuration,
				LockAcquireTimeout: r.Host.LockAcquireTimeout,
			},
			Network: remoteState.NetworkV4(),
		})
		if err != nil {
			return handleErr(fmt.Errorf("failed to create IPAM allocator: %w", err))
		}
		err = ipam.Locker().Acquire(ctx)
		if err != nil {
			return handleErr(fmt.Errorf("failed to acquire IPAM lock: %w", err))
		}
		defer ipam.Locker().Release(ctx)
		alloc, err := ipam.Allocate(ctx, bridge.ID())
		if err != nil {
			return handleErr(fmt.Errorf("failed to allocate IPv4 address: %w", err))
		}
		ipv4addr = alloc.String()
	}
	encoded, err := bridge.Key().PublicKey().Encode()
	if err != nil {
		return handleErr(fmt.Errorf("failed to encode public key: %w", err))
	}
	peer := meshtypes.MeshNode{
		MeshNode: &v1.MeshNode{
			Id:              bridge.ID().String(),
			PublicKey:       encoded,
			ZoneAwarenessID: r.Host.NodeID,
			PrivateIPv4:     ipv4addr,
			PrivateIPv6: func() string {
				if nw.Spec.Network.DisableIPv6 {
					return ""
				}
				return netutil.AssignToPrefix(remoteState.NetworkV6(), bridge.Key().PublicKey()).String()
			}(),
		},
	}
	log.Info("Registering ourselves with the remote meshdb", "peer", peer.MeshNode)
	if err := db.MeshDB().Peers().Put(ctx, peer); err != nil {
		return handleErr(fmt.Errorf("failed to register peer: %w", err))
	}
	log.Info("Registering local routes with the remote meshdb")
	routeName := fmt.Sprintf("%s-node-gw", bridge.ID().String())
	err = db.MeshDB().Networking().PutRoute(ctx, meshtypes.Route{
		Route: &v1.Route{
			Name: routeName,
			Node: bridge.ID().String(),
			DestinationCIDRs: func() []string {
				var out []string
				for _, ep := range eps {
					out = append(out, ep.String())
				}
				if r.Host.Network.PodCIDR != "" {
					for _, addr := range strings.Split(r.Host.Network.PodCIDR, ",") {
						out = append(out, strings.TrimSpace(addr))
					}
				}
				if r.Host.Network.ServiceCIDR != "" {
					for _, addr := range strings.Split(r.Host.Network.ServiceCIDR, ",") {
						out = append(out, strings.TrimSpace(addr))
					}
				}
				return out
			}(),
		},
	})
	if err != nil {
		return handleErr(fmt.Errorf("failed to register route: %w", err))
	}
	// Add ourselves as an observer to the remote consensus group.
	// This should trigger the remote CNI to edge us to all other remote CNI nodes.
	err = db.Consensus().AddObserver(ctx, meshtypes.StoragePeer{
		StoragePeer: &v1.StoragePeer{
			Id:        bridge.ID().String(),
			PublicKey: encoded,
		},
	})
	if err != nil {
		return handleErr(fmt.Errorf("failed to register with remote as observer: %w", err))
	}
	// Setup a join transport using the client to the remote network.
	joinRTT := meshtransport.JoinRoundTripperFunc(func(ctx context.Context, _ *v1.JoinRequest) (*v1.JoinResponse, error) {
		// Retrieve the peer we created earlier
		peer, err := db.MeshDB().Peers().Get(ctx, bridge.ID())
		if err != nil {
			return nil, fmt.Errorf("failed to get registered peer for container: %w", err)
		}
		// Compute the current topology for the container.
		peers, err := meshnet.WireGuardPeersFor(ctx, db.MeshDB(), bridge.ID())
		if err != nil {
			return nil, fmt.Errorf("failed to get peers for container: %w", err)
		}
		return &v1.JoinResponse{
			MeshDomain: remoteState.Domain(),
			// We always return both networks regardless of IP preferences.
			NetworkIPv4: remoteState.NetworkV4().String(),
			NetworkIPv6: remoteState.NetworkV6().String(),
			// Addresses as allocated above.
			AddressIPv4: peer.PrivateIPv4,
			AddressIPv6: peer.PrivateIPv6,
			Peers:       peers,
		}, nil
	})
	leaveRTT := meshtransport.LeaveRoundTripperFunc(func(ctx context.Context, req *v1.LeaveRequest) (*v1.LeaveResponse, error) {
		// We remove ourself from the remote network.
		if err := db.MeshDB().Networking().DeleteRoute(ctx, routeName); err != nil {
			log.Error(err, "Failed to remove route from remote meshdb")
		}
		if err := db.MeshDB().Peers().Delete(ctx, bridge.ID()); err != nil {
			log.Error(err, "Failed to remove peer from remote meshdb")
		}
		return &v1.LeaveResponse{}, db.Consensus().RemovePeer(ctx, meshtypes.StoragePeer{
			StoragePeer: &v1.StoragePeer{
				Id: bridge.ID().String(),
			},
		}, false)
	})
	log.Info("Connecting to remote network")
	err = bridge.Connect(ctx, meshnode.ConnectOptions{
		StorageProvider:   db,
		MaxJoinRetries:    10,
		JoinRoundTripper:  joinRTT,
		LeaveRoundTripper: leaveRTT,
		NetworkOptions: meshnet.Options{
			ZoneAwarenessID: r.Host.NodeID,
			DisableIPv4:     nw.Spec.Network.DisableIPv4,
			DisableIPv6:     nw.Spec.Network.DisableIPv6,
			ListenPort:      nw.Spec.Network.WireGuardPort,
			MTU: func() int {
				if nw.Spec.Network.MTU > 0 {
					return nw.Spec.Network.MTU
				}
				return meshsys.DefaultMTU
			}(),
			InterfaceName: func() string {
				if nw.Spec.Network.InterfaceName != "" {
					return nw.Spec.Network.InterfaceName
				}
				return types.IfNameFromID(nw.GetName())
			}(),
			ForceReplace: true,
			// Maybe by configuration?
			RecordMetrics:         false,
			RecordMetricsInterval: 0,
		},
		PreferIPv6: !nw.Spec.Network.DisableIPv6,
	})
	if err != nil {
		return handleErr(fmt.Errorf("failed to connect to remote network: %w", err))
	}
	log.Info("Bridge node is connected, registering endpoints with remote network")
	wireguardPort, err := bridge.Network().WireGuard().ListenPort()
	if err != nil {
		defer bridge.Close(ctx)
		return fmt.Errorf("failed to get wireguard listen port: %w", err)
	}
	var wgeps []string
	for _, ep := range eps.AddrPorts(uint16(wireguardPort)) {
		wgeps = append(wgeps, ep.String())
	}
	// Patch the peer we created earlier with our wireguard endpoints
	peer = meshtypes.MeshNode{
		MeshNode: &v1.MeshNode{
			Id:        bridge.ID().String(),
			PublicKey: encoded,
			PrimaryEndpoint: func() string {
				if eps.FirstPublicAddr().IsValid() {
					return eps.FirstPublicAddr().String()
				}
				return eps.PrivateAddrs()[0].String()
			}(),
			WireguardEndpoints: wgeps,
			ZoneAwarenessID:    r.Host.NodeID,
			PrivateIPv4:        ipv4addr,
			PrivateIPv6: func() string {
				if nw.Spec.Network.DisableIPv6 {
					return ""
				}
				return netutil.AssignToPrefix(remoteState.NetworkV6(), bridge.Key().PublicKey()).String()
			}(),
			// TODO: Optionally advertise forward DNS.
			Features: nil,
		},
	}
	log.Info("Updating peer with wireguard endpoints", "peer", peer.MeshNode)
	if err := db.MeshDB().Peers().Put(ctx, peer); err != nil {
		defer bridge.Close(ctx)
		return fmt.Errorf("failed to update peer with wireguard endpoints: %w", err)
	}
	return err
}

func (r *RemoteNetworkReconciler) reconcileRemove(ctx context.Context, key client.ObjectKey, nw *cniv1.RemoteNetwork) error {
	log := log.FromContext(ctx)
	// Make sure the bridge connection is shutdown
	if bridge, ok := r.bridges[key]; ok {
		err := bridge.Close(ctx)
		if err != nil {
			log.Error(err, "Failed to close bridge node")
		}
		delete(r.bridges, key)
	}
	// Make sure we've removed routes to the remote network.
	err := r.Provider.MeshDB().Networking().DeleteRoute(ctx, r.localRouteName(nw))
	if err != nil {
		log.Error(err, "Failed to remove local routes to remote network")
		// Try again on the next reconcile.
		return fmt.Errorf("failed to remove local routes to remote network: %w", err)
	}
	// Remove the finalizer
	if controllerutil.ContainsFinalizer(nw, cniv1.RemoteNetworkFinalizer) {
		updated := controllerutil.RemoveFinalizer(nw, cniv1.RemoteNetworkFinalizer)
		if updated {
			log.Info("Removing finalizer from remote network")
			if err := r.Update(ctx, nw); err != nil {
				return fmt.Errorf("failed to remove finalizer: %w", err)
			}
		}
	}
	return nil
}

func (r *RemoteNetworkReconciler) localRouteName(nw *cniv1.RemoteNetwork) string {
	return fmt.Sprintf("%s-%s-bridge", r.HostNode.ID(), nw.GetName())
}

func (r *RemoteNetworkReconciler) setFailedStatus(ctx context.Context, bridge *cniv1.RemoteNetwork, reason error) {
	bridge.Status.BridgeStatus = cniv1.BridgeStatusFailed
	bridge.Status.Error = reason.Error()
	err := r.updateBridgeStatus(ctx, bridge)
	if err != nil {
		log.FromContext(ctx).Error(err, "Failed to update container status")
	}
}

func (r *RemoteNetworkReconciler) updateBridgeStatus(ctx context.Context, bridge *cniv1.RemoteNetwork) error {
	bridge.SetManagedFields(nil)
	err := r.Status().Patch(ctx,
		bridge,
		client.Apply,
		client.ForceOwnership,
		client.FieldOwner(cniv1.FieldOwner),
	)
	if err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}
	return nil
}

func (r *RemoteNetworkReconciler) ensureBridgeReadyStatus(ctx context.Context, nw *cniv1.RemoteNetwork, node meshnode.Node) (err error) {
	log := log.FromContext(ctx)
	// Update the status to running and sets its IP address.
	var updateStatus bool
	origStatus := nw.Status
	addrV4 := validOrEmpty(node.Network().WireGuard().AddressV4())
	addrV6 := validOrEmpty(node.Network().WireGuard().AddressV6())
	netv4 := validOrEmpty(node.Network().NetworkV4())
	netv6 := validOrEmpty(node.Network().NetworkV6())
	if nw.Status.BridgeStatus != cniv1.BridgeStatusRunning {
		// Update the status to running and sets its IP address.
		nw.Status.BridgeStatus = cniv1.BridgeStatusRunning
		updateStatus = true
	}
	hwaddr, _ := node.Network().WireGuard().HardwareAddr()
	if nw.Status.MACAddress != hwaddr.String() {
		nw.Status.MACAddress = hwaddr.String()
		updateStatus = true
	}

	if nw.Status.IPv4Address != addrV4 {
		nw.Status.IPv4Address = addrV4
		updateStatus = true
	}

	if nw.Status.IPv6Address != addrV6 {
		nw.Status.IPv6Address = addrV6
		updateStatus = true
	}
	if nw.Status.NetworkV4 != netv4 {
		nw.Status.NetworkV4 = netv4
		updateStatus = true
	}
	if nw.Status.NetworkV6 != netv6 {
		nw.Status.NetworkV6 = netv6
		updateStatus = true
	}
	if nw.Status.InterfaceName != node.Network().WireGuard().Name() {
		nw.Status.InterfaceName = node.Network().WireGuard().Name()
		updateStatus = true
	}
	if nw.Status.Error != "" {
		nw.Status.Error = ""
		updateStatus = true
	}
	// TODO: Lookup our direct peers and populate the status
	if updateStatus {
		log.Info("Updating container interface status",
			"newStatus", nw.Status,
			"oldStatus", origStatus,
		)
		return r.updateBridgeStatus(ctx, nw)
	}
	return nil
}
