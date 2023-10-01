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
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnode"
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
	Scheme *runtime.Scheme

	nodes map[types.NamespacedName]meshnode.Node
	mu    sync.Mutex
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
	// Check if we have started the node yet.
	name := types.NamespacedName{Name: container.Spec.NodeName}
	node, ok := r.nodes[name]
	if !ok {
		log.Info("Mesh node for container not found, we must need to create it", "container", name)
		// We need to create the node.
		key, err := crypto.GenerateKey()
		if err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}
		r.nodes[name] = meshnode.NewWithLogger(logging.NewLogger(container.Spec.LogLevel), meshnode.Config{
			NodeID:          container.Spec.ContainerID,
			Key:             key,
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
		err := node.Connect(ctx, meshnode.ConnectOptions{
			StorageProvider:  nil, // Need a global provider we give all containers.
			JoinRoundTripper: nil, // Needs a nil one.
			NetworkOptions: meshnet.Options{
				NodeID:                meshtypes.NodeID(container.Spec.ContainerID),
				InterfaceName:         container.Spec.IfName,
				ForceReplace:          true,
				ListenPort:            0, // TODO
				MTU:                   container.Spec.MTU,
				RecordMetrics:         false, // Maybe by configuration?
				RecordMetricsInterval: 0,
				StoragePort:           0,
				GRPCPort:              0,
				ZoneAwarenessID:       container.Spec.NodeName,
				DisableIPv4:           container.Spec.DisableIPv4,
				DisableIPv6:           container.Spec.DisableIPv6,
				Relays:                meshnet.RelayOptions{}, // TODO
			},
			MaxJoinRetries:     1,
			PrimaryEndpoint:    netip.Addr{},
			WireGuardEndpoints: []netip.AddrPort{},
			Routes:             []netip.Prefix{},
			DirectPeers:        map[string]v1.ConnectProtocol{},
			PreferIPv6:         !container.Spec.DisableIPv6,
		})
		if err != nil {
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
		container.Status.Error = ctx.Err().Error()
		container.Status.Status = cniv1.InterfaceStatusFailed
		if err := r.Status().Update(ctx, container); err != nil {
			return fmt.Errorf("failed to update status: %w", err)
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
	}
	if err := node.Close(ctx); err != nil {
		log.Error(err, "Failed to stop mesh node for container", "container", name)
	}
	delete(r.nodes, name)
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PeerContainerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cniv1.PeerContainer{}).
		Complete(r)
}
