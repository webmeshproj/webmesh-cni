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
	"sync"

	"github.com/webmeshproj/webmesh/pkg/meshnode"
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
	_ = log.FromContext(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.nodes == nil {
		r.nodes = make(map[types.NamespacedName]meshnode.Node)
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
