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

	v1 "github.com/webmeshproj/api/v1"
	storagev1 "github.com/webmeshproj/storage-provider-k8s/api/storage/v1"
	"github.com/webmeshproj/storage-provider-k8s/provider"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// StoragePeerFinalizer is the StoragePeer finalizer.
const StoragePeerFinalizer = "storagepeer.cniv1.webmesh.io"

//+kubebuilder:rbac:groups=storage.webmesh.io,resources=storagepeers/finalizers,verbs=get;update;patch

// NodeReconciler watches for nodes joining and leaving the cluster and ensures
// we have edges between the host node and them.
type NodeReconciler struct {
	client.Client
	Provider *provider.Provider
	NodeName string
}

// SetupWithManager sets up the node reconciler with the manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("node-edges").
		Watches(&storagev1.StoragePeer{}, &handler.EnqueueRequestForObject{}).
		Complete(r)
}

// Reconcile reconciles a node.
func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("Reconciling cluster CNI node")
	var node storagev1.StoragePeer
	if err := r.Get(ctx, req.NamespacedName, &node); err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Error(err, "Failed to lookup node")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if node.GetName() == r.NodeName {
		log.Info("Ignoring the local host node")
		return ctrl.Result{}, nil
	}
	if node.GetDeletionTimestamp() != nil {
		// Ensure the edge is removed.
		log.Info("Removing edge to node", "source", r.NodeName, "target", node.GetName())
		err := r.Provider.MeshDB().Peers().RemoveEdge(ctx, meshtypes.NodeID(r.NodeName), meshtypes.NodeID(node.GetId()))
		if err != nil {
			log.Error(err, "Failed to remove edge to node")
			return ctrl.Result{}, err
		}
		if controllerutil.ContainsFinalizer(&node, StoragePeerFinalizer) {
			updated := controllerutil.RemoveFinalizer(&node, StoragePeerFinalizer)
			if updated {
				log.Info("Removing finalizer from storage peer")
				if err := r.Update(ctx, &node); err != nil {
					return ctrl.Result{}, fmt.Errorf("failed to remove finalizer: %w", err)
				}
			}
		}
		return ctrl.Result{}, nil
	}
	// Make sure the finalizer is present first.
	if !controllerutil.ContainsFinalizer(&node, StoragePeerFinalizer) {
		updated := controllerutil.AddFinalizer(&node, StoragePeerFinalizer)
		if updated {
			log.V(1).Info("Adding finalizer to storage peer")
			if err := r.Update(ctx, &node); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
			}
			return ctrl.Result{}, nil
		}
	}
	log.Info("Ensuring edge to node", "source", r.NodeName, "target", node.GetName())
	err := r.Provider.MeshDB().Peers().PutEdge(ctx, meshtypes.MeshEdge{
		MeshEdge: &v1.MeshEdge{
			Source: r.NodeName,
			Target: node.GetId(),
			Weight: 1,
		},
	})
	if err != nil {
		log.Error(err, "Failed to add edge to node")
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}
