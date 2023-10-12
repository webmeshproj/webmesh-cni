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
	"errors"
	"fmt"
	"strings"

	v1 "github.com/webmeshproj/api/v1"
	"github.com/webmeshproj/storage-provider-k8s/provider"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// PodReconciler watches for pods of interest to the outside world
// that have become ready and ensures their features are advertised.
type PodReconciler struct {
	client.Client
	Provider     *provider.Provider
	DNSSelector  map[string]string
	DNSNamespace string
	DNSPort      string
}

//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// SetupWithManager sets up the node reconciler with the manager.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("pod-features").
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []ctrl.Request {
			pod := o.(*corev1.Pod)
			// Ignore pods that aren't in the DNS namespace.
			if pod.GetNamespace() != r.DNSNamespace {
				return nil
			}
			// Ignore pods that don't match the DNS selector.
			for k, v := range r.DNSSelector {
				if pod.GetLabels()[k] != v {
					return nil
				}
			}
			// Ignore host network pods.
			if pod.Spec.HostNetwork {
				return nil
			}
			// Only match pods that are running.
			if pod.Status.Phase != corev1.PodRunning {
				return nil
			}
			// Ignore deleted pods.
			if pod.GetDeletionTimestamp() != nil {
				return nil
			}
			// Make sure the pod has a container ID
			var hasContainerID bool
			for _, container := range pod.Status.ContainerStatuses {
				if container.ContainerID != "" {
					hasContainerID = true
					break
				}
			}
			if !hasContainerID {
				return nil
			}
			// Reconcile the pod.
			return []ctrl.Request{{
				NamespacedName: client.ObjectKeyFromObject(pod),
			}}
		})).
		Complete(r)
}

// Reconcile reconciles a node.
func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("Reconciling available features for pod")
	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Check if the pod has a container ID so we can match it to a peer
	for _, container := range pod.Status.ContainerStatuses {
		if container.ContainerID != "" {
			// There should be a peer in the storage provider with the truncated
			// container ID.
			log = log.WithValues("containerID", container.ContainerID)
			log.Info("Found container ID for pod")
			spl := strings.Split(container.ContainerID, "://")
			if len(spl) != 2 {
				log.Error(errors.New("invalid container ID"), "Failed to parse container ID")
				return ctrl.Result{}, nil
			}
			containerID := spl[1]
			// Get the peer from the storage provider.
			id := meshtypes.TruncateID(containerID)
			peer, err := r.Provider.MeshDB().Peers().Get(ctx, meshtypes.NodeID(id))
			if err != nil {
				log.Error(err, "Failed to lookup peer for container ID")
				return ctrl.Result{}, nil
			}
			// Ensure the pod has the DNS feature.
			if !peer.HasFeature(v1.Feature_MESH_DNS) {
				log.Info("Ensuring pod has DNS feature")
				peer.Features = append(peer.Features, &v1.FeaturePort{
					Feature: v1.Feature_MESH_DNS,
					Port: func() int32 {
						for _, container := range pod.Spec.Containers {
							for _, port := range container.Ports {
								if port.Name == r.DNSPort {
									return port.ContainerPort
								}
							}
						}
						// Assume the DNS port is 53.
						return 53
					}(),
				})
				if err := r.Provider.MeshDB().Peers().Put(ctx, peer); err != nil {
					log.Error(err, "Failed to add DNS feature to peer")
					return ctrl.Result{}, nil
				}
			}
			return ctrl.Result{}, nil
		}
	}
	return ctrl.Result{}, fmt.Errorf("pod has no container ID")
}
