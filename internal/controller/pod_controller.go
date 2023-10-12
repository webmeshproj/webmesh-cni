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
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"github.com/webmeshproj/storage-provider-k8s/provider"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/webmeshproj/webmesh-cni/internal/host"
)

//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// PodReconciler watches for pods of interest to the outside world
// that have become ready and ensures their features are advertised.
type PodReconciler struct {
	client.Client
	Host         host.Node
	Provider     *provider.Provider
	DNSSelector  map[string]string
	DNSNamespace string
	DNSPort      string
}

// SetupWithManager sets up the node reconciler with the manager.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("pod-features").
		Watches(
			&corev1.Pod{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueIfReadyAndInNetwork),
		).
		Complete(r)
}

// Reconcile reconciles a node.
func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	if !r.Host.Started() {
		// Requeue until the host is started.
		log.Info("Host not started, requeuing")
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 2}, nil
	}
	log.Info("Reconciling available features for pod")
	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Get the peer from the storage provider by their IP address.
	db := r.Provider.Datastore()
	var peer meshtypes.MeshNode
	for _, ip := range pod.Status.PodIPs {
		if ip.IP == "" {
			continue
		}
		addr, err := netip.ParseAddr(ip.IP)
		if err != nil {
			log.Error(err, "Failed to parse pod IP")
			continue
		}
		switch {
		case addr.Is4():
			peer, err = db.GetPeerByIPv4Addr(ctx, netip.PrefixFrom(addr, 32))
		case addr.Is6():
			peer, err = db.GetPeerByIPv6Addr(ctx, netip.PrefixFrom(addr, 112))
		default:
			log.Info("Ignoring invalid IP address", "addr", addr.String())
			continue
		}
		if err != nil {
			log.Error(err, "Failed to lookup peer by IP address")
			continue
		}
	}
	if peer.MeshNode == nil {
		return ctrl.Result{}, fmt.Errorf("failed to find peer for pod")
	}
	// Ensure the pod has the DNS feature.
	if !peer.HasFeature(v1.Feature_MESH_DNS) {
		log.Info("Ensuring pod has MeshDNS feature")
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

func (r *PodReconciler) enqueueIfReadyAndInNetwork(ctx context.Context, o client.Object) []ctrl.Request {
	// Fast path, if the host isn't running there isn't anything we care about
	if !r.Host.Started() {
		return nil
	}
	pod := o.(*corev1.Pod)
	// Ignore deleted pods.
	if pod.GetDeletionTimestamp() != nil {
		return nil
	}
	// Ignore host network pods.
	if pod.Spec.HostNetwork {
		return nil
	}
	// Ignore pods that aren't running yet.
	if pod.Status.Phase != corev1.PodRunning {
		return nil
	}
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
	// Match the request if the pod has an in network IP.
	key := client.ObjectKeyFromObject(pod)
	req := ctrl.Request{NamespacedName: key}
	for _, ip := range pod.Status.PodIPs {
		if ip.IP == "" {
			continue
		}
		addr, err := netip.ParseAddr(ip.IP)
		if err != nil {
			log.FromContext(ctx).Error(err, "Failed to parse pod IP")
			continue
		}
		switch {
		case addr.Is6() && r.Host.Node().Network().NetworkV6().Contains(addr):
			return []ctrl.Request{req}
		case addr.Is4() && r.Host.Node().Network().NetworkV4().Contains(addr):
			return []ctrl.Request{req}
		}
	}
	return nil
}
