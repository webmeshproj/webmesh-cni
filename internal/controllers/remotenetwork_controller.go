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
	"sync"
	"time"

	"github.com/webmeshproj/storage-provider-k8s/provider"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
	"github.com/webmeshproj/webmesh-cni/internal/config"
	"github.com/webmeshproj/webmesh-cni/internal/host"
)

//+kubebuilder:rbac:groups=cni.webmesh.io,resources=remotenetworks,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=remotenetworks/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=remotenetworks/finalizers,verbs=update

// RemoteNetworkReconciler ensures bridge connections to other clusters.
type RemoteNetworkReconciler struct {
	client.Client
	config.Config
	Provider *provider.Provider
	Host     host.Node
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
	if !r.Host.Started() {
		// Request a requeue until the host is started.
		log.Info("Host not started yet, requeuing")
		return ctrl.Result{Requeue: true, RequeueAfter: time.Second * 2}, nil
	}
	return ctrl.Result{}, nil
}
