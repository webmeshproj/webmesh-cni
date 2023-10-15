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
	"sync"
	"time"

	"github.com/webmeshproj/storage-provider-k8s/provider"
	meshnode "github.com/webmeshproj/webmesh/pkg/meshnode"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
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
	Namespace string
	Provider  *provider.Provider
	Host      host.Node
	bridges   map[client.ObjectKey]meshnode.Node
	mu        sync.Mutex
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
		return ctrl.Result{}, r.reconcileRemove(ctx, &nw)
	}
	return ctrl.Result{}, r.reconcileNetwork(ctx, &nw)
}

func (r *RemoteNetworkReconciler) reconcileNetwork(ctx context.Context, nw *cniv1.RemoteNetwork) error {
	log := log.FromContext(ctx)
	log.Info("Reconciling remote network")
	if r.bridges == nil {
		r.bridges = map[client.ObjectKey]meshnode.Node{}
	}
	// Ensure the finalizer on the network.
	if !controllerutil.ContainsFinalizer(nw, cniv1.RemoteNetworkFinalizer) {
		updated := controllerutil.AddFinalizer(nw, cniv1.RemoteNetworkFinalizer)
		if updated {
			log.V(1).Info("Adding finalizer to remote network")
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
				return r.Namespace
			}(),
		}, &secret); err != nil {
			return fmt.Errorf("failed to fetch credentials: %w", err)
		}
		creds = secret.Data
	}
	switch nw.Spec.AuthMethod {
	case cniv1.RemoteAuthMethodNone, cniv1.RemoteAuthMethodNative:
		return r.reconcileWithRPCs(ctx, nw, creds)
	case cniv1.RemoteAuthMethodKubernetes:
		kubeconfig, ok := creds[cniv1.KubeconfigKey]
		if !ok {
			return fmt.Errorf("kubeconfig not provided in credentials")
		}
		return r.reconcileWithKubeconfig(ctx, nw, kubeconfig)
	default:
		return fmt.Errorf("unknown auth method: %s", nw.Spec.AuthMethod)
	}
}

func (r *RemoteNetworkReconciler) reconcileWithRPCs(ctx context.Context, nw *cniv1.RemoteNetwork, creds map[string][]byte) error {
	return nil
}

func (r *RemoteNetworkReconciler) reconcileWithKubeconfig(ctx context.Context, nw *cniv1.RemoteNetwork, kubeconfig []byte) error {
	return nil
}

func (r *RemoteNetworkReconciler) reconcileRemove(ctx context.Context, nw *cniv1.RemoteNetwork) error {
	log := log.FromContext(ctx)
	log.Info("Removing remote network")
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
