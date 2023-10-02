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

// Package node contains the entrypoint for the webmesh-cni node component.
package node

import (
	"flag"
	"os"
	"time"

	storagev1 "github.com/webmeshproj/storage-provider-k8s/api/storage/v1"
	storageprovider "github.com/webmeshproj/storage-provider-k8s/provider"
	meshstorage "github.com/webmeshproj/webmesh/pkg/storage"
	mesherrors "github.com/webmeshproj/webmesh/pkg/storage/errors"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
	"github.com/webmeshproj/webmesh-cni/internal/controller"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cniv1.AddToScheme(scheme))
	utilruntime.Must(storagev1.AddToScheme(scheme))
}

// Main runs the webmesh-cni daemon.
func Main(version string) {
	// Parse flags and setup logging.
	var (
		namespace                string
		metricsAddr              string
		probeAddr                string
		clusterDomain            string
		podCIDR                  string
		nodeID                   string
		leaderElectLeaseDuration time.Duration
		leaderElectRenewDeadline time.Duration
		leaderElectRetryPeriod   time.Duration
		shutdownTimeout          time.Duration
		zapopts                  = zap.Options{Development: true}
	)
	flag.StringVar(&namespace, "namespace", os.Getenv("K8S_POD_NAMESPACE"), "The namespace to use for the webmesh resources.")
	flag.StringVar(&nodeID, "node-id", os.Getenv("KUBERNETES_NODE_NAME"), "The node ID to use for the webmesh cluster.")
	flag.StringVar(&podCIDR, "pod-cidr", "172.16.0.0/12", "The pod CIDR to use for the webmesh cluster.")
	flag.StringVar(&clusterDomain, "cluster-domain", "cluster.local", "The cluster domain to use for the webmesh cluster.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.DurationVar(&leaderElectLeaseDuration, "leader-elect-lease-duration", time.Second*15, "The duration that non-leader candidates will wait to force acquire leadership.")
	flag.DurationVar(&leaderElectRenewDeadline, "leader-elect-renew-deadline", time.Second*10, "The duration that the acting leader will retry refreshing leadership before giving up.")
	flag.DurationVar(&leaderElectRetryPeriod, "leader-elect-retry-period", time.Second*2, "The duration the LeaderElector clients should wait between tries of actions.")
	flag.DurationVar(&shutdownTimeout, "shutdown-timeout", time.Second*10, "The duration to wait for the manager to shutdown.")
	zapopts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapopts)))

	setupLog.Info("Starting webmesh-cni node", "version", version)

	// Create the manager.
	ctx := ctrl.SetupSignalHandler()
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		GracefulShutdownTimeout: &shutdownTimeout,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Create the storage provider.
	storageProvider, err := storageprovider.NewWithManager(mgr, storageprovider.Options{
		NodeID:                      nodeID,
		Namespace:                   "webmesh",
		LeaderElectionLeaseDuration: leaderElectLeaseDuration,
		LeaderElectionRenewDeadline: leaderElectRenewDeadline,
		LeaderElectionRetryPeriod:   leaderElectRetryPeriod,
	})
	if err != nil {
		setupLog.Error(err, "unable to create webmesh storage provider")
		os.Exit(1)
	}
	err = storageProvider.StartUnmanaged(ctx)
	if err != nil {
		setupLog.Error(err, "unable to start webmesh storage provider")
		os.Exit(1)
	}
	defer storageProvider.Close()

	// Make sure the network state is boostrapped.
	networkState, err := meshstorage.Bootstrap(ctx, storageProvider.MeshDB(), meshstorage.BootstrapOptions{
		MeshDomain:           clusterDomain,
		IPv4Network:          podCIDR,
		Admin:                meshstorage.DefaultMeshAdmin,
		DefaultNetworkPolicy: meshstorage.DefaultNetworkPolicy,
		DisableRBAC:          true, // Make this configurable? But really, just use the RBAC from Kubernetes.
	})
	if err != nil && !mesherrors.Is(err, mesherrors.ErrAlreadyBootstrapped) {
		setupLog.Error(err, "Unable to bootstrap network state")
		os.Exit(1)
	}

	// Register the peer container controller.
	if err = (&controller.PeerContainerReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		Provider:   storageProvider,
		NetworkV4:  networkState.NetworkV4,
		NetworkV6:  networkState.NetworkV6,
		MeshDomain: networkState.MeshDomain,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Unable to create controller", "controller", "PeerContainer")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Unable to set up ready check")
		os.Exit(1)
	}

	// TODO: Register a cleanup function to remove the node and all containers
	// when the manager is shutting down.

	donec := make(chan struct{})
	go func() {
		defer close(donec)
		setupLog.Info("Starting peer container manager")
		if err := mgr.Start(ctx); err != nil {
			setupLog.Error(err, "problem running manager")
			os.Exit(1)
		}
	}()

	// TODO: We can optionally expose the Webmesh API to allow people outside the cluster
	// to join the network.

	<-ctx.Done()
	select {
	case <-donec:
		setupLog.Info("Finished running manager")
	case <-time.After(shutdownTimeout):
		setupLog.Info("Shutdown timeout reached, exiting")
	}
}
