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
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"
	storagev1 "github.com/webmeshproj/storage-provider-k8s/api/storage/v1"
	storageprovider "github.com/webmeshproj/storage-provider-k8s/provider"
	meshstorage "github.com/webmeshproj/webmesh/pkg/storage"
	mesherrors "github.com/webmeshproj/webmesh/pkg/storage/errors"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
	"github.com/webmeshproj/webmesh-cni/internal/config"
	"github.com/webmeshproj/webmesh-cni/internal/controller"
	"github.com/webmeshproj/webmesh-cni/internal/version"
)

var (
	scheme  = runtime.NewScheme()
	mainLog = ctrl.Log.WithName("webmesh-cni")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cniv1.AddToScheme(scheme))
	utilruntime.Must(storagev1.AddToScheme(scheme))
}

// Main runs the webmesh-cni daemon.
func Main(build version.BuildInfo) {
	// Parse flags and setup logging.
	var (
		cniopts = config.Config{}
		zapopts = zap.Options{Development: true}
	)
	zapset := flag.NewFlagSet("zap", flag.ContinueOnError)
	fs := pflag.NewFlagSet("webmesh-cni", pflag.ContinueOnError)
	cniopts.BindFlags(fs)
	zapopts.BindFlags(zapset)
	fs.AddGoFlagSet(zapset)
	if len(os.Args) < 2 {
		fs.PrintDefaults()
		os.Exit(0)
	}
	err := fs.Parse(os.Args[1:])
	if errors.Is(err, pflag.ErrHelp) {
		os.Exit(0)
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapopts)))

	// Validate the configuration.
	err = cniopts.Validate()
	if err != nil {
		mainLog.Error(err, "Invalid CNI configuration")
		os.Exit(1)
	}

	mainLog.Info("Starting webmesh-cni node", "version", build)

	// Create the manager.
	ctx := ctrl.SetupSignalHandler()
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: cniopts.Manager.MetricsAddress,
		},
		HealthProbeBindAddress:  cniopts.Manager.ProbeAddress,
		GracefulShutdownTimeout: &cniopts.Manager.ShutdownTimeout,
		Controller: ctrlconfig.Controller{
			GroupKindConcurrency: map[string]int{
				"PeerContainer.cni.webmesh.io": 1,
			},
			NeedLeaderElection: &[]bool{false}[0],
		},
		Client: client.Options{
			Cache: &client.CacheOptions{
				DisableFor: storagev1.CustomObjects,
			},
		},
	})
	if err != nil {
		mainLog.Error(err, "Failed to create controller manager")
		os.Exit(1)
	}

	// Create the storage provider.
	storageOpts := storageprovider.Options{
		NodeID:                      cniopts.Manager.NodeName,
		Namespace:                   cniopts.Manager.Namespace,
		ListenPort:                  cniopts.HostNode.GRPCListenPort,
		LeaderElectionLeaseDuration: cniopts.Storage.LeaderElectLeaseDuration,
		LeaderElectionRenewDeadline: cniopts.Storage.LeaderElectRenewDeadline,
		LeaderElectionRetryPeriod:   cniopts.Storage.LeaderElectRetryPeriod,
		ShutdownTimeout:             cniopts.Manager.ShutdownTimeout,
	}
	mainLog.V(1).Info("Creating webmesh storage provider", "options", storageOpts)
	storageProvider, err := storageprovider.NewWithManager(mgr, storageOpts)
	if err != nil {
		mainLog.Error(err, "Failed to create webmesh storage provider")
		os.Exit(1)
	}

	// Register the peer container controller.
	mainLog.V(1).Info("Registering peer container controller")
	containerReconciler := &controller.PeerContainerReconciler{
		Client:   mgr.GetClient(),
		Provider: storageProvider,
		Config:   cniopts,
	}
	if err = containerReconciler.SetupWithManager(mgr); err != nil {
		mainLog.Error(err, "Failed to setup controller with manager", "controller", "PeerContainer")
		os.Exit(1)
	}
	// Register a node reconciler to make sure edges exist across the cluster.
	mainLog.V(1).Info("Registering node reconciler")
	nodeReconciler := &controller.NodeReconciler{
		Client:   mgr.GetClient(),
		Provider: storageProvider,
		NodeName: cniopts.Manager.NodeName,
	}
	if err = nodeReconciler.SetupWithManager(mgr); err != nil {
		mainLog.Error(err, "Failed to setup controller with manager", "controller", "Node")
		os.Exit(1)
	}

	// TODO: Register another Node reconciler that maintains the consensus group.

	// Register the health and ready checks.
	mainLog.V(1).Info("Registering health and ready checks")
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		mainLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		mainLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	// TODO: Register a cleanup function to remove all containers
	// when the node itself is shutting down. Otherwise hopefully
	// a restart will bring things back to the correct state.

	donec := make(chan struct{})
	go func() {
		defer close(donec)
		mainLog.Info("Starting peer container manager")
		if err := mgr.Start(ctx); err != nil {
			mainLog.Error(err, "Problem running manager")
			os.Exit(1)
		}
	}()

	// Start the storage provider in unmanaged mode.
	mainLog.Info("Starting webmesh storage provider")
	err = storageProvider.StartUnmanaged(ctx)
	if err != nil {
		mainLog.Error(err, "Failed to start webmesh storage provider")
		os.Exit(1)
	}
	defer storageProvider.Close()

	// Wait for the manager cache to sync and then get ready to handle requests

	mainLog.Info("Waiting for manager cache to sync", "timeout", cniopts.Storage.CacheSyncTimeout)
	cacheCtx, cancel := context.WithTimeout(ctx, cniopts.Storage.CacheSyncTimeout)
	if synced := mgr.GetCache().WaitForCacheSync(cacheCtx); !synced {
		cancel()
		mainLog.Error(err, "Timed out waiting for caches to sync")
		os.Exit(1)
	}
	cancel()
	mainLog.V(1).Info("Caches synced, bootstrapping network state")

	mainLog.Info("Starting host node for routing traffic")
	results, err := tryBootstrap(log.IntoContext(ctx, mainLog), storageProvider, cniopts.Network)
	if err != nil {
		mainLog.Error(err, "Failed to bootstrap network state")
		os.Exit(1)
	}
	err = containerReconciler.StartHostNode(ctx, results)
	if err != nil {
		mainLog.Error(err, "Failed to start host webmesh node")
		os.Exit(1)
	}

	// TODO: We can optionally expose the Webmesh API to allow people outside the cluster
	// to join the network.

	mainLog.Info("Webmesh CNI node started")

	// Wait for the manager to exit.
	<-ctx.Done()

	// Go ahead and stop the host node.
	containerReconciler.StopHostNode(log.IntoContext(context.Background(), mainLog))

	// Wait for the manager to exit.
	select {
	case <-donec:
		mainLog.Info("Finished running manager")
	case <-time.After(cniopts.Manager.ShutdownTimeout):
		mainLog.Info("Shutdown timeout reached, exiting")
	}
}

func tryBootstrap(ctx context.Context, provider *storageprovider.Provider, config config.NetworkConfig) (meshstorage.BootstrapResults, error) {
	log := log.FromContext(ctx).WithName("bootstrap")
	log.Info("Checking that webmesh network is bootstrapped")
	// Try to bootstrap the storage provider.
	log.V(1).Info("Attempting to bootstrap storage provider")
	var networkState meshstorage.BootstrapResults
	err := provider.Bootstrap(ctx)
	if err != nil {
		if !mesherrors.Is(err, mesherrors.ErrAlreadyBootstrapped) {
			log.Error(err, "Unable to bootstrap storage provider")
			return networkState, fmt.Errorf("failed to bootstrap storage provider: %w", err)
		}
		log.V(1).Info("Storage provider already bootstrapped, making sure network state is boostrapped")
	}
	// Make sure the network state is boostrapped.
	bootstrapOpts := meshstorage.BootstrapOptions{
		MeshDomain:           config.ClusterDomain,
		IPv4Network:          config.PodCIDR,
		Admin:                meshstorage.DefaultMeshAdmin,
		DefaultNetworkPolicy: meshstorage.DefaultNetworkPolicy,
		DisableRBAC:          true, // Make this configurable? But really, just use the RBAC from Kubernetes.
	}
	log.V(1).Info("Attempting to bootstrap network state", "options", bootstrapOpts)
	networkState, err = meshstorage.Bootstrap(ctx, provider.MeshDB(), bootstrapOpts)
	if err != nil && !mesherrors.Is(err, mesherrors.ErrAlreadyBootstrapped) {
		log.Error(err, "Unable to bootstrap network state")
		return networkState, fmt.Errorf("failed to bootstrap network state: %w", err)
	} else if mesherrors.Is(err, mesherrors.ErrAlreadyBootstrapped) {
		log.Info("Network already bootstrapped")
	} else {
		log.Info("Network state bootstrapped for the first time")
	}
	return networkState, nil
}
