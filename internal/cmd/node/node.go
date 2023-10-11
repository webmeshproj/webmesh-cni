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
	"strings"
	"time"

	"github.com/spf13/pflag"
	storagev1 "github.com/webmeshproj/storage-provider-k8s/api/storage/v1"
	storageprovider "github.com/webmeshproj/storage-provider-k8s/provider"
	"github.com/webmeshproj/webmesh/pkg/cmd/cmdutil"
	meshconfig "github.com/webmeshproj/webmesh/pkg/config"
	meshcontext "github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins"
	meshservices "github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/version"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
	"github.com/webmeshproj/webmesh-cni/internal/config"
	"github.com/webmeshproj/webmesh-cni/internal/controller"
	"github.com/webmeshproj/webmesh-cni/internal/host"
)

var (
	scheme  = runtime.NewScheme()
	log     = ctrl.Log.WithName("webmesh-cni")
	cniopts = config.NewDefaultConfig()
	zapopts = zap.Options{Development: true}
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cniv1.AddToScheme(scheme))
	utilruntime.Must(storagev1.AddToScheme(scheme))
}

func pluginInArgs(pluginName string) bool {
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, fmt.Sprintf("--host.plugins.%s", pluginName)) {
			return true
		}
	}
	return false
}

// Main runs the webmesh-cni daemon.
func Main(build version.BuildInfo) {
	// Parse flags and setup logging.
	zapset := flag.NewFlagSet("zap", flag.ContinueOnError)
	fs := pflag.NewFlagSet("webmesh-cni", pflag.ContinueOnError)
	cniopts.BindFlags(fs)
	zapopts.BindFlags(zapset)
	fs.AddGoFlagSet(zapset)
	// Create a separate flag set with all plugins for usage.
	usage := pflag.NewFlagSet("usage", pflag.ContinueOnError)
	usage.AddFlagSet(fs)
	pluginConfigs := builtins.NewPluginConfigs()
	for pluginName, pluginConfig := range pluginConfigs {
		if !pluginInArgs(pluginName) {
			pluginConfig.BindFlags(fmt.Sprintf("host.plugins.%s.", pluginName), usage)
		}
	}
	fs.Usage = cmdutil.NewUsageFunc(cmdutil.UsageConfig{
		Name:        "webmesh-cni-node",
		Description: "The webmesh-cni node component.",
		Prefixes: []string{
			"manager",
			"host",
			"host.auth",
			"host.network",
			"host.services",
			"host.wireguard",
			"host.plugins",
			"storage",
		},
		Flagset: usage,
	})

	err := fs.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Println("ERROR: Failed to parse flags:", err)
		os.Exit(1)
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapopts)))

	// Validate the configuration.
	err = cniopts.Validate()
	if err != nil {
		log.Error(err, "Invalid CNI configuration")
		os.Exit(1)
	}

	log.Info("Starting webmesh-cni node", "version", build)

	// Create the manager.
	ctx := ctrl.SetupSignalHandler()
	ctx = ctrllog.IntoContext(ctx, log)

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
		log.Error(err, "Failed to create controller manager")
		os.Exit(1)
	}

	// Create the storage provider.
	storageOpts := storageprovider.Options{
		NodeID:                      cniopts.Host.NodeID,
		Namespace:                   cniopts.Host.Namespace,
		ListenPort:                  int(cniopts.Host.Services.API.ListenPort()),
		LeaderElectionLeaseDuration: cniopts.Storage.LeaderElectLeaseDuration,
		LeaderElectionRenewDeadline: cniopts.Storage.LeaderElectRenewDeadline,
		LeaderElectionRetryPeriod:   cniopts.Storage.LeaderElectRetryPeriod,
		ShutdownTimeout:             cniopts.Manager.ShutdownTimeout,
	}
	log.V(1).Info("Creating webmesh storage provider", "options", storageOpts)
	storageProvider, err := storageprovider.NewWithManager(mgr, storageOpts)
	if err != nil {
		log.Error(err, "Failed to create webmesh storage provider")
		os.Exit(1)
	}

	// Register the peer container controller.
	log.V(1).Info("Registering peer container controller")
	containerReconciler := &controller.PeerContainerReconciler{
		Client:   mgr.GetClient(),
		Host:     host.NewNode(storageProvider, cniopts.Host),
		Provider: storageProvider,
		Config:   cniopts,
	}
	if err = containerReconciler.SetupWithManager(mgr); err != nil {
		log.Error(err, "Failed to setup controller with manager", "controller", "PeerContainer")
		os.Exit(1)
	}
	// Register a node reconciler to make sure edges exist across the cluster.
	log.V(1).Info("Registering node reconciler")
	nodeReconciler := &controller.NodeReconciler{
		Client:   mgr.GetClient(),
		Provider: storageProvider,
		NodeName: cniopts.Host.NodeID,
	}
	if err = nodeReconciler.SetupWithManager(mgr); err != nil {
		log.Error(err, "Failed to setup controller with manager", "controller", "Node")
		os.Exit(1)
	}

	// Register the health and ready checks.
	log.V(1).Info("Registering health and ready checks")
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	donec := make(chan struct{})
	go func() {
		defer close(donec)
		log.Info("Starting peer container manager")
		if err := mgr.Start(ctx); err != nil {
			log.Error(err, "Problem running manager")
			os.Exit(1)
		}
		log.Info("Peer container manager finished")
		ctx, cancel := context.WithTimeout(
			ctrllog.IntoContext(context.Background(), log),
			cniopts.Manager.ShutdownTimeout,
		)
		defer cancel()
		log.Info("Shutting down managed container nodes")
		containerReconciler.Shutdown(ctx)
	}()

	// Start the storage provider in unmanaged mode.
	log.Info("Starting webmesh storage provider")
	err = storageProvider.StartUnmanaged(ctx)
	if err != nil {
		log.Error(err, "Failed to start webmesh storage provider")
		os.Exit(1)
	}
	defer storageProvider.Close()

	// Wait for the manager cache to sync and then get ready to handle requests

	log.Info("Waiting for manager cache to sync", "timeout", cniopts.Storage.CacheSyncTimeout)
	cacheCtx, cancel := context.WithTimeout(ctx, cniopts.Storage.CacheSyncTimeout)
	if synced := mgr.GetCache().WaitForCacheSync(cacheCtx); !synced {
		cancel()
		log.Error(err, "Timed out waiting for caches to sync")
		os.Exit(1)
	}
	cancel()
	log.V(1).Info("Caches synced, bootstrapping network state")

	log.Info("Starting host node for routing traffic")
	host := containerReconciler.Host
	err = host.Start(ctx, mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to start host node")
		os.Exit(1)
	}

	log.Info("Webmesh CNI node started")

	// Start any configured services.

	hostCtx := meshcontext.WithLogger(context.Background(), host.NodeLogger())
	srvOpts, err := cniopts.Host.Services.NewServiceOptions(hostCtx, host.Node())
	if err != nil {
		log.Error(err, "Failed to create webmesh service options")
		os.Exit(1)
	}
	srv, err := meshservices.NewServer(hostCtx, srvOpts)
	if err != nil {
		log.Error(err, "Failed to create webmesh services server")
		os.Exit(1)
	}
	features := cniopts.Host.Services.NewFeatureSet(storageProvider, srv.GRPCListenPort())
	err = cniopts.Host.Services.RegisterAPIs(hostCtx, meshconfig.APIRegistrationOptions{
		Node:        host.Node(),
		Server:      srv,
		Features:    features,
		BuildInfo:   build,
		Description: "webmesh-cni",
	})
	if err != nil {
		log.Error(err, "Failed to register webmesh services APIs")
		os.Exit(1)
	}
	go func() {
		log.Info("Starting webmesh services")
		err := srv.ListenAndServe()
		if err != nil {
			log.Error(err, "Failed to start webmesh services server")
			os.Exit(1)
		}
	}()

	// Wait for the manager to exit.
	<-ctx.Done()

	log.Info("Shutting down webmesh node and services")

	shutdownCtx, cancel := context.WithTimeout(
		ctrllog.IntoContext(context.Background(), log),
		cniopts.Manager.ShutdownTimeout,
	)
	defer cancel()
	err = containerReconciler.Host.Stop(shutdownCtx)
	if err != nil {
		log.Error(err, "Failed to stop host node")
	}
	srv.Shutdown(hostCtx)

	// Wait for the manager to exit.
	select {
	case <-donec:
		log.Info("Finished running manager")
	case <-time.After(cniopts.Manager.ShutdownTimeout):
		log.Info("Shutdown timeout reached, exiting")
	}
}
