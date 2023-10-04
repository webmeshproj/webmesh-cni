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
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	storagev1 "github.com/webmeshproj/storage-provider-k8s/api/storage/v1"
	storageprovider "github.com/webmeshproj/storage-provider-k8s/provider"
	meshnode "github.com/webmeshproj/webmesh/pkg/meshnode"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
)

func TestReconciler(t *testing.T) {
	NewNode = meshnode.NewTestNodeWithLogger

	t.Run("ReconcileValidNodes", func(t *testing.T) {
		_, _ = newTestManager(t)
	})
}

func newTestManager(t *testing.T) (ctrl.Manager, *storageprovider.Provider) {
	t.Helper()
	cfg := newTestEnv(t)
	t.Log("Setting up test manager")
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cniv1.AddToScheme(scheme))
	utilruntime.Must(storagev1.AddToScheme(scheme))
	shutdownTimeout := time.Second * 10
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
		HealthProbeBindAddress:  "0",
		GracefulShutdownTimeout: &shutdownTimeout,
		Controller: config.Controller{
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
		t.Fatal("Failed to create manager", err)
	}
	// Create the storage provider.
	t.Log("Creating webmesh storage provider")
	storageOpts := storageprovider.Options{
		NodeID:                      uuid.NewString(),
		Namespace:                   "default",
		ListenPort:                  0,
		LeaderElectionLeaseDuration: time.Second * 15,
		LeaderElectionRenewDeadline: time.Second * 10,
		LeaderElectionRetryPeriod:   time.Second * 2,
		ShutdownTimeout:             shutdownTimeout,
	}
	storageProvider, err := storageprovider.NewWithManager(mgr, storageOpts)
	if err != nil {
		t.Fatal("Failed to create storage provider", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Log("Starting manager and storage provider")
	go func() {
		if err := mgr.Start(ctx); err != nil {
			t.Log("Failed to start manager:", err)
		}
	}()
	err = storageProvider.StartUnmanaged(ctx)
	if err != nil {
		t.Fatal("Failed to start storage provider", err)
	}
	t.Cleanup(func() {
		_ = storageProvider.Close()
	})
	return mgr, storageProvider
}

func newTestEnv(t *testing.T) *rest.Config {
	t.Helper()
	t.Log("Starting test environment")
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zap.Options{Development: true})))
	testenv := envtest.Environment{
		CRDs:                     storagev1.GetCustomResourceDefintions(),
		CRDDirectoryPaths:        []string{os.Getenv("CRD_PATHS")},
		ErrorIfCRDPathMissing:    true,
		ControlPlaneStartTimeout: time.Second * 20,
		ControlPlaneStopTimeout:  time.Second * 10,
	}
	cfg, err := testenv.Start()
	if err != nil {
		t.Fatal("Failed to start test environment", err)
	}
	t.Cleanup(func() {
		t.Log("Stopping test environment")
		err := testenv.Stop()
		if err != nil {
			t.Log("Failed to stop test environment", err)
		}
	})
	return cfg
}
