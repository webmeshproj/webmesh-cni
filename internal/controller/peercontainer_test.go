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
	"github.com/webmeshproj/webmesh/pkg/meshnet/system"
	meshnode "github.com/webmeshproj/webmesh/pkg/meshnode"
	meshstorage "github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
)

func TestReconciler(t *testing.T) {
	NewNode = meshnode.NewTestNodeWithLogger

	t.Run("SingleNode", func(t *testing.T) {
		rs := newTestReconcilers(t, 1)
		r := rs[0]
		cli := r.Client

		t.Run("ValidContainer", func(t *testing.T) {
			container := newTestContainerFor(r)
			err := cli.Create(context.Background(), &container)
			if err != nil {
				t.Fatal("Failed to create container", err)
			}
			ValidateReconciledContainer(t, r, cli, client.ObjectKeyFromObject(&container))
		})
	})
}

func ValidateReconciledContainer(t *testing.T, r *PeerContainerReconciler, cli client.Client, key client.ObjectKey) {
	// The finalizer should eventually be set.
	var err error
	ok := testutil.Eventually[bool](func() bool {
		var container cniv1.PeerContainer
		err = cli.Get(context.Background(), key, &container)
		if err != nil {
			t.Log("Failed to get container", err)
			return false
		}
		return controllerutil.ContainsFinalizer(&container, cniv1.PeerContainerFinalizer)
	}).ShouldEqual(time.Second*10, time.Second, true)
	if !ok {
		t.Error("Failed to see finalizer on peer container")
	}
	// The node should eventually be in the reconcilers node list.
	ok = testutil.Eventually[bool](func() bool {
		_, ok := r.nodes[key]
		return ok
	}).ShouldEqual(time.Second*10, time.Second, true)
	if !ok {
		t.Error("Failed to see node in reconciler")
	}
	// The node should eventually be started.
	ok = testutil.Eventually[bool](func() bool {
		node, ok := r.nodes[key]
		if !ok {
			// Would be very strange at this point
			t.Log("Failed to find node in reconciler")
			return false
		}
		return node.Started()
	}).ShouldEqual(time.Second*10, time.Second, true)
	if !ok {
		t.Error("Failed to see node in started state")
	}
	// The peer container status should eventually be set to Running
	var container cniv1.PeerContainer
	ok = testutil.Eventually[bool](func() bool {
		err = cli.Get(context.Background(), key, &container)
		if err != nil {
			t.Log("Failed to get container", err)
			return false
		}
		t.Log("Container status", container.Status)
		return container.Status.InterfaceStatus == cniv1.InterfaceStatusRunning
	}).ShouldEqual(time.Second*10, time.Second, true)
	if !ok {
		t.Error("Failed to see container in running state")
	}
	// All status fields should be populated
	if container.Status.InterfaceName != container.Spec.IfName {
		t.Error("Interface name not set correctly, got:", container.Status.InterfaceName, "expected:", container.Spec.IfName)
	}
	if !container.Status.HasNetworkInfo() {
		t.Error("Network info not set")
	}
}

func newTestContainerFor(r *PeerContainerReconciler) cniv1.PeerContainer {
	containerID := uuid.NewString()
	return cniv1.PeerContainer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "PeerContainer",
			APIVersion: cniv1.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      containerID,
			Namespace: "default",
		},
		Spec: cniv1.PeerContainerSpec{
			NodeID:   containerID,
			Netns:    "/proc/1/ns/net",
			IfName:   containerID[:min(9, len(containerID))] + "0",
			NodeName: r.NodeName,
			MTU:      1500,
		},
	}
}

func newTestReconcilers(t *testing.T, count int) []*PeerContainerReconciler {
	t.Helper()
	mgr, provider := newTestManager(t)
	var out []*PeerContainerReconciler
	for i := 0; i < count; i++ {
		r := &PeerContainerReconciler{
			Client: mgr.GetClient(),
			PeerContainerReconcilerConfig: PeerContainerReconcilerConfig{
				Provider:         provider,
				NodeName:         uuid.NewString(),
				Namespace:        "default",
				ReconcileTimeout: time.Second * 10,
				HostNodeLogLevel: "debug",
				MTU:              system.DefaultMTU,
				ConnectTimeout:   time.Second * 10,
			},
		}
		err := r.SetupWithManager(mgr)
		if err != nil {
			t.Fatal("Failed to setup reconciler", err)
		}
		out = append(out, r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		err := mgr.Start(ctx)
		if err != nil {
			t.Log("Failed to start manager", err)
		}
	}()
	err := provider.StartUnmanaged(context.Background())
	if err != nil {
		t.Fatal("Failed to start storage provider", err)
	}
	t.Cleanup(func() {
		_ = provider.Close()
	})
	err = provider.Bootstrap(ctx)
	if err != nil {
		t.Fatal("Failed to bootstrap storage provider", err)
	}
	networkState, err := meshstorage.Bootstrap(ctx, provider.MeshDB(), meshstorage.BootstrapOptions{
		MeshDomain:           "cluster.local",
		IPv4Network:          "10.42.0.0/16",
		Admin:                meshstorage.DefaultMeshAdmin,
		DefaultNetworkPolicy: meshstorage.DefaultNetworkPolicy,
		DisableRBAC:          true,
	})
	if err != nil {
		t.Fatal("Failed to bootstrap network state", err)
	}
	for _, r := range out {
		err := r.StartHostNode(ctx, networkState)
		if err != nil {
			t.Fatal("Failed to start host node", err)
		}
	}
	return out
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
	provider, err := storageprovider.NewWithManager(mgr, storageOpts)
	if err != nil {
		t.Fatal("Failed to create storage provider", err)
	}
	return mgr, provider
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
