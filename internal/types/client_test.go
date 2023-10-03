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

package types

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	storagev1 "github.com/webmeshproj/storage-provider-k8s/api/storage/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestClient(t *testing.T) {
	t.Parallel()
	cfg := setupClientTest(t)

	t.Run("NewClientForConfig", func(t *testing.T) {
		t.Parallel()
		// Invalid configs should fail.
		_, err := NewClientForConfig(ClientConfig{
			NetConf:    &NetConf{},
			RestConfig: nil,
		})
		if err == nil {
			t.Fatal("Expected error for invalid config")
		}
		// NewClient should never fail with a valid config.
		client, err := NewClientForConfig(ClientConfig{
			NetConf:    &NetConf{},
			RestConfig: cfg,
		})
		if err != nil {
			t.Fatal("Failed to create client", err)
		}
		// The client should be able to "Ping" the API server.
		err = client.Ping(time.Second * 3)
		if err != nil {
			t.Fatal("Failed to ping API server", err)
		}
	})

	t.Run("NewClientFromNetConf", func(t *testing.T) {
		t.Parallel()
		kubeconfig, err := KubeconfigFromRestConfig(cfg, "default")
		if err != nil {
			t.Fatal("Failed to get kubeconfig", err)
		}

		t.Run("NilConf", func(t *testing.T) {
			t.Parallel()
			var netconf *NetConf
			_, err := netconf.NewClient(time.Second)
			if err == nil {
				t.Fatal("Expected error for nil config")
			}
		})

		t.Run("InvalidKubeconfig", func(t *testing.T) {
			t.Parallel()
			netconf := &NetConf{
				Kubernetes: Kubernetes{
					Kubeconfig: "invalid",
				},
			}
			_, err := netconf.NewClient(time.Second)
			if err == nil {
				t.Fatal("Expected error for invalid kubeconfig")
			}
		})

		t.Run("Valid Kubeconfig", func(t *testing.T) {
			t.Parallel()
			dirTmp, err := os.MkdirTemp("", "")
			if err != nil {
				t.Fatal("Failed to create temp dir", err)
			}
			defer os.RemoveAll(dirTmp)
			kpath := filepath.Join(dirTmp, "kubeconfig")
			err = clientcmd.WriteToFile(kubeconfig, kpath)
			if err != nil {
				t.Fatal("Failed to write kubeconfig", err)
			}
			netconf := &NetConf{
				Kubernetes: Kubernetes{
					Kubeconfig: kpath,
				},
			}
			client, err := netconf.NewClient(time.Second)
			if err != nil {
				t.Fatal("Failed to create client", err)
			}
			err = client.Ping(time.Second * 3)
			if err != nil {
				t.Errorf("Failed to ping API server: %v", err)
			}
		})
	})
}

func setupClientTest(t *testing.T) *rest.Config {
	t.Helper()
	t.Log("Starting test environment")
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zap.Options{Development: true})))
	testenv := envtest.Environment{
		CRDInstallOptions:        envtest.CRDInstallOptions{},
		ErrorIfCRDPathMissing:    true,
		CRDs:                     storagev1.GetCustomResourceDefintions(),
		CRDDirectoryPaths:        []string{"../../deploy/crds"},
		ControlPlaneStartTimeout: time.Second * 30,
		ControlPlaneStopTimeout:  time.Second * 3,
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
