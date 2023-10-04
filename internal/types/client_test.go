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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	storagev1 "github.com/webmeshproj/storage-provider-k8s/api/storage/v1"
	"github.com/webmeshproj/webmesh/pkg/storage/testutil"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	meshcniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
)

func TestClient(t *testing.T) {
	t.Parallel()
	cfg := setupClientTest(t)

	t.Run("NewClientForConfig", func(t *testing.T) {
		t.Parallel()

		t.Run("NilConf", func(t *testing.T) {
			// Invalid configs should fail.
			_, err := NewClientForConfig(ClientConfig{
				NetConf:    &NetConf{},
				RestConfig: nil,
			})
			if err == nil {
				t.Fatal("Expected error for invalid config")
			}
		})

		t.Run("ValidConf", func(t *testing.T) {
			// NewClient should never fail with a valid config.
			client, err := NewClientForConfig(ClientConfig{
				NetConf:    &NetConf{},
				RestConfig: cfg,
			})
			if err != nil {
				t.Fatal("Failed to create client", err)
			}
			// The client should be able to "Ping" the API server.
			err = client.Ping(time.Second)
			if err != nil {
				t.Fatal("Failed to ping API server", err)
			}
		})
	})

	t.Run("NewClientFromNetConf", func(t *testing.T) {
		t.Parallel()

		kubeconfig, err := KubeconfigFromRestConfig(cfg, "default")
		if err != nil {
			t.Fatal("Failed to get kubeconfig", err)
		}

		t.Run("NilConf", func(t *testing.T) {
			var netconf *NetConf
			_, err := netconf.NewClient(time.Second)
			if err == nil {
				t.Fatal("Expected error for nil config")
			}
		})

		t.Run("InvalidKubeconfig", func(t *testing.T) {
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
			err = client.Ping(time.Second)
			if err != nil {
				t.Errorf("Failed to ping API server: %v", err)
			}
		})
	})

	t.Run("PeerContainers", func(t *testing.T) {
		t.Parallel()
		netConf := &NetConf{
			Interface: Interface{
				MTU:         1234,
				DisableIPv4: false,
				DisableIPv6: true,
			},
			Kubernetes: Kubernetes{
				NodeName:  "node-a",
				Namespace: "default",
			},
		}
		cniclient, err := NewClientForConfig(ClientConfig{
			NetConf:    netConf,
			RestConfig: cfg,
		})
		if err != nil {
			t.Fatal("Failed to create client", err)
		}
		if err := cniclient.Ping(time.Second); err != nil {
			t.Fatal("Failed to ping API server", err)
		}

		t.Run("CreatePeerContainer", func(t *testing.T) {
			args := &skel.CmdArgs{
				ContainerID: "create-container-a",
				Netns:       "/proc/1/ns/net",
			}
			expectedContainer := netConf.ContainerFromArgs(args)
			err := cniclient.CreatePeerContainer(context.Background(), args)
			if err != nil {
				t.Fatal("Failed to create peer container", err)
			}
			// We should eventually be able to get the container back and it should
			// match the expected container.
			var container *meshcniv1.PeerContainer
			ok := testutil.Eventually[error](func() error {
				container, err = cniclient.GetPeerContainer(context.Background(), args)
				return err
			}).ShouldNotError(time.Second*10, time.Second)
			if !ok {
				t.Fatal("Failed to get peer container", err)
			}
			expectedData, err := json.Marshal(expectedContainer.Spec)
			if err != nil {
				t.Fatal("Failed to marshal expected container", err)
			}
			actualData, err := json.Marshal(container.Spec)
			if err != nil {
				t.Fatal("Failed to marshal actual container", err)
			}
			if !bytes.Equal(expectedData, actualData) {
				t.Fatalf("Expected container %s, got %s", string(expectedData), string(actualData))
			}
			// Make the container ID invalid and try to get it again.
			args.ContainerID = "invalid/container/id"
			err = cniclient.CreatePeerContainer(context.Background(), args)
			if err == nil {
				t.Fatal("Expected error for invalid container ID")
			}
		})

		t.Run("GetPeerContainer", func(t *testing.T) {
			args := &skel.CmdArgs{
				ContainerID: "get-container-a",
				Netns:       "/proc/1/ns/net",
			}
			err := cniclient.CreatePeerContainer(context.Background(), args)
			if err != nil {
				t.Fatal("Failed to create peer container", err)
			}
			// We should eventually be able to get the container back.
			ok := testutil.Eventually[error](func() error {
				_, err = cniclient.GetPeerContainer(context.Background(), args)
				return err
			}).ShouldNotError(time.Second*10, time.Second)
			if !ok {
				t.Fatal("Failed to get peer container", err)
			}
			// Try to get a non-existent container.
			args.ContainerID = "non-existent-container"
			_, err = cniclient.GetPeerContainer(context.Background(), args)
			if err == nil {
				t.Fatal("Expected error for non-existent container")
			}
			// The error should be a ErrPeerContainerNotFound.
			if !IsPeerContainerNotFound(err) {
				t.Fatal("Expected ErrPeerContainerNotFound")
			}
		})

		t.Run("DeletePeerContainer", func(t *testing.T) {
			args := &skel.CmdArgs{
				ContainerID: "delete-container-a",
				Netns:       "/proc/1/ns/net",
			}
			err := cniclient.CreatePeerContainer(context.Background(), args)
			if err != nil {
				t.Fatal("Failed to create peer container", err)
			}
			// We should eventually be able to get the container back.
			ok := testutil.Eventually[error](func() error {
				_, err = cniclient.GetPeerContainer(context.Background(), args)
				return err
			}).ShouldNotError(time.Second*10, time.Second)
			if !ok {
				t.Fatal("Failed to get peer container", err)
			}
			// Delete the container.
			err = cniclient.DeletePeerContainer(context.Background(), args)
			if err != nil {
				t.Fatal("Failed to delete peer container", err)
			}
			// The container should eventually be gone
			ok = testutil.Eventually[error](func() error {
				_, err = cniclient.GetPeerContainer(context.Background(), args)
				return err
			}).ShouldError(time.Second*10, time.Second)
			if !ok {
				t.Fatal("Expected error for non-existent container")
			}
			// The error should be a ErrPeerContainerNotFound.
			if !IsPeerContainerNotFound(err) {
				t.Fatal("Expected ErrPeerContainerNotFound, got:", err)
			}
			// Deleting non-existent containers should not fail.
			args.ContainerID = "non-existent-container"
			err = cniclient.DeletePeerContainer(context.Background(), args)
			if err != nil {
				t.Fatal("Failed to delete peer container", err)
			}
		})

		t.Run("EnsurePeerContainer", func(t *testing.T) {
			// This test behaves more or less like the CreatePeerContainer test, but
			// should only create the container once.
			args := &skel.CmdArgs{
				ContainerID: "create-not-exists-container-a",
				Netns:       "/proc/1/ns/net",
			}
			err := cniclient.EnsureContainer(context.Background(), args)
			if err != nil {
				t.Fatal("Failed to create peer container", err)
			}
			var container1 *meshcniv1.PeerContainer
			// We should eventually be able to get the container back.
			ok := testutil.Eventually[error](func() error {
				container1, err = cniclient.GetPeerContainer(context.Background(), args)
				return err
			}).ShouldNotError(time.Second*10, time.Second)
			if !ok {
				t.Fatal("Failed to get peer container", err)
			}
			// Furhter calls should not mutate the container.
			err = cniclient.EnsureContainer(context.Background(), args)
			if err != nil {
				t.Fatal("Failed to create peer container", err)
			}
			var container2 *meshcniv1.PeerContainer
			ok = testutil.Eventually[error](func() error {
				container2, err = cniclient.GetPeerContainer(context.Background(), args)
				return err
			}).ShouldNotError(time.Second*10, time.Second)
			if !ok {
				t.Fatal("Failed to get peer container", err)
			}
			if container1.GetResourceVersion() != container2.GetResourceVersion() {
				t.Fatal("Expected container to not be mutated")
			}
		})

		t.Run("WaitForStatus", func(t *testing.T) {
			t.Run("Timeout", func(t *testing.T) {
				args := &skel.CmdArgs{
					ContainerID: "timeout-container",
					Netns:       "/proc/1/ns/net",
				}
				err = cniclient.CreatePeerContainer(context.Background(), args)
				if err != nil {
					t.Fatal("Failed to create peer container", err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				// Wait for Running should time out as the status is not set.
				_, err = cniclient.WaitForRunning(ctx, args)
				if err == nil {
					t.Fatal("Expected error for timeout")
				} else if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("Expected context error, got:", err)
				}
				// Try again with a higher timeout in a best-effort to get full coverage on the select.
				ctx, cancel = context.WithTimeout(context.Background(), time.Second*2)
				defer cancel()
				// Wait for Running should time out as the status is not set.
				_, err = cniclient.WaitForRunning(ctx, args)
				if err == nil {
					t.Fatal("Expected error for timeout")
				} else if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("Expected context error, got:", err)
				}
			})

			t.Run("StatusNotReached", func(t *testing.T) {
				args := &skel.CmdArgs{
					ContainerID: "unreached-status-container",
					Netns:       "/proc/1/ns/net",
				}
				raw, err := NewRawClientForConfig(cfg)
				if err != nil {
					t.Fatal("Failed to create raw client", err)
				}
				err = cniclient.CreatePeerContainer(context.Background(), args)
				if err != nil {
					t.Fatal("Failed to create peer container", err)
				}
				// Wait for the container to exist and then patch its status
				var container *meshcniv1.PeerContainer
				ok := testutil.Eventually[error](func() error {
					container, err = cniclient.GetPeerContainer(context.Background(), args)
					return err
				}).ShouldNotError(time.Second*10, time.Second)
				if !ok {
					t.Fatal("Failed to get peer container", err)
				}
				container.Status.Phase = meshcniv1.InterfacePhaseFailed
				container.SetManagedFields(nil)
				err = raw.Status().Patch(context.Background(), container, client.Apply, client.ForceOwnership, client.FieldOwner(meshcniv1.FieldOwner))
				if err != nil {
					t.Fatal("Failed to patch peer container", err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				// Wait for Running should time out as the status is not set.
				_, err = cniclient.WaitForRunning(ctx, args)
				if err == nil {
					t.Fatal("Expected error for timeout")
				} else if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("Expected context error, got:", err)
				}
				// Try again with a higher timeout in a best-effort to get full coverage on the select.
				ctx, cancel = context.WithTimeout(context.Background(), time.Second*2)
				defer cancel()
				// Wait for Running should time out as the status is not set.
				_, err = cniclient.WaitForRunning(ctx, args)
				if err == nil {
					t.Fatal("Expected error for timeout")
				} else if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("Expected context error, got:", err)
				}
			})

			t.Run("StatusReached", func(t *testing.T) {
				args := &skel.CmdArgs{
					ContainerID: "reached-status-container",
					Netns:       "/proc/1/ns/net",
				}
				raw, err := NewRawClientForConfig(cfg)
				if err != nil {
					t.Fatal("Failed to create raw client", err)
				}
				err = cniclient.CreatePeerContainer(context.Background(), args)
				if err != nil {
					t.Fatal("Failed to create peer container", err)
				}
				// Wait for the container to exist and then patch its status
				var container *meshcniv1.PeerContainer
				ok := testutil.Eventually[error](func() error {
					container, err = cniclient.GetPeerContainer(context.Background(), args)
					return err
				}).ShouldNotError(time.Second*10, time.Second)
				if !ok {
					t.Fatal("Failed to get peer container", err)
				}
				container.Status.Phase = meshcniv1.InterfacePhaseRunning
				container.Status.IPv4Address = "test-ipv4"
				container.Status.IPv6Address = "test-ipv6"
				container.SetManagedFields(nil)
				err = raw.Status().Patch(context.Background(), container, client.Apply, client.ForceOwnership, client.FieldOwner(meshcniv1.FieldOwner))
				if err != nil {
					t.Fatal("Failed to patch peer container", err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				// Wait for Running should time out as the status is not set.
				status, err := cniclient.WaitForRunning(ctx, args)
				if err != nil {
					t.Fatal("Failed to wait for running", err)
				}
				if status.IPv4Address != "test-ipv4" {
					t.Fatal("Expected IPv4 address to be set")
				}
				if status.IPv6Address != "test-ipv6" {
					t.Fatal("Expected IPv6 address to be set")
				}
				// Do a raw test of the equivalent to better test real eventuality.
				t.Run("Raw", func(t *testing.T) {
					args := &skel.CmdArgs{
						ContainerID: "reached-status-container-raw",
						Netns:       "/proc/1/ns/net",
					}
					raw, err := NewRawClientForConfig(cfg)
					if err != nil {
						t.Fatal("Failed to create raw client", err)
					}
					container := cniclient.conf.ContainerFromArgs(args)
					err = raw.Patch(context.Background(), &container, client.Apply, client.ForceOwnership, client.FieldOwner(meshcniv1.FieldOwner))
					if err != nil {
						t.Fatal("Failed to patch peer container", err)
					}
					container.Status.Phase = meshcniv1.InterfacePhaseRunning
					container.Status.IPv4Address = "test-ipv4"
					container.Status.IPv6Address = "test-ipv6"
					container.SetManagedFields(nil)
					err = raw.Status().Patch(context.Background(), &container, client.Apply, client.ForceOwnership, client.FieldOwner(meshcniv1.FieldOwner))
					if err != nil {
						t.Fatal("Failed to patch peer container status", err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
					defer cancel()
					// Wait for Running should time out as the status is not set.
					status, err := cniclient.WaitForRunning(ctx, args)
					if err != nil {
						t.Fatal("Failed to wait for running", err)
					}
					if status.IPv4Address != "test-ipv4" {
						t.Fatal("Expected IPv4 address to be set")
					}
					if status.IPv6Address != "test-ipv6" {
						t.Fatal("Expected IPv6 address to be set")
					}
				})
			})
		})
	})
}

func setupClientTest(t *testing.T) *rest.Config {
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
