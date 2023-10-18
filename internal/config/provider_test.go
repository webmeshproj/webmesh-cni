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

package config

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	kjson "github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestConfigMapLoader(t *testing.T) {
	ctx := context.Background()
	cfg, cli := setupProviderTest(t)
	provider := NewConfigMapProvider(cfg, client.ObjectKey{
		Name:      "config",
		Namespace: "default",
	})
	// Create a configmap that tests the various types we'll encounter
	err := cli.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "config",
			Namespace: "default",
		},
		Data: map[string]string{
			"manager.metrics-address":           "localhost:8080",
			"manager.reconcile-timeout":         "1s",
			"manager.max-concurrent-reconciles": "10",
			"manager.cluster-dns-selector":      `{"k8s-app": "kube-dns"}`,
			"manager.enable-metadata-server":    "false",
			"storage.cache-sync-timeout":        "2s",
			"host.wireguard.listen-port":        "51820",
		},
	})
	if err != nil {
		t.Fatal("Failed to create configmap", err)
	}
	k := koanf.New(".")
	err = k.Load(provider, kjson.Parser())
	if err != nil {
		t.Fatal("Failed to load configmap", err)
	}
	var c Config
	err = k.Unmarshal("", &c)
	if err != nil {
		t.Fatal("Failed to unmarshal configmap", err)
	}
	if c.Manager.MetricsAddress != "localhost:8080" {
		t.Fatalf("Expected manager.metrics-address to be localhost:8080, got %s", c.Manager.MetricsAddress)
	}
	if c.Manager.ReconcileTimeout != time.Second {
		t.Fatalf("Expected manager.reconcile-timeout to be 1s, got %s", c.Manager.ReconcileTimeout)
	}
	if c.Manager.MaxConcurrentReconciles != 10 {
		t.Fatalf("Expected manager.max-concurrent-reconciles to be 10, got %d", c.Manager.MaxConcurrentReconciles)
	}
	if c.Manager.ClusterDNSSelector["k8s-app"] != "kube-dns" {
		t.Fatalf("Expected manager.cluster-dns-selector to be {\"k8s-app\": \"kube-dns\"}, got %s", c.Manager.ClusterDNSSelector)
	}
	if c.Manager.EnableMetadataServer {
		t.Fatal("Expected manager.enable-metadata-server to be false, got true")
	}
	if c.Storage.CacheSyncTimeout != 2*time.Second {
		t.Fatalf("Expected storage.cache-sync-timeout to be 2s, got %s", c.Storage.CacheSyncTimeout)
	}
	if c.Host.WireGuard.ListenPort != 51820 {
		t.Fatalf("Expected host.wireguard.listen-port to be 51820, got %d", c.Host.WireGuard.ListenPort)
	}
}

func TestConfigMapProvider(t *testing.T) {
	ctx := context.Background()
	cfg, cli := setupProviderTest(t)

	tc := []struct {
		name     string
		cmdata   map[string]string
		expected map[string]any
	}{
		{
			name: "SingleValue",
			cmdata: map[string]string{
				"key": "value",
			},
			expected: map[string]any{
				"key": "value",
			},
		},
		{
			name: "NestedValues",
			cmdata: map[string]string{
				"key":        "value",
				"nested.key": "nested.value",
			},
			expected: map[string]any{
				"key": "value",
				"nested": map[string]any{
					"key": "nested.value",
				},
			},
		},
		{
			name: "TripleNestedValues",
			cmdata: map[string]string{
				"key":            "value",
				"nested.foo.bar": "baz",
			},
			expected: map[string]any{
				"key": "value",
				"nested": map[string]any{
					"foo": map[string]any{
						"bar": "baz",
					},
				},
			},
		},
		{
			name: "SingleValueSupportedTypes",
			cmdata: map[string]string{
				"string":   "value",
				"number":   "0",
				"bool":     "true",
				"duration": "1s",
				"slice":    "[1, 2, 3]",
			},
			expected: map[string]any{
				"string":   "value",
				"number":   0,
				"bool":     true,
				"duration": time.Second,
				"slice":    []int{1, 2, 3},
			},
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			err := cli.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      strings.ToLower(tt.name),
					Namespace: "default",
				},
				Data: tt.cmdata,
			})
			if err != nil {
				t.Fatal("Failed to create configmap", err)
			}
			p := NewConfigMapProvider(cfg, client.ObjectKey{
				Name:      strings.ToLower(tt.name),
				Namespace: "default",
			})
			data, err := p.Read()
			if err != nil {
				t.Fatal("Failed to read configmap", err)
			}
			if len(data) != len(tt.expected) {
				t.Fatalf("Expected %d keys, got %d", len(tt.expected), len(data))
			}
			dataJSON, err := p.ReadBytes()
			if err != nil {
				t.Fatal("Failed to read configmap", err)
			}
			expectedJSON, _ := json.Marshal(tt.expected)
			if !bytes.Equal(expectedJSON, dataJSON) {
				t.Fatalf("Expected %s, got %s", string(expectedJSON), string(dataJSON))
			}
		})
	}
}

func setupProviderTest(t *testing.T) (*rest.Config, client.Client) {
	t.Helper()
	t.Log("Starting test environment")
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zap.Options{Development: true})))
	testenv := envtest.Environment{
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
	scheme := runtime.NewScheme()
	err = clientgoscheme.AddToScheme(scheme)
	if err != nil {
		t.Fatal("Failed to add client-go scheme to runtime scheme", err)
	}
	cli, err := client.New(cfg, client.Options{
		Scheme: scheme,
		Cache: &client.CacheOptions{
			DisableFor: []client.Object{&corev1.ConfigMap{}},
		},
	})
	if err != nil {
		t.Fatal("Failed to create client", err)
	}
	return cfg, cli
}
