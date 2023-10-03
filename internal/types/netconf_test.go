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
	"encoding/json"
	"os"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	meshsys "github.com/webmeshproj/webmesh/pkg/meshnet/system"
)

// TestNetConf tests the NetConf type.
func TestNetConf(t *testing.T) {
	t.Parallel()

	t.Run("Defaults", func(t *testing.T) {
		t.Parallel()
		// Make sure an empty configuration produces the correct defaults.
		conf := &NetConf{}
		conf = conf.SetDefaults()
		if conf.LogLevel != "info" {
			t.Errorf("expected default log level to be info, got %s", conf.LogLevel)
		}
		if conf.Kubernetes.Kubeconfig != DefaultKubeconfigPath {
			t.Errorf("expected default kubeconfig to be %s, got %s", DefaultKubeconfigPath, conf.Kubernetes.Kubeconfig)
		}
		if conf.Interface.MTU != meshsys.DefaultMTU {
			t.Errorf("expected default MTU to be %d, got %d", meshsys.DefaultMTU, conf.Interface.MTU)
		}
		// Make sure defaults dont override existing values.
		conf = &NetConf{
			LogLevel: "debug",
			Kubernetes: Kubernetes{
				Kubeconfig: "foo",
			},
			Interface: Interface{
				MTU: 1234,
			},
		}
		conf = conf.SetDefaults()
		if conf.LogLevel != "debug" {
			t.Errorf("expected log level to be debug, got %s", conf.LogLevel)
		}
		if conf.Kubernetes.Kubeconfig != "foo" {
			t.Errorf("expected kubeconfig to be foo, got %s", conf.Kubernetes.Kubeconfig)
		}
		if conf.Interface.MTU != 1234 {
			t.Errorf("expected MTU to be 1234, got %d", conf.Interface.MTU)
		}
	})

	t.Run("Decoders", func(t *testing.T) {
		t.Parallel()

		testConf := &NetConf{
			Kubernetes: Kubernetes{
				Kubeconfig: "foo",
				NodeName:   "bar",
				K8sAPIRoot: "http://localhost:8080",
				Namespace:  "baz",
			},
			Interface: Interface{
				MTU:         1234,
				DisableIPv4: true,
				DisableIPv6: true,
			},
			LogLevel: "info",
		}
		testData, err := json.Marshal(testConf)
		if err != nil {
			t.Fatal("marshal test data", err)
		}

		t.Run("FromFile", func(t *testing.T) {
			t.Parallel()
			f, err := os.CreateTemp("", "")
			if err != nil {
				t.Fatal("create temporary file", err)
			}
			defer os.Remove(f.Name())
			_, err = f.Write(testData)
			if err != nil {
				t.Fatal("write test data", err)
			}
			err = f.Close()
			if err != nil {
				t.Fatal("close file", err)
			}
			conf, err := LoadNetConfFromFile(f.Name())
			if err != nil {
				t.Fatal("load config from file", err)
			}
			if !testConf.DeepEqual(conf) {
				t.Errorf("expected config to be equal to test config, got %v", conf)
			}
		})

		t.Run("FromArgs", func(t *testing.T) {
			t.Parallel()
			conf, err := LoadNetConfFromArgs(&skel.CmdArgs{
				StdinData: testData,
			})
			if err != nil {
				t.Fatal("load config from file", err)
			}
			if !testConf.DeepEqual(conf) {
				t.Errorf("expected config to be equal to test config, got %v", conf)
			}
		})
	})

	t.Run("Logging", func(t *testing.T) {
		t.Parallel()

		t.Run("NewLogger", func(t *testing.T) {
			t.Parallel()
		})

		t.Run("LogLevel", func(t *testing.T) {
			t.Parallel()
		})

		t.Run("LogWriter", func(t *testing.T) {
			t.Parallel()
		})
	})

	t.Run("PeerContainers", func(t *testing.T) {
		t.Parallel()
	})
}
