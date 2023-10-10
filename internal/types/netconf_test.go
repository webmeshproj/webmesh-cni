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
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	meshsys "github.com/webmeshproj/webmesh/pkg/meshnet/system"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"

	v1 "github.com/webmeshproj/webmesh-cni/api/v1"
)

// TestNetConf tests the NetConf type.
func TestNetConf(t *testing.T) {
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

	t.Run("Defaults", func(t *testing.T) {
		t.Parallel()
		// Make sure a nil configuration produces the correct defaults.
		var conf *NetConf
		if conf.DeepEqual(testConf) {
			t.Errorf("expected testConf to not be equal to nil conf")
		}
		if testConf.DeepEqual(conf) {
			t.Errorf("expected nil conf to not be equal to testConf")
		}
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
		if conf.DeepEqual(testConf) {
			t.Errorf("expected testConf to not be equal to conf")
		}
		// Make sure the same goes for an empty one
		conf = &NetConf{}
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
		if conf.DeepEqual(testConf) {
			t.Errorf("expected testConf to not be equal to conf")
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
			t.Run("NonExist", func(t *testing.T) {
				t.Parallel()
				_, err := LoadNetConfFromFile("nonexist")
				if err == nil {
					t.Error("expected error, got nil")
				}
			})
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

		t.Run("InvalidData", func(t *testing.T) {
			_, err := DecodeNetConf([]byte("invalid"))
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	})

	t.Run("Logging", func(t *testing.T) {
		t.Parallel()

		t.Run("NewLogger", func(t *testing.T) {
			t.Parallel()
			// NewLogger should never return nil.
			log := testConf.NewLogger(&skel.CmdArgs{})
			if log == nil {
				t.Error("expected logger to not be nil")
			}
		})

		t.Run("LogWriter", func(t *testing.T) {
			t.Parallel()
			conf := &NetConf{}
			tc := []struct {
				name     string
				level    string
				expected io.Writer
			}{
				{
					name:     "Default",
					expected: os.Stderr,
				},
				{
					name:     "Debug",
					level:    "debug",
					expected: os.Stderr,
				},
				{
					name:     "Info",
					level:    "info",
					expected: os.Stderr,
				},
				{
					name:     "Warn",
					level:    "warn",
					expected: os.Stderr,
				},
				{
					name:     "Error",
					level:    "error",
					expected: os.Stderr,
				},
				{
					name:     "Silent",
					level:    "silent",
					expected: io.Discard,
				},
				{
					name:     "Off",
					level:    "off",
					expected: io.Discard,
				},
			}
			for _, c := range tc {
				conf.LogLevel = c.level
				if conf.LogWriter() != c.expected {
					t.Errorf("expected log writer to be %v, got %v", c.expected, conf.LogWriter())
				}
			}
		})

		t.Run("LogLevels", func(t *testing.T) {
			t.Parallel()
			conf := &NetConf{}
			tc := []struct {
				name     string
				level    string
				expected slog.Level
			}{
				{
					name:     "Default",
					expected: slog.LevelInfo,
				},
				{
					name:     "Debug",
					level:    "debug",
					expected: slog.LevelDebug,
				},
				{
					name:     "DebugAllCaps",
					level:    "DEBUG",
					expected: slog.LevelDebug,
				},
				{
					name:     "DebugMixedCase",
					level:    "DeBuG",
					expected: slog.LevelDebug,
				},
				{
					name:     "Info",
					level:    "info",
					expected: slog.LevelInfo,
				},
				{
					name:     "InfoAllCaps",
					level:    "INFO",
					expected: slog.LevelInfo,
				},
				{
					name:     "InfoMixedCase",
					level:    "InFo",
					expected: slog.LevelInfo,
				},
				{
					name:     "Warn",
					level:    "warn",
					expected: slog.LevelWarn,
				},
				{
					name:     "WarnAllCaps",
					level:    "WARN",
					expected: slog.LevelWarn,
				},
				{
					name:     "WarnMixedCase",
					level:    "WaRn",
					expected: slog.LevelWarn,
				},
				{
					name:     "Error",
					level:    "error",
					expected: slog.LevelError,
				},
				{
					name:     "ErrorAllCaps",
					level:    "ERROR",
					expected: slog.LevelError,
				},
				{
					name:     "ErrorMixedCase",
					level:    "ErRoR",
					expected: slog.LevelError,
				},
			}
			for _, c := range tc {
				conf.LogLevel = c.level
				if conf.SlogLevel() != c.expected {
					t.Errorf("expected slog level to be %v, got %v", c.expected, conf.SlogLevel())
				}
			}
		})

	})

	t.Run("PeerContainers", func(t *testing.T) {
		t.Parallel()

		t.Run("ObjectKeys", func(t *testing.T) {
			t.Parallel()
			// Object keys should be the container ID and configured namespace.
			conf := &NetConf{
				Kubernetes: Kubernetes{
					Namespace: "foo",
				},
			}
			args := &skel.CmdArgs{
				ContainerID: "bar",
			}
			key := conf.ObjectKeyFromArgs(args)
			if key.Name != args.ContainerID {
				t.Errorf("expected object key name to be %s, got %s", args.ContainerID, key.Name)
			}
			if key.Namespace != conf.Kubernetes.Namespace {
				t.Errorf("expected object key namespace to be %s, got %s", conf.Kubernetes.Namespace, key.Namespace)
			}
		})

		t.Run("ContainerObjects", func(t *testing.T) {
			t.Parallel()
			// A new container's spec should match the given args and configuration.
			conf := &NetConf{
				Interface: Interface{
					MTU:         1234,
					DisableIPv4: true,
					DisableIPv6: true,
				},
				Kubernetes: Kubernetes{
					NodeName:  "k8s-node",
					Namespace: "default",
				},
				LogLevel: "debug",
			}
			args := &skel.CmdArgs{
				ContainerID: "bar",
				Netns:       "/proc/1234/ns/net",
			}
			container := conf.ContainerFromArgs(args)

			// Make sure the container's spec matches the configuration.
			EnsureContainerEqualsTestConf(t, conf, &container, args)

			// Set the container ID to a really long name and make sure the interface
			// is truncated to 15 characters.
			args.ContainerID = "reallylongcontainerid"
			container = conf.ContainerFromArgs(args)
			if len(container.Spec.IfName) != 15 {
				t.Errorf("expected container ifname to be truncated to 15 characters, got %s", container.Spec.IfName)
			}
			if container.Spec.IfName != IfacePrefix+"reallylon0" {
				t.Errorf("expected container ifname to be %s, got %s", "wmeshreallylongc0", container.Spec.IfName)
			}
		})
	})
}

func EnsureContainerEqualsTestConf(t *testing.T, conf *NetConf, container *v1.PeerContainer, args *skel.CmdArgs) {
	if container.Name != args.ContainerID {
		t.Errorf("expected container name to be %s, got %s", args.ContainerID, container.Name)
	}
	if container.Namespace != conf.Kubernetes.Namespace {
		t.Errorf("expected container namespace to be %s, got %s", conf.Kubernetes.Namespace, container.Namespace)
	}
	if container.Spec.NodeID != meshtypes.TruncateID(args.ContainerID) {
		t.Errorf("expected container node ID to be %s, got %s", args.ContainerID, container.Spec.NodeID)
	}
	if container.Spec.Netns != args.Netns {
		t.Errorf("expected container netns to be %s, got %s", args.Netns, container.Spec.Netns)
	}
	expectedIfName := IfNameFromID(meshtypes.TruncateID(args.ContainerID))
	if container.Spec.IfName != expectedIfName {
		t.Errorf("expected container ifname to be %s, got %s", expectedIfName, container.Spec.IfName)
	}
	if container.Spec.NodeName != conf.Kubernetes.NodeName {
		t.Errorf("expected container node name to be %s, got %s", conf.Kubernetes.NodeName, container.Spec.NodeName)
	}
	if container.Spec.MTU != conf.Interface.MTU {
		t.Errorf("expected container mtu to be %d, got %d", conf.Interface.MTU, container.Spec.MTU)
	}
	if container.Spec.DisableIPv4 != conf.Interface.DisableIPv4 {
		t.Errorf("expected container disable ipv4 to be %t, got %t", conf.Interface.DisableIPv4, container.Spec.DisableIPv4)
	}
	if container.Spec.DisableIPv6 != conf.Interface.DisableIPv6 {
		t.Errorf("expected container disable ipv6 to be %t, got %t", conf.Interface.DisableIPv6, container.Spec.DisableIPv6)
	}
	if container.Spec.LogLevel != conf.LogLevel {
		t.Errorf("expected container log level to be %s, got %s", conf.LogLevel, container.Spec.LogLevel)
	}
}
