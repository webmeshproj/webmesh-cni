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
	"errors"
	"os"
	"testing"
)

func TestLoadInstallOptions(t *testing.T) {
	// We haven't set any environment variables so a first call should fail.
	_, err := LoadInstallOptionsFromEnv()
	if err == nil {
		t.Fatal("Expected error for invalid environment variables")
	}

	t.Run("GetExecutable", func(t *testing.T) {
		os.Setenv(NodeNameEnvVar, "test-node")
		os.Setenv(PodNamespaceEnvVar, "test-namespace")
		os.Setenv(NetConfEnvVar, "test-netconf")
		defer os.Unsetenv(NodeNameEnvVar)
		defer os.Unsetenv(PodNamespaceEnvVar)
		defer os.Unsetenv(NetConfEnvVar)
		current, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		conf, err := LoadInstallOptionsFromEnv()
		if err != nil {
			t.Error(err)
		}
		if conf.SourceBinary != current {
			t.Error("Expected executable to be current executable")
		}
		t.Run("InvalidExecutable", func(t *testing.T) {
			getExecutable = func() (string, error) {
				return "", errors.New("test error")
			}
			_, err := LoadInstallOptionsFromEnv()
			if err == nil {
				t.Error("Expected error for invalid executable")
			}
			if !errors.Is(err, ErrInvalidExecutable) {
				t.Error("Expected ErrInvalidExecutable")
			}
			getExecutable = os.Executable
		})
	})

	t.Run("Namespace", func(t *testing.T) {
		os.Setenv(NodeNameEnvVar, "test-node")
		os.Setenv(NetConfEnvVar, "test-netconf")
		defer os.Unsetenv(NodeNameEnvVar)
		defer os.Unsetenv(NetConfEnvVar)

		t.Run("EnvVarNotSet", func(t *testing.T) {
			t.Run("InCluster", func(t *testing.T) {
				t.Run("WithoutNamespaceFile", func(t *testing.T) {
					// This should always fail
					_, err := LoadInstallOptionsFromEnv()
					if err == nil {
						t.Fatal("Expected error for invalid environment variables")
					}
					if !errors.Is(err, ErrMissingEnvar) {
						t.Fatal("Expected ErrMissingEnvar")
					}
				})
				t.Run("WithNamespaceFile", func(t *testing.T) {
					tmpFile, err := os.CreateTemp("", "")
					if err != nil {
						t.Fatal(err)
					}
					defer os.Remove(tmpFile.Name())
					inClusterNamespacePath = tmpFile.Name()
					// First close the file with no contents
					err = tmpFile.Close()
					if err != nil {
						t.Fatal(err)
					}
					t.Run("EmptyNamespaceFile", func(t *testing.T) {
						// This should always fail
						_, err := LoadInstallOptionsFromEnv()
						if err == nil {
							t.Fatal("Expected error for invalid environment variables")
						}
						if !errors.Is(err, ErrMissingEnvar) {
							t.Fatal("Expected ErrMissingEnvar")
						}
					})
					t.Run("NamespaceFile", func(t *testing.T) {
						// Now write the namespace to the file
						err = os.WriteFile(inClusterNamespacePath, []byte("test-namespace"), 0644)
						if err != nil {
							t.Fatal(err)
						}
						// We should now have a valid config
						conf, err := LoadInstallOptionsFromEnv()
						if err != nil {
							t.Fatal("Unexpected error for valid namespce file", err)
						}
						if conf.Namespace != "test-namespace" {
							t.Fatal("Expected namespace to be 'test-namespace'")
						}
					})
				})
			})
			t.Run("OutOfCluster", func(t *testing.T) {
				// This should always fail
				_, err := LoadInstallOptionsFromEnv()
				if err == nil {
					t.Fatal("Expected error for invalid environment variables")
				}
				if !errors.Is(err, ErrMissingEnvar) {
					t.Fatal("Expected ErrMissingEnvar")
				}
			})
		})
	})

	t.Run("NodeName", func(t *testing.T) {
		os.Setenv(PodNamespaceEnvVar, "test-namespace")
		os.Setenv(NetConfEnvVar, "test-netconf")
		defer os.Unsetenv(PodNamespaceEnvVar)
		defer os.Unsetenv(NetConfEnvVar)

		t.Run("EnvVarNotSet", func(t *testing.T) {
			_, err := LoadInstallOptionsFromEnv()
			if err == nil {
				t.Fatal("Expected error for invalid environment variables")
			}
			if !errors.Is(err, ErrMissingEnvar) {
				t.Fatal("Expected ErrMissingEnvar")
			}
		})
		t.Run("EnvVarSet", func(t *testing.T) {
			// Set the node name to a valid value.
			os.Setenv(NodeNameEnvVar, "test-node")
			defer os.Unsetenv(NodeNameEnvVar)
			conf, err := LoadInstallOptionsFromEnv()
			if err != nil {
				t.Fatal("Unexpected error for valid environment variables")
			}
			if conf.NodeName != "test-node" {
				t.Fatal("Expected node name to be 'test-node'")
			}
		})
	})

	t.Run("NetConfTemplate", func(t *testing.T) {
		os.Setenv(PodNamespaceEnvVar, "test-namespace")
		os.Setenv(NodeNameEnvVar, "test-node")
		defer os.Unsetenv(PodNamespaceEnvVar)
		defer os.Unsetenv(NodeNameEnvVar)

		t.Run("EnvVarNotSet", func(t *testing.T) {
			// This should always fail
			_, err := LoadInstallOptionsFromEnv()
			if err == nil {
				t.Fatal("Expected error for invalid environment variables")
			}
			if !errors.Is(err, ErrMissingEnvar) {
				t.Fatal("Expected ErrMissingEnvar")
			}
		})
		t.Run("EnvVarSet", func(t *testing.T) {
			// Set the netconf template to a valid value.
			os.Setenv(NetConfEnvVar, "test-netconf")
			defer os.Unsetenv(NetConfEnvVar)
			conf, err := LoadInstallOptionsFromEnv()
			if err != nil {
				t.Fatal("Unexpected error for valid environment variables")
			}
			if conf.NetConfTemplate != "test-netconf" {
				t.Fatal("Expected netconf template to be 'test-netconf'")
			}
		})
	})
}
