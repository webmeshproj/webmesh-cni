//go:build e2e

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

package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/webmeshproj/webmesh/pkg/storage/testutil"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/webmeshproj/webmesh-cni/internal/types"
)

var (
	testImageEnvVar      = "E2E_TEST_IMAGE"
	kindExec             = os.Getenv("E2E_KIND_EXEC")
	kustomizeExec        = os.Getenv("E2E_KUSTOMIZE_EXEC")
	kubectlExec          = os.Getenv("E2E_KUBECTL_EXEC")
	defaultKindExec      = "kind"
	defaultKustomizeExec = "kustomize"
	defaultKubectlExec   = "kubectl"
	testImage            = "ghcr.io/webmeshproj/webmesh-cni:latest"
	defaultKustomization = mustAbsolute("../../deploy/kustomization.yaml")
	kustomizeImageName   = "ghcr.io/webmeshproj/webmesh-cni"
	testDirs             = []string{
		mustAbsolute("../../examples/single-cluster"),
	}
)

// E2ESpec is the spec for an end-to-end test.
type E2ESpec struct {
	// Clusters is the list of clusters to create for the test.
	Clusters []E2ECluster `yaml:"clusters,omitempty"`
}

func (e *E2ESpec) Default() {
	for _, cfg := range e.Clusters {
		cfg.Default()
	}
}

// E2ECluster is the spec of a cluster in an end-to-end test.
type E2ECluster struct {
	// Name is the name of the cluster.
	Name string `yaml:"name,omitempty"`
	// CNINamespace is the namespace the kustomization installs the CNI in.
	// Defaults to kube-system.
	CNINamespace string `yaml:"cniNamespace,omitempty"`
	// KindConfig is the path to the kind config to use for the cluster.
	// If left empty, it will be automatically detected.
	KindConfig string `yaml:"kindConfig,omitempty"`
	// Kustomization is the path to the kustomization file to use for the test.
	// Empty or "default" means to use the default kustomization.
	Kustomization string `yaml:"kustomization,omitempty"`
	// NodeCount is the number of nodes the cluster creates. This will be used
	// to verify how many webmesh-nodes should become ready.
	NodeCount int `yaml:"nodeCount,omitempty"`
	// PodCIDR is the pod CIDR to use for the cluster. This will be used to verify
	// that all nodes in the cluster are assigned an IP address from the pod CIDR.
	PodCIDR Prefix `yaml:"podCIDR,omitempty"`
	// PodCount is the number of pods that the test will create.
	// This will be used to verify that all containers become ready
	// and are assigned an IP address from the pod CIDR. Defaults to
	// the node count + 1 which is the assumed number of coredns pods
	// and a local path provisioner pod.
	// Any provided value must take coredns pods and any local-path-provisioners
	// into account. This can be set to -1 to skip the test.
	PodCount int `yaml:"podCount,omitempty"`
}

func (e *E2ECluster) Default() {
	if e.CNINamespace == "" {
		e.CNINamespace = "kube-system"
	}
	if e.Kustomization == "" {
		e.Kustomization = defaultKustomization
	}
	if e.PodCount == 0 {
		e.PodCount = e.NodeCount + 1
	}
}

type Prefix struct{ netip.Prefix }

func (p Prefix) MarshalYAML() (interface{}, error) {
	return p.String(), nil
}

func (p *Prefix) UnmarshalYAML(value *yaml.Node) error {
	s := value.Value
	if s == "" {
		return nil
	}
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return err
	}
	*p = Prefix{prefix}
	return nil
}

func TestWebmeshCNIEndToEnd(t *testing.T) {
	Init(t)
	for _, dir := range testDirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			// Setup the test.
			t.Log("Changing directory to: ", dir)
			err := os.Chdir(dir)
			if err != nil {
				t.Fatalf("Failed to change directory to %s: %v", dir, err)
			}
			// Expect an e2e.yaml file in the test directory.
			e2eFile := filepath.Join(dir, "e2e.yaml")
			t.Logf("Reading e2e file: %s", e2eFile)
			data, err := os.ReadFile(e2eFile)
			if err != nil {
				t.Fatalf("Failed to read e2e file: %v", err)
			}
			var e2eSpec E2ESpec
			err = yaml.Unmarshal(data, &e2eSpec)
			if err != nil {
				t.Fatalf("Failed to unmarshal e2e file: %v", err)
			}
			e2eSpec.Default()
			t.Logf("Using e2e spec: %+v", e2eSpec)

			// Create the clusters for the test.
			// kindConfigs := findKindConfigs(t, dir)
			kubeConfigs := make(map[string]string, len(e2eSpec.Clusters))
			for _, cfg := range e2eSpec.Clusters {
				// Create a kind clusterfor the kind config.
				kindConfig := cfg.KindConfig
				if kindConfig == "" {
					configs := findKindConfigs(t, dir)
					if len(configs) == 0 {
						t.Fatal("No kind configs found")
					}
					kindConfig = configs[0]
				}
				clusterName := fmt.Sprintf("cni-e2e-%s", filepath.Base(filepath.Dir(kindConfig)))
				kubeconf, err := os.CreateTemp("", "webmesh-cni-e2e-*")
				if err != nil {
					t.Fatalf("Failed to create kubeconf: %v", err)
				}
				kubeConfigs[cfg.Name] = kubeconf.Name()
				t.Logf("Using temporary kubeconf: %s", kubeconf.Name())
				t.Cleanup(func() {
					t.Log("Deleting kubeconf: ", kubeconf.Name())
					os.Remove(kubeconf.Name())
				})
				err = kubeconf.Close()
				if err != nil {
					t.Fatalf("Failed to close kubeconf: %v", err)
				}
				t.Logf("Creating kind cluster %q for config: %s", clusterName, kindConfig)
				execCmd(t,
					kindExec, "create", "cluster",
					"--config", kindConfig,
					"--name", clusterName,
					"--kubeconfig", kubeconf.Name(),
				)
				t.Cleanup(func() {
					t.Log("Deleting kind cluster: ", clusterName)
					execCmd(t, kindExec, "delete", "cluster", "--name", clusterName)
				})
				t.Logf("Importing image %q into kind cluster %q", testImage, clusterName)
				execCmd(t,
					kindExec, "load", "docker-image",
					"--name", clusterName,
					testImage,
				)
				var kustomization string
				if cfg.Kustomization == "" || cfg.Kustomization == "default" {
					kustomization = defaultKustomization
				} else {
					kustomization, err = filepath.Abs(cfg.Kustomization)
					if err != nil {
						t.Fatalf("Failed to get absolute path for %s: %v", cfg.Kustomization, err)
					}
				}
				kustomizationDir := filepath.Dir(kustomization)
				// Edit the kustomization to use the test image.
				t.Logf("Editing kustomization %s to use image %s", kustomization, testImage)
				doInDir(t, kustomizationDir, func() {
					execCmd(t,
						kustomizeExec, "edit", "set", "image", kustomizeImageName+"="+testImage,
					)
				})
				t.Logf("Installing webmesh-cni using kustomization %s", kustomization)
				execCmd(t,
					kubectlExec,
					"--kubeconfig", kubeconf.Name(),
					"apply", "-k", kustomizationDir,
				)
			}

			// Run the test specs.

			t.Run("ReadyWebmeshCNIPods", func(t *testing.T) {
				// We should have a ready webmesh-node for each node in the cluster.
				ctx := context.Background()
				for _, cfg := range e2eSpec.Clusters {
					t.Run(cfg.Name, func(t *testing.T) {
						kubeconf := kubeConfigs[cfg.Name]
						cli := getClient(t, kubeconf)
						expectedNodes := cfg.NodeCount
						var got int
						// There should eventually be running CNI pods for each node in the cluster.
						var pods []client.ObjectKey
						ok := testutil.Eventually[int](func() int {
							var podList corev1.PodList
							err := cli.List(ctx, &podList, client.InNamespace(cfg.CNINamespace))
							if err != nil {
								t.Fatalf("Failed to list pods: %v", err)
								return -1
							}
							pods = make([]client.ObjectKey, 0, len(podList.Items))
						Pods:
							for _, pod := range podList.Items {
								// Ignore pods we've already seen
								for _, seen := range pods {
									if seen.Namespace == pod.Namespace && seen.Name == pod.Name {
										continue Pods
									}
								}
								if pod.GetDeletionTimestamp() != nil {
									continue
								}
								if !strings.HasPrefix(pod.GetName(), "webmesh-node-") {
									continue
								}
								t.Log("Found webmesh-node pod: ", pod.Name)
								if pod.Status.Phase != corev1.PodRunning {
									t.Log("Pod is not running: ", pod.Name)
									continue
								}
								t.Log("webmesh-node pod is running: ", pod.Name)
								pods = append(pods, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name})
							}
							got = len(pods)
							return got
						}).ShouldEqual(time.Minute, time.Second*2, expectedNodes)
						if !ok {
							t.Fatalf("Failed to get expected number of CNI pods: %d, got: %d", expectedNodes, got)
						}
						// Each of the above pods should eventually reach the ready state.
						for _, podKey := range pods {
							t.Log("Waiting for CNI pod to reach ready state: ", podKey)
							ok := testutil.Eventually[bool](func() bool {
								var pod corev1.Pod
								err := cli.Get(ctx, podKey, &pod)
								if err != nil {
									t.Fatalf("Failed to get CNI pod %s: %v", podKey, err)
									return false
								}
								for _, cond := range pod.Status.Conditions {
									if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
										return true
									}
								}
								return false
							}).ShouldEqual(time.Second*30, time.Second, true)
							if !ok {
								t.Error("Failed to get CNI pod to ready state: ", podKey)
							}
						}
					})
				}
			})

			t.Run("CoreDNSPodsAssignedIPs", func(t *testing.T) {
				// The clusters are assumed to use coredns and each coredns pod
				// should eventually be assigned an IP address from the pod CIDR.
				ctx := context.Background()
				for _, cfg := range e2eSpec.Clusters {
					t.Run(cfg.Name, func(t *testing.T) {
						kubeconf := kubeConfigs[cfg.Name]
						cli := getClient(t, kubeconf)
						expectedNodes := cfg.NodeCount
						var got int
						// There should eventually be running CoreDNS pods for each node in the cluster.
						var pods []client.ObjectKey
						ok := testutil.Eventually[int](func() int {
							var podList corev1.PodList
							err := cli.List(ctx, &podList, client.InNamespace("kube-system"), client.MatchingLabels{
								"k8s-app": "kube-dns",
							})
							if err != nil {
								t.Fatalf("Failed to list pods: %v", err)
								return -1
							}
							pods = make([]client.ObjectKey, 0, len(podList.Items))
						Pods:
							for _, pod := range podList.Items {
								// Ignore pods we've already seen
								for _, seen := range pods {
									if seen.Namespace == pod.Namespace && seen.Name == pod.Name {
										continue Pods
									}
								}
								if pod.GetDeletionTimestamp() != nil {
									continue
								}
								t.Log("Found CoreDNS pod: ", pod.Name)
								if pod.Status.Phase != corev1.PodRunning {
									t.Log("Pod is not running: ", pod.Name)
									continue
								}
								t.Log("CoreDNS pod is running: ", pod.Name)
								pods = append(pods, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name})
							}
							got = len(pods)
							return got
						}).ShouldEqual(time.Second*30, time.Second, expectedNodes)
						if !ok {
							t.Fatalf("Failed to get expected number of CoreDNS pods: %d, got: %d", expectedNodes, got)
						}
						// Each of the above pods should eventually reach the ready state.
						for _, podKey := range pods {
							t.Log("Waiting for CoreDNS pod to reach ready state: ", podKey)
							ok := testutil.Eventually[bool](func() bool {
								var pod corev1.Pod
								err := cli.Get(ctx, podKey, &pod)
								if err != nil {
									t.Fatalf("Failed to get pod %s: %v", podKey, err)
									return false
								}
								for _, cond := range pod.Status.Conditions {
									if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
										return true
									}
								}
								return false
							}).ShouldEqual(time.Second*30, time.Second, true)
							if !ok {
								t.Error("Failed to get CoreDNS pod to ready state: ", podKey)
							}
						}
						// Each of the above pods IP addresses should be in the pod CIDR.
						seen := make(map[netip.Addr]struct{})
						for _, podKey := range pods {
							t.Logf("Checking that %s has an IP address from the pod CIDR", podKey)
							var pod corev1.Pod
							err := cli.Get(ctx, podKey, &pod)
							if err != nil {
								t.Fatalf("Failed to get pod %s: %v", podKey, err)
							}
							var hasIP bool
							for _, ip := range pod.Status.PodIPs {
								addr, err := netip.ParseAddr(ip.IP)
								if err != nil {
									t.Fatalf("Failed to parse IP address %s: %v", ip.IP, err)
								}
								if _, ok := seen[addr]; ok {
									t.Errorf("CoreDNS pod %s has duplicate IP address %s", podKey, ip.IP)
									continue
								}
								seen[addr] = struct{}{}
								if cfg.PodCIDR.Contains(addr) {
									t.Logf("CoreDNS pod %s has unique IP address %s from pod CIDR %s", podKey, ip.IP, cfg.PodCIDR)
									hasIP = true
									return
								}
							}
							if !hasIP {
								t.Errorf("Pod %s does not have an IP address from pod CIDR %s", podKey, cfg.PodCIDR)
							}
						}
					})
				}
			})

			t.Run("ReadyPods", func(t *testing.T) {
				// The number of containers provided in the spec should exist and
				// each have a unique IP address from the pod CIDR.
				// We should have a ready webmesh-node for each node in the cluster.
				ctx := context.Background()
				for _, cfg := range e2eSpec.Clusters {
					t.Run(cfg.Name, func(t *testing.T) {
						if cfg.PodCount <= 0 {
							t.Skip("No pod count specified for cluster")
						}
						kubeconf := kubeConfigs[cfg.Name]
						cli := getClient(t, kubeconf)
						// There should eventually be the following running pods.
						///    podCount +
						//     cni-nodes (nodeCount) +
						//     etcd (1) +
						//     control-plane (3)
						//     kube-proxy (nodeCount)
						var got int
						expectedPods := cfg.PodCount + cfg.NodeCount + 1 + 3 + cfg.NodeCount
						var pods []client.ObjectKey
						ok := testutil.Eventually[int](func() int {
							var podList corev1.PodList
							err := cli.List(ctx, &podList, client.InNamespace(""))
							if err != nil {
								t.Fatalf("Failed to list pods: %v", err)
								return -1
							}
							pods = make([]client.ObjectKey, 0, len(podList.Items))
						Pods:
							for _, pod := range podList.Items {
								// Ignore pods we've already seen.
								for _, seen := range pods {
									if seen.Namespace == pod.Namespace && seen.Name == pod.Name {
										continue Pods
									}
								}
								if pod.GetDeletionTimestamp() != nil {
									continue
								}
								t.Log("Found pod: ", pod.Name)
								if pod.Status.Phase != corev1.PodRunning {
									t.Log("Pod is not running: ", pod.Name)
									continue
								}
								t.Log("Pod is running: ", pod.Name)
								pods = append(pods, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name})
							}
							got = len(pods)
							return got
						}).ShouldEqual(time.Second*30, time.Second, expectedPods)
						if !ok {
							t.Fatalf("Failed to get expected number of running pods: %d, got: %d", expectedPods, got)
						}
						// The podCount of those pods should eventually be ready with unique IP addresses from the pod CIDR.
						var cniManagedPods []*corev1.Pod
						expectedPods = cfg.PodCount
						got = 0
						ok = testutil.Eventually[int](func() int {
							var podList corev1.PodList
							err := cli.List(ctx, &podList, client.InNamespace(""))
							if err != nil {
								t.Fatalf("Failed to list pods: %v", err)
								return -1
							}
						Pods:
							for _, pod := range podList.Items {
								// If we've already seen the pod continue.
								p := pod
								for _, seen := range cniManagedPods {
									if seen.Name == pod.Name && seen.Namespace == pod.Namespace {
										continue Pods
									}
								}
								if pod.GetDeletionTimestamp() != nil {
									continue
								}
								name := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
								t.Log("Found pod: ", pod.Name)
								if pod.Status.Phase != corev1.PodRunning {
									t.Log("Pod is not running: ", name)
									continue
								}
								t.Log("Pod is running: ", name)
								var isReady bool
								for _, cond := range pod.Status.Conditions {
									if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
										isReady = true
										break
									}
								}
								if !isReady {
									t.Log("Pod is not ready: ", name)
									continue
								}
								t.Logf("Checking that %s has an IP address from the pod CIDR", name)
								var hasIP bool
								for _, ip := range pod.Status.PodIPs {
									addr, err := netip.ParseAddr(ip.IP)
									if err != nil {
										t.Fatalf("Failed to parse IP address %s: %v", ip.IP, err)
									}
									if cfg.PodCIDR.Contains(addr) {
										t.Logf("Pod %s has IP address %s from pod CIDR %s", name, ip.IP, cfg.PodCIDR)
										hasIP = true
										break
									}
								}
								if !hasIP {
									t.Log("Ignoring pod without IP address from pod CIDR: ", name)
									continue
								}
								cniManagedPods = append(cniManagedPods, &p)
							}
							got = len(cniManagedPods)
							return got
						}).ShouldEqual(time.Second*30, time.Second, expectedPods)
						if !ok {
							t.Fatalf("Failed to get expected number of pods in the CNI network: %d, got: %d", expectedPods, got)
						}
						seen := make(map[netip.Addr]struct{})
					Pods:
						for _, pod := range cniManagedPods {
						IPs:
							for _, ip := range pod.Status.PodIPs {
								addr, err := netip.ParseAddr(ip.IP)
								if err != nil {
									t.Fatalf("Failed to parse IP address %s: %v", ip.IP, err)
								}
								if !cfg.PodCIDR.Contains(addr) {
									continue IPs
								}
								if _, ok := seen[addr]; ok {
									t.Errorf("Pod %s has duplicate IP address %s", pod.Name, ip.IP)
									continue IPs
								}
								t.Logf("Pod %s has unique IP address %s", pod.Name, ip.IP)
								seen[addr] = struct{}{}
								continue Pods
							}
						}
					})
				}
			})
		})
	}
}

// Init initializes the end-to-end test.
func Init(t *testing.T) {
	t.Helper()
	// Set the controller-runtime logger.
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zap.Options{Development: true})))
	// Set the path to the kind binary.
	var err error
	if kindExec == "" {
		kindExec = defaultKindExec
	}
	kindExec, err = exec.LookPath(defaultKindExec)
	if err != nil {
		t.Fatal("Failed to resolve kind executable path:", err)
	}
	// Set the path to the kustomize binary.
	if kustomizeExec == "" {
		kustomizeExec = defaultKustomizeExec
	}
	kustomizeExec, err = exec.LookPath(kustomizeExec)
	if err != nil {
		t.Fatal("Failed to resolve kustomize executable path:", err)
	}
	// Set the path to the kubectl binary.
	if kubectlExec == "" {
		kubectlExec = defaultKubectlExec
	}
	kubectlExec, err = exec.LookPath(kubectlExec)
	if err != nil {
		t.Fatal("Failed to resolve kubectl executable path:", err)
	}
	envTestImage := os.Getenv(testImageEnvVar)
	if envTestImage != "" {
		testImage = envTestImage
	}
}

func findKindConfigs(t *testing.T, path string) []string {
	t.Helper()
	var configs []string
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".yaml" {
			return nil
		}
		t.Log("Checking if path is a cluster config: ", path)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var config map[string]any
		err = yaml.Unmarshal(data, &config)
		if err != nil {
			return err
		}
		if config["kind"] == "Cluster" {
			t.Log("Found kind cluster config: ", path)
			configs = append(configs, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk %s: %v", path, err)
	}
	return configs
}

func getClient(t *testing.T, kubeconfig string) client.Client {
	t.Helper()
	cfg, err := clientcmd.BuildConfigFromKubeconfigGetter("", func() (*clientcmdapi.Config, error) {
		conf, err := clientcmd.LoadFromFile(kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig from file: %w", err)
		}
		return conf, nil
	})
	if err != nil {
		t.Fatalf("Failed to create REST config: %v", err)
	}
	cli, err := types.NewRawClientForConfig(cfg)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	return cli
}

func doInDir(t *testing.T, dir string, fn func()) {
	t.Helper()
	curdir := mustAbsolute(".")
	t.Log("Changing directory to: ", dir)
	err := os.Chdir(dir)
	if err != nil {
		t.Fatalf("Failed to change directory to %s: %v", dir, err)
	}
	defer func() {
		t.Log("Changing directory back to: ", curdir)
		err := os.Chdir(curdir)
		if err != nil {
			t.Fatalf("Failed to change directory to %s: %v", curdir, err)
		}
	}()
	fn()
}

func execCmd(t *testing.T, cmd string, args ...string) {
	t.Helper()
	cmdStr := func() string {
		cmdStr := cmd + " "
		for _, arg := range args {
			cmdStr += fmt.Sprintf("%v ", arg)
		}
		return cmdStr
	}()
	t.Log("Running command: ", cmdStr)
	execCmd := exec.Command(cmd, args...)
	execCmd.Stdout = &testLogWriter{t: t}
	execCmd.Stderr = &testLogWriter{t: t}
	if err := execCmd.Run(); err != nil {
		t.Fatalf("Failed to run %q: %v", cmdStr, err)
	}
}

func mustAbsolute(path string) string {
	absPath, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	return absPath
}

type testLogWriter struct {
	t *testing.T
}

func (w *testLogWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	data := bytes.TrimSpace(p)
	if len(data) == 0 {
		return
	}
	w.t.Log(string(data))
	return
}

func toAnySlice[T any](slice []T) []any {
	var anySlice []any
	for _, s := range slice {
		anySlice = append(anySlice, s)
	}
	return anySlice
}
