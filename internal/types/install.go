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
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	// NetConfEnvVar is the name of the environment variable that contains the CNI configuration.
	NetConfEnvVar = "CNI_NETWORK_CONFIG"
	// NetConfFileName is the name of the file that contains the CNI configuration.
	NetConfFileNameEnvVar = "CNI_CONF_NAME"
	// BinaryDestBinEnvVar is the destination directory for the CNI binaries.
	BinaryDestBinEnvVar = "CNI_BIN_DIR"
	// BinaryDestConfEnvVar is the destination directory for the CNI configuration.
	BinaryDestConfEnvVar = "CNI_CONF_DIR"
	// CNINetDirEnvVar is the directory containing host-local IPAM allocations. We release these
	// when we start for the first time.
	CNINetDirEnvVar = "CNI_NET_DIR"
	// NodeNameEnvVar is the name of the environment variable that contains the node name.
	NodeNameEnvVar = "KUBERNETES_NODE_NAME"
	// PodNamespaceEnvVar is the name of the environment variable that contains the pod namespace.
	PodNamespaceEnvVar = "KUBERNETES_POD_NAMESPACE"
	// NodeNameReplaceStr is the string that will be replaced in the CNI configuration with the node name.
	NodeNameReplaceStr = "__KUBERNETES_NODE_NAME__"
	// PodNamespaceReplaceStr is the string that will be replaced in the CNI configuration with the pod namespace.
	PodNamespaceReplaceStr = "__KUBERNETES_POD_NAMESPACE__"
	// KubeAPIEndpointReplaceStr is the string that will be replaced in the CNI configuration with the Kubernetes API endpoint.
	APIEndpointReplaceStr = "__KUBERNETES_API_ENDPOINT__"
	// KubeconfigFilepathReplaceStr is the string that will be replaced in the CNI configuration with the kubeconfig filepath.
	KubeconfigFilepathReplaceStr = "__KUBECONFIG_FILEPATH__"
	// HostLocalNetDir is the directory containing host-local IPAM allocations. We release these when we start for the first time.
	DefaultHostLocalNetDir = "/var/lib/cni/networks"
	// DefaultDestBin is the default destination directory for the CNI binaries.
	DefaultDestBin = "/opt/cni/bin"
	// DefaultDestConfDir is the default destination directory for the CNI configuration.
	DefaultDestConfDir = "/etc/cni/net.d"
	// DefaultDestConfName is the default name of the CNI configuration file.
	DefaultDestConfName = "10-webmesh.conflist"
	// DefaultNetConfPath is the default path to the CNI configuration file.
	DefaultNetConfPath = "/etc/cni/net.d/10-webmesh.conflist"
	// Default kubeconfig path if not provided.
	DefaultKubeconfigPath = "/opt/cni/bin/webmesh-kubeconfig"
	// DefaultNamespace is the default namespace to use for the plugin.
	DefaultNamespace = "kube-system"
	// PluginKubeconfigName is the name of the kubeconfig file for the plugin.
	PluginKubeconfigName = "webmesh-kubeconfig"
	// PluginBinaryName is the name of the plugin binary.
	PluginBinaryName = "webmesh"
	// KubeconfigContextName is the name of the context in the kubeconfig.
	KubeconfigContextName = "webmesh-cni"
)

// ErrMissingEnvVar is returned when a required environment variable is missing.
var ErrMissingEnvar = fmt.Errorf("missing environment variable")

// ErrGetExecutable is returned when we can't determine the binary to install.
var ErrInvalidExecutable = fmt.Errorf("error getting executable path")

// InstallOptions are the options for the install component.
type InstallOptions struct {
	// SourceBinary is the path to the source binary.
	SourceBinary string
	// BinaryDestBin is the destination directory for the CNI binaries.
	BinaryDestBin string
	// BinaryName is the name of the plugin binary.
	BinaryName string
	// ConfDestDir is the destination directory for the CNI configuration.
	ConfDestDir string
	// ConfDestName is the name of the CNI configuration file.
	ConfDestName string
	// HostLocalNetDir is the directory containing host-local IPAM allocations.
	// We release these when we start for the first time.
	HostLocalNetDir string
	// NetConfTemplate is the template for the CNI configuration.
	NetConfTemplate string
	// NodeName is the name of the node we are running on.
	NodeName string
	// Namespace is the namespace to use for the plugin.
	Namespace string
}

// getExecutable is the function for retrieving the current executable.
// This is overridden in tests.
var getExecutable = os.Executable

// LoadInstallOptionsFromEnv loads the install options from the environment.
func LoadInstallOptionsFromEnv() (*InstallOptions, error) {
	var opts InstallOptions
	var err error
	opts.BinaryName = PluginBinaryName
	opts.HostLocalNetDir = os.Getenv(CNINetDirEnvVar)
	if opts.HostLocalNetDir == "" {
		opts.HostLocalNetDir = DefaultHostLocalNetDir
	}
	opts.NodeName = os.Getenv(NodeNameEnvVar)
	if opts.NodeName == "" {
		return nil, fmt.Errorf("%w: %s", ErrMissingEnvar, NodeNameEnvVar)
	}
	opts.Namespace = os.Getenv(PodNamespaceEnvVar)
	if opts.Namespace == "" {
		opts.Namespace, err = getInClusterNamespace()
		if err != nil {
			return nil, fmt.Errorf("%s %w and error getting in-cluster namespace: %v", PodNamespaceEnvVar, ErrMissingEnvar, err)
		}
		if opts.Namespace == "" {
			return nil, fmt.Errorf("%w: %s", ErrMissingEnvar, PodNamespaceEnvVar)
		}
	}
	opts.NetConfTemplate = os.Getenv(NetConfEnvVar)
	if opts.NetConfTemplate == "" {
		return nil, fmt.Errorf("%w: %s", ErrMissingEnvar, NetConfEnvVar)
	}
	opts.SourceBinary, err = getExecutable()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidExecutable, err)
	}
	opts.BinaryDestBin = os.Getenv(BinaryDestBinEnvVar)
	if opts.BinaryDestBin == "" {
		opts.BinaryDestBin = DefaultDestBin
	}
	opts.ConfDestDir = os.Getenv(BinaryDestConfEnvVar)
	if opts.ConfDestDir == "" {
		opts.ConfDestDir = DefaultDestConfDir
	}
	opts.ConfDestName = os.Getenv(NetConfFileNameEnvVar)
	if opts.ConfDestName == "" {
		opts.ConfDestName = DefaultDestConfName
	}
	return &opts, nil
}

// getInstallRestConfig is the function for retrieving the REST config during installation.
// This is overridden in tests.
var getInstallRestConfig = ctrl.GetConfig

// RunInstall is an alias for running all install steps.
func (i *InstallOptions) RunInstall() error {
	apicfg, err := getInstallRestConfig()
	if err != nil {
		log.Println("error getting kubeconfig:", err)
		return err
	}
	// Clear any local host IPAM allocations that already exist.
	log.Println("clearing host-local IPAM allocations from", i.HostLocalNetDir)
	err = i.ClearHostLocalIPAMAllocations()
	if err != nil {
		log.Println("error clearing host-local IPAM allocations:", err)
		return err
	}
	pluginBin := filepath.Join(i.BinaryDestBin, PluginBinaryName)
	log.Println("installing plugin binary to -> ", pluginBin)
	err = i.InstallPlugin(pluginBin)
	if err != nil {
		log.Println("error installing plugin:", err)
		return err
	}
	err = os.Chdir(i.BinaryDestBin)
	if err != nil {
		log.Printf("error changing directory to %s: %v", i.BinaryDestBin, err)
		return err
	}
	for _, symlinkName := range []string{"loopback", "host-local"} {
		log.Println("creating symlink for ->", filepath.Join(i.BinaryDestBin, symlinkName))
		err = os.Symlink(PluginBinaryName, symlinkName)
		if err != nil {
			log.Printf("error creating symlink for %s: %v", symlinkName, err)
			return err
		}
	}
	kubeconfigPath := filepath.Join(i.BinaryDestBin, PluginKubeconfigName)
	log.Println("installing kubeconfig to destination -> ", kubeconfigPath)
	err = i.InstallKubeconfig(kubeconfigPath)
	if err != nil {
		log.Println("error writing kubeconfig:", err)
		return err
	}
	log.Println("rendering CNI configuration")
	netConf := i.RenderNetConf(apicfg.Host)
	log.Println("effective CNI configuration ->\n", netConf)
	confPath := filepath.Join(i.ConfDestDir, i.ConfDestName)
	log.Println("installing CNI configuration to destination -> ", confPath)
	err = i.InstallNetConf(confPath, netConf)
	if err != nil {
		log.Println("error writing netconf:", err)
		return err
	}
	return nil
}

// ClearHostLocalIPAMAllocations removes any host-local CNI plugins from the CNI configuration.
func (i *InstallOptions) ClearHostLocalIPAMAllocations() error {
	dir, err := os.ReadDir(i.HostLocalNetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("error reading host-local CNI directory: %w", err)
	}
	for _, file := range dir {
		// Skip parent directory.
		if file.Name() == filepath.Base(i.HostLocalNetDir) {
			continue
		}
		err = os.RemoveAll(filepath.Join(i.HostLocalNetDir, file.Name()))
		if err != nil {
			return fmt.Errorf("error removing host-local CNI plugin: %w", err)
		}
	}
	return nil
}

// InstallPlugin installs the plugin.
func (i *InstallOptions) InstallPlugin(dest string) error {
	if err := installPluginBinary(i.SourceBinary, dest); err != nil {
		log.Printf("error installing binary to %s: %v", dest, err)
		return err
	}
	return nil
}

// InstallNetConf installs the CNI configuration.
func (i *InstallOptions) InstallNetConf(path string, config string) error {
	if err := os.WriteFile(path, []byte(config), 0644); err != nil {
		log.Println("error writing CNI configuration:", err)
		return err
	}
	return nil
}

// RenderNetConf renders the CNI configuration.
func (i *InstallOptions) RenderNetConf(apiEndpoint string) string {
	kubeconfigPath := strings.TrimPrefix(filepath.Join(i.BinaryDestBin, PluginKubeconfigName), "/host")
	conf := i.NetConfTemplate
	conf = strings.Replace(conf, NodeNameReplaceStr, i.NodeName, -1)
	conf = strings.Replace(conf, PodNamespaceReplaceStr, i.Namespace, -1)
	conf = strings.Replace(conf, APIEndpointReplaceStr, apiEndpoint, -1)
	conf = strings.Replace(conf, KubeconfigFilepathReplaceStr, kubeconfigPath, -1)
	return conf
}

// InstallKubeconfig writes the kubeconfig file for the plugin.
func (i *InstallOptions) InstallKubeconfig(kubeconfigPath string) error {
	kubeconfig, err := i.GetKubeconfig()
	if err != nil {
		return fmt.Errorf("error getting kubeconfig: %w", err)
	}
	if err := clientcmd.WriteToFile(kubeconfig, kubeconfigPath); err != nil {
		log.Println("error writing kubeconfig:", err)
		return err
	}
	return nil
}

// GetKubeconfig tries to build a kubeconfig from the current in cluster
// configuration.
func (i *InstallOptions) GetKubeconfig() (clientcmdapi.Config, error) {
	// If our cert data is empty, convert it to the contents of the cert file.
	cfg, err := getInstallRestConfig()
	if err != nil {
		return clientcmdapi.Config{}, fmt.Errorf("error getting config: %w", err)
	}
	return KubeconfigFromRestConfig(cfg, i.Namespace)
}

// KubeconfigFromRestConfig returns a kubeconfig from the given rest config.
// It reads in any files and encodes them as base64 in the final configuration.
// GetKubeconfig tries to build a kubeconfig from the current in cluster
// configuration.
func KubeconfigFromRestConfig(cfg *rest.Config, namespace string) (clientcmdapi.Config, error) {
	if cfg.CAFile != "" {
		caData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return clientcmdapi.Config{}, fmt.Errorf("error reading certificate authority data: %w", err)
		}
		cfg.CAData = caData
	}
	// If our bearer token is a file, convert it to the contents of the file.
	if cfg.BearerTokenFile != "" {
		token, err := os.ReadFile(cfg.BearerTokenFile)
		if err != nil {
			return clientcmdapi.Config{}, fmt.Errorf("error reading bearer token: %w", err)
		}
		cfg.BearerToken = string(token)
	}
	// If our client certificate is a file, convert it to the contents of the file.
	if cfg.CertFile != "" {
		cert, err := os.ReadFile(cfg.CertFile)
		if err != nil {
			log.Println("error reading client certificate:", err)
			return clientcmdapi.Config{}, fmt.Errorf("error reading client certificate: %w", err)
		}
		cfg.CertData = cert
	}
	// Same for any key
	if cfg.KeyFile != "" {
		key, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			log.Println("error reading client key:", err)
			return clientcmdapi.Config{}, fmt.Errorf("error reading client key: %w", err)
		}
		cfg.KeyData = key
	}
	return clientcmdapi.Config{
		Kind:       "Config",
		APIVersion: "v1",
		Clusters: map[string]*clientcmdapi.Cluster{
			KubeconfigContextName: {
				Server:                   cfg.Host,
				TLSServerName:            cfg.ServerName,
				InsecureSkipTLSVerify:    cfg.Insecure,
				CertificateAuthorityData: cfg.CAData,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			KubeconfigContextName: {
				ClientCertificateData: cfg.CertData,
				ClientKeyData:         cfg.KeyData,
				Token:                 cfg.BearerToken,
				Impersonate:           cfg.Impersonate.UserName,
				ImpersonateGroups:     cfg.Impersonate.Groups,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			KubeconfigContextName: {
				Cluster:   KubeconfigContextName,
				AuthInfo:  KubeconfigContextName,
				Namespace: namespace,
			},
		},
		CurrentContext: KubeconfigContextName,
	}, nil
}

var setSuidBit = setSuidBitToFile

// installPluginBinary copies the binary to the destination directory.
func installPluginBinary(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("error opening binary: %w", err)
	}
	defer f.Close()
	// Create the destination directory if it doesn't exist.
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("error creating destination directory: %w", err)
	}
	// Create the destination file.
	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("error creating destination file: %w", err)
	}
	// Copy the binary to the destination file.
	if _, err := io.Copy(out, f); err != nil {
		return fmt.Errorf("error copying binary: %w", err)
	}
	err = out.Close()
	if err != nil {
		return fmt.Errorf("error closing destination file: %w", err)
	}
	// Make the destination file executable.
	if err := os.Chmod(dest, 0755); err != nil {
		return fmt.Errorf("error making destination file executable: %w", err)
	}
	return setSuidBit(dest)
}

func setSuidBitToFile(file string) error {
	if runtime.GOOS == "windows" {
		// chmod doesn't work on windows
		log.Println("chmod doesn't work on windows, skipping setSuidBit()")
		return nil
	}
	fi, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("failed to stat file: %s", err)
	}
	err = os.Chmod(file, fi.Mode()|os.FileMode(uint32(8388608)))
	if err != nil {
		return fmt.Errorf("failed to chmod file: %s", err)
	}
	return nil
}

// inClusterNamespacePath is the path to the namespace file in the pod.
// Declared as a variable for testing.
var inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

func getInClusterNamespace() (string, error) {
	// Load the namespace file and return its content
	namespace, err := os.ReadFile(inClusterNamespacePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("namespace file does not exist, not running in-cluster")
		}
		return "", fmt.Errorf("error reading namespace file: %w", err)
	}
	return string(bytes.TrimSpace(namespace)), nil
}
