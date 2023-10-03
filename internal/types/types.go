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
	"io"
	"log/slog"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
)

const (
	// NetConfEnvVar is the name of the environment variable that contains the CNI configuration.
	NetConfEnvVar = "CNI_NETWORK_CONFIG"
	// NetConfFileName is the name of the file that contains the CNI configuration.
	NetConfFileNameEnvVar = "CNI_CONF_NAME"
	// NodeNameEnvVar is the name of the environment variable that contains the node name.
	NodeNameEnvVar = "KUBERNETES_NODE_NAME"
	// BinaryDestBinEnvVar is the destination directory for the CNI binaries.
	BinaryDestBinEnvVar = "CNI_BIN_DIR"
	// BinaryDestConfEnvVar is the destination directory for the CNI configuration.
	BinaryDestConfEnvVar = "CNI_CONF_DIR"
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
	// HostLocalNetDir is the directory containing host-local CNI plugins. We remove these plugins from the CNI configuration.
	HostLocalNetDir = "/var/lib/cni/networks"
	// PluginBinaryName is the name of the plugin binary.
	PluginBinaryName = "webmesh"
	// Default kubeconfig path if not provided.
	DefaultKubeconfigPath = "/opt/cni/bin/webmesh-kubeconfig"
)

// NetConf is the configuration for the CNI plugin.
type NetConf struct {
	// NetConf is the typed configuration for the CNI plugin.
	cnitypes.NetConf `json:",inline"`

	// Kubernetes is the configuration for the Kubernetes API server and
	// information about the node we are running on.
	Kubernetes Kubernetes `json:"kubernetes"`
	// Interface is the configuration for the interface.
	Interface Interface `json:"interface"`
	// LogLevel is the log level for the plugin and managed interfaces.
	LogLevel string `json:"logLevel"`
}

// Interface is the configuration for a single interface.
type Interface struct {
	// MTU is the MTU to set on interfaces.
	MTU int `json:"mtu"`
	// DisableIPv4 is whether to disable IPv4 on the interface.
	DisableIPv4 bool `json:"disableIPv4"`
	// DisableIPv6 is whether to disable IPv6 on the interface.
	DisableIPv6 bool `json:"disableIPv6"`
}

// Kubernetes is the configuration for the Kubernetes API server and
// information about the node we are running on.
type Kubernetes struct {
	// Kubeconfig is the path to the kubeconfig file.
	Kubeconfig string `json:"kubeconfig"`
	// NodeName is the name of the node we are running on.
	NodeName string `json:"nodeName"`
	// K8sAPIRoot is the root URL of the Kubernetes API server.
	K8sAPIRoot string `json:"k8sAPIRoot"`
	// Namespace is the namespace to use for the plugin.
	Namespace string `json:"namespace"`
}

// LoadConfigFromArgs loads the configuration from the given CNI arguments.
func LoadConfigFromArgs(cmd *skel.CmdArgs) (*NetConf, error) {
	netConf := &NetConf{}
	if err := cnitypes.LoadArgs(cmd.Args, netConf); err != nil {
		return nil, err
	}
	if netConf.Kubernetes.Kubeconfig == "" {
		netConf.Kubernetes.Kubeconfig = DefaultKubeconfigPath
	}
	return netConf, nil
}

// NewLogger creates a new logger for the plugin.
func (n *NetConf) NewLogger() *slog.Logger {
	var writer io.Writer = os.Stderr
	var level slog.Level
	switch n.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	case "silent":
		writer = io.Discard
	default:
		level = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
	}))
}
