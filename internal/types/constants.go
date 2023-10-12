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
	"fmt"
)

const (
	// PodCIDREnvVar is the name of the environment variable that contains the pod CIDR.
	PodCIDREnvVar = "WEBMESH_CNI_POD_CIDR"
	// ServiceCIDREnvVar is the name of the environment variable that contains the service CIDR.
	ServiceCIDREnvVar = "WEBMESH_CNI_SERVICE_CIDR"
	// ClusterDomainEnvVar is the name of the environment variable that contains the cluster domain.
	ClusterDomainEnvVar = "WEBMESH_CNI_CLUSTER_DOMAIN"
	// DryRunEnvVar is the name of the environment variable that enables dry run mode.
	DryRunEnvVar = "WEBMESH_CNI_INSTALL_DRY_RUN"
	// NetConfTemplateEnvVar is the name of the environment variable that contains the CNI configuration.
	NetConfTemplateEnvVar = "WEBMESH_CNI_NETWORK_CONFIG"
	// DestConfFileNameEnvVar is the name of the file that contains the CNI configuration.
	DestConfFileNameEnvVar = "WEBMESH_CNI_CONF_NAME"
	// DestBinEnvVar is the destination directory for the CNI binaries.
	DestBinEnvVar = "WEBMESH_CNI_BIN_DIR"
	// DestConfEnvVar is the destination directory for the CNI configuration.
	DestConfEnvVar = "WEBMESH_CNI_CONF_DIR"
	// CNINetDirEnvVar is the directory containing host-local IPAM allocations. We release these
	// when we start for the first time.
	CNINetDirEnvVar = "WEBMESH_CNI_HOSTNET_DIR"
	// NodeNameEnvVar is the name of the environment variable that contains the node name.
	NodeNameEnvVar = "KUBERNETES_NODE_NAME"
	// PodNamespaceEnvVar is the name of the environment variable that contains the pod namespace.
	PodNamespaceEnvVar = "KUBERNETES_POD_NAMESPACE"
	// KubeconfigEnvVar is the name of the environment variable that contains the kubeconfig.
	KubeconfigEnvVar = "WEBMESH_CNI_KUBECONFIG"
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
	// DefaultDestConfFilename is the default name of the CNI configuration file.
	DefaultDestConfFilename = "10-webmesh.conflist"
	// DefaultNetConfPath is the default path to the CNI configuration file.
	DefaultNetConfPath = "/etc/cni/net.d/10-webmesh.conflist"
	// Default kubeconfig path if not provided.
	DefaultKubeconfigPath = "/etc/cni/net.d/webmesh-kubeconfig"
	// DefaultNamespace is the default namespace to use for the plugin.
	DefaultNamespace = "kube-system"
	// PluginKubeconfigName is the name of the kubeconfig file for the plugin.
	PluginKubeconfigName = "webmesh-kubeconfig"
	// PluginBinaryName is the name of the plugin binary.
	PluginBinaryName = "webmesh"
	// KubeconfigContextName is the name of the context in the kubeconfig.
	KubeconfigContextName = "webmesh-cni"
	// IfacePrefix is the prefix for interface names.
	IfacePrefix = "wmesh"
	// IPAMLockID is the ID used for the IPAM lock.
	IPAMLockID = "webmesh-cni-ipam"
)

var (
	// ErrPeerContainerNotFound is returned when a container is not found.
	ErrPeerContainerNotFound = fmt.Errorf("peer container not found")
)

// IsPeerContainerNotFound returns true if the given error is a peer container not found error.
func IsPeerContainerNotFound(err error) bool {
	return errors.Is(err, ErrPeerContainerNotFound)
}
