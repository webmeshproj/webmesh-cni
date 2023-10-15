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

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RemoteAuthMethod is a method for authenticating with a remote network.
type RemoteAuthMethod string

const (
	// RemoteAuthMethodNone is the no authentication method.
	RemoteAuthMethodNone RemoteAuthMethod = "none"
	// RemoteAuthMethodNative is the native gRPC authentication method.
	// This may or may not require TLS credentials depending on the remote
	// network configuration.
	RemoteAuthMethodNative RemoteAuthMethod = "native"
	// RemoteAuthMethodKubernetes is the Kubernetes authentication method.
	// This requires a kubeconfig for the remote network where this node
	// will write its network configuration directly to the cluster.
	RemoteAuthMethodKubernetes RemoteAuthMethod = "kubernetes"
)

const (
	// RemoteNetworkFinalizer is the RemoteNetwork finalizer.
	RemoteNetworkFinalizer = "remotenetwork.cniv1.webmesh.io"
	// KubeconfigKey is the key in the secret containing the kubeconfig
	// for the remote network.
	KubeconfigKey = "kubeconfig"
	// TLSCertificateKey is the key in the secret containing the TLS certificate
	// for the remote network.
	TLSCertificateKey = "tls.crt"
	// TLSPrivateKeyKey is the key in the secret containing the TLS private key
	// for the remote network.
	TLSPrivateKeyKey = "tls.key"
	// TLSCACertificateKey is the key in the secret containing the TLS CA certificate
	// for the remote network.
	TLSCACertificateKey = "ca.crt"
	// PreSharedKeyKey is the key in the secret containing the pre-shared-key
	// for the remote network.
	PreSharedKeyKey = "pre-shared-key"
)

// BridgeStatus is the current status of a bridge interface.
type BridgeStatus string

const (
	// InterfaceStatusCreated is the initial phase of a new peer interface.
	BridgeStatusCreated BridgeStatus = "Created"
	// InterfaceStatusStarting is the phase when the interface is starting.
	BridgeStatusStarting BridgeStatus = "Starting"
	// InterfaceStatusRunning is the phase when the interface is running.
	BridgeStatusRunning BridgeStatus = "Running"
	// InterfaceStatusFailed is the phase when the interface failed to start.
	BridgeStatusFailed BridgeStatus = "Failed"
)

// RemoteNetworkTypeMeta is the type meta for the RemoteNetwork.
var RemoteNetworkTypeMeta = metav1.TypeMeta{
	APIVersion: GroupVersion.String(),
	Kind:       "RemoteNetwork",
}

// RemoteNetworkSpec defines the configuration for peering with another
// webmesh network.
type RemoteNetworkSpec struct {
	// AuthMethod is the authentication method to use for peering with
	// the remote network.
	// +kubebuilder:validation:Enum=none;native;kubernetes
	// +kubebuilder:default=native
	AuthMethod RemoteAuthMethod `json:"authMethod"`
	// RemoteNamespace is the remote namespace to use for peer storage
	// when using the kubernetes authentication method. Defaults to the
	// storage namespace configured on the host.
	RemoteNamespace string `json:"remoteNamespace,omitempty"`
	// Network is the network configuration for the bridge connection.
	Network NetworkConfig `json:"network,omitempty"`
	// Peers are one or more peers in the remote network. These are optional
	// when using kubernetes authentication. Endpoints must be supplied for
	// one or more peers in the list if not using peer-discovery.
	Peers []Peer `json:"peers,omitempty"`
	// Credentials are a reference to a secret containing credentials for the remote
	// network. It may contain a kubeconfig for kubernetes authentication or TLS
	// credentials for mTLS authentication. If native authentication is set and no
	// kubeconfig or TLS credentials are present, ID authentication will be used.
	Credentials *corev1.ObjectReference `json:"credentials,omitempty"`
	// CheckInterval is the interval to check on the remote network status when
	// using native or no authentication. Defaults to 1 minute. Kubernetes authentiation
	// relies on storage subscription events and does not require a check interval.
	CheckInterval *metav1.Duration `json:"checkInterval,omitempty"`
}

// NetworkConfig is configuration options for the bridge connection.
type NetworkConfig struct {
	// WireGuardPort is the port to use for WireGuard. One will be
	// allocated automatically if not provided.
	WireGuardPort int `json:"wireguardPort,omitempty"`
	// InterfaceName is the name to give the interface. It will be
	// automatically chosen from the name of the remote network if
	// not provided.
	InterfaceName string `json:"interfaceName,omitempty"`
	// MTU is the MTU to use for the interface. It will be automatically
	// chosen if not provided.
	MTU int `json:"mtu,omitempty"`
	// DisableIPv4 disables IPv4 forwarding on the interface.
	DisableIPv4 bool `json:"disableIPv4,omitempty"`
	// DisableIPv6 disables IPv6 forwarding on the interface.
	DisableIPv6 bool `json:"disableIPv6,omitempty"`
}

// Peer is a CNI node in the remote network.
type Peer struct {
	// ID is the ID of the peer. If provided, the native authentication
	// will attempt ID based authentication. If not provided, an ID will
	// be extracted from the public key and used for authentication.
	ID string `json:"id,omitempty"`
	// PublicKey is the public key of the peer. This must be provided if no
	// ID is provided.
	PublicKey string `json:"publicKey,omitempty"`
	// Endpoints are the endpoints of the peer. When not performing
	// authentication and not using peer-discovery, these are remote
	// wireguard endpoints. When performing authentication without
	// peer-discovery, these are remote gRPC endpoints.
	Endpoints []string `json:"endpoints,omitempty"`
	// Rendezvous is a rendezvous point for the peer. This is used for
	// peer discovery.
	Rendezvous string `json:"rendezvous,omitempty"`
}

// RemoteNetworkStatus will contain the status of the peering with
// the remote network.
type RemoteNetworkStatus struct {
	// BridgeStatus is the status of the bridge interface.
	BridgeStatus BridgeStatus `json:"bridgeStatus,omitempty"`
	// InterfaceName is the name of the interface.
	InterfaceName string `json:"interfaceName"`
	// MACAddress is the MAC address of the interface.
	MACAddress string `json:"macAddress"`
	// IPv4Address is the IPv4 address of the interface.
	IPv4Address string `json:"ipv4Address"`
	// IPv6Address is the IPv6 address of the interface.
	IPv6Address string `json:"ipv6Address"`
	// NetworkV4 is the IPv4 network of the interface.
	NetworkV4 string `json:"networkV4"`
	// NetworkV6 is the IPv6 network of the interface.
	NetworkV6 string `json:"networkV6"`
	// Peers are the peers in the remote network.
	Peers []Peer `json:"peers,omitempty"`
	// Error is the last error encountered when peering with the remote network.
	Error string `json:"error,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Status",type=boolean,JSONPath=`.status.bridgeStatus`,description="The status of the remote bridge interface"

// RemoteNetwork is the Schema for the remotenetworks API
type RemoteNetwork struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RemoteNetworkSpec   `json:"spec,omitempty"`
	Status RemoteNetworkStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// RemoteNetworkList contains a list of RemoteNetworks.
type RemoteNetworkList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RemoteNetwork `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RemoteNetwork{}, &RemoteNetworkList{})
}
