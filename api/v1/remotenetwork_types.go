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

// RemoteNetworkSpec defines the configuration for peering with another
// webmesh network.
type RemoteNetworkSpec struct {
	// Peers are the peers in the remote network.
	Peers []Peer `json:"peers,omitempty"`
	// Credentials are a reference to a secret containing credentials
	// for authenticating with the remote network. The objects in the
	// secret depend on the authentication method used.
	Credentials *corev1.ObjectReference `json:"credentials,omitempty"`
	// PreSharedKey is a pre-shared key for seeding address space allocation
	// in the bridge network.
	PreSharedKey string `json:"preSharedKey,omitempty"`
}

// Peer is a CNI node in the remote network.
type Peer struct {
	// PublicKey is the public key of the peer. This is only required
	// when not performing authentication.
	PublicKey string `json:"publicKey"`
	// Endpoints are the endpoints of the peer. When not performing
	// authentication, these are remote wireguard endpoints. When
	// performing authentication, these are remote gRPC endpoints.
	Endpoints []string `json:"endpoints"`
}
