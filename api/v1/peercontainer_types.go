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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// InterfaceStatus is the current status of a new peer interface.
type InterfaceStatus string

const (
	InterfaceStatusCreating InterfaceStatus = "Creating"
	InterfaceStatusCreated  InterfaceStatus = "Created"
	InterfaceStatusStarting InterfaceStatus = "Starting"
	InterfaceStatusFailed   InterfaceStatus = "Failed"
)

// PeerContainerSpec defines the desired state of PeerContainer
type PeerContainerSpec struct {
	// ContainerID is the ID of the container to peer with.
	ContainerID string `json:"containerID"`
	// Netns is the network namespace of the container to peer with.
	Netns string `json:"netns"`
	// IfName is the name of the interface to peer with.
	IfName string `json:"ifName"`
	// NodeName is the name of the node the container is running on.
	NodeName string `json:"nodeName"`
	// MTU is the MTU to set on the interface.
	MTU int `json:"mtu"`
	// LogLevel is the log level for the webmesh interface.
	LogLevel string `json:"logLevel"`
}

// PeerContainerStatus defines the observed state of PeerContainer
type PeerContainerStatus struct {
	// Status is the current status of the interface.
	Status InterfaceStatus `json:"status"`
	// IPv4Address is the IPv4 address of the interface.
	IPv4Address string `json:"ipv4Address"`
	// IPv6Address is the IPv6 address of the interface.
	IPv6Address string `json:"ipv6Address"`
	// MacAddress is the MAC address of the interface.
	MacAddress string `json:"macAddress"`
	// Error is any error that occurred while peering the interface.
	Error string `json:"error"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// PeerContainer is the Schema for the peercontainers API
type PeerContainer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PeerContainerSpec   `json:"spec,omitempty"`
	Status PeerContainerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// PeerContainerList contains a list of PeerContainer
type PeerContainerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PeerContainer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PeerContainer{}, &PeerContainerList{})
}
