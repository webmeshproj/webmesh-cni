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

// InterfacePhase is the current status of a new peer interface.
type InterfacePhase string

const (
	// InterfacePhaseCreated is the initial phase of a new peer interface.
	InterfacePhaseCreated InterfacePhase = "Created"
	// InterfacePhaseStarting is the phase when the interface is starting.
	InterfacePhaseStarting InterfacePhase = "Starting"
	// InterfacePhaseRunning is the phase when the interface is running.
	InterfacePhaseRunning InterfacePhase = "Running"
	// InterfacePhaseFailed is the phase when the interface failed to start.
	InterfacePhaseFailed InterfacePhase = "Failed"
)

const (
	// FieldOwner is the field owner for CNI objects.
	FieldOwner = "webmesh-cni"
	// PeerContainerFinalizer is the PeerContainer finalizer.
	PeerContainerFinalizer = "peercontainer.cniv1.webmesh.io"
)

// PeerContainerSpec defines the desired state of PeerContainer
type PeerContainerSpec struct {
	// NodeID is the ID to use for the container.
	NodeID string `json:"containerID"`
	// Netns is the network namespace of the container to peer with.
	Netns string `json:"netns"`
	// IfName is the name of the interface to peer with.
	IfName string `json:"ifName"`
	// NodeName is the name of the node the container is running on.
	NodeName string `json:"nodeName"`
	// MTU is the MTU to set on the interface.
	MTU int `json:"mtu"`
	// DisableIPv4 is whether to disable IPv4 on the interface.
	DisableIPv4 bool `json:"disableIPv4"`
	// DisableIPv6 is whether to disable IPv6 on the interface.
	DisableIPv6 bool `json:"disableIPv6"`
	// LogLevel is the log level for the webmesh interface.
	LogLevel string `json:"logLevel"`
}

// PeerContainerStatus defines the observed state of PeerContainer
type PeerContainerStatus struct {
	// Phase is the current status of the interface.
	Phase InterfacePhase `json:"status"`
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
