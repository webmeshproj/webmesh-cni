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
	"fmt"
	"net"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// InterfaceStatus is the current status of a container interface.
type InterfaceStatus string

const (
	// InterfaceStatusCreated is the initial phase of a new peer interface.
	InterfaceStatusCreated InterfaceStatus = "Created"
	// InterfaceStatusStarting is the phase when the interface is starting.
	InterfaceStatusStarting InterfaceStatus = "Starting"
	// InterfaceStatusRunning is the phase when the interface is running.
	InterfaceStatusRunning InterfaceStatus = "Running"
	// InterfaceStatusFailed is the phase when the interface failed to start.
	InterfaceStatusFailed InterfaceStatus = "Failed"
)

const (
	// FieldOwner is the field owner for CNI objects.
	FieldOwner = "webmesh-cni"
	// PeerContainerFinalizer is the PeerContainer finalizer.
	PeerContainerFinalizer = "peercontainer.cniv1.webmesh.io"
	// PeerContainerPodNameLabel is the label for the pod name.
	PeerContainerPodNameLabel = "webmesh.io/pod-name"
	// PeerContainerPodNamespaceLabel is the label for the pod namespace.
	PeerContainerPodNamespaceLabel = "webmesh.io/pod-namespace"
)

// PeerContainerSpec defines the desired state of PeerContainer
type PeerContainerSpec struct {
	// NodeID is the ID to use for the container.
	NodeID string `json:"nodeID"`
	// ContainerID is the ID of the container being created.
	ContainerID string `json:"containerID"`
	// Netns is the network namespace of the container being created.
	Netns string `json:"netns"`
	// IfName is the name of the interface create.
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
	// InterfaceStatus is the current status of the interface.
	InterfaceStatus InterfaceStatus `json:"status"`
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

// IsEmpty returns true if the status is empty.
func (p PeerContainerStatus) IsEmpty() bool {
	return p.InterfaceStatus == "" && p.Error == "" && !p.HasNetworkInfo()
}

// HasNetworkInfo returns true if the status has network information.
func (p PeerContainerStatus) HasNetworkInfo() bool {
	return p.MACAddress != "" &&
		p.IPv4Address != "" &&
		p.IPv6Address != "" &&
		p.NetworkV4 != "" &&
		p.NetworkV6 != ""
}

// AppendToResults appends the network information to the results.
func (p PeerContainer) AppendToResults(result *cniv1.Result) error {
	if p.Status.IPv4Address != "" && !p.Spec.DisableIPv4 {
		ipv4net, err := netlink.ParseIPNet(p.Status.IPv4Address)
		if err != nil {
			return fmt.Errorf("failed to parse IPv4 address: %w", err)
		}
		result.IPs = append(result.IPs, &cniv1.IPConfig{
			Address: *ipv4net,
			Gateway: ipv4net.IP,
		})
		result.Routes = append(result.Routes, &cnitypes.Route{
			Dst: net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, 32),
			},
			GW: ipv4net.IP,
		})
		rtnet, err := netlink.ParseIPNet(p.Status.NetworkV4)
		if err != nil {
			return fmt.Errorf("failed to parse IPv4 network: %w", err)
		}
		result.Routes = append(result.Routes, &cnitypes.Route{
			Dst: *rtnet,
			GW:  ipv4net.IP,
		})
	}
	if p.Status.IPv6Address != "" && !p.Spec.DisableIPv6 {
		ipv6net, err := netlink.ParseIPNet(p.Status.IPv6Address)
		if err != nil {
			return fmt.Errorf("failed to parse IPv6 address: %w", err)
		}
		result.IPs = append(result.IPs, &cniv1.IPConfig{
			Address: *ipv6net,
			Gateway: ipv6net.IP,
		})
		result.Routes = append(result.Routes, &cnitypes.Route{
			Dst: net.IPNet{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, 128),
			},
			GW: ipv6net.IP,
		})
		rtnet, err := netlink.ParseIPNet(p.Status.NetworkV6)
		if err != nil {
			return fmt.Errorf("failed to parse IPv6 network: %w", err)
		}
		result.Routes = append(result.Routes, &cnitypes.Route{
			Dst: *rtnet,
			GW:  ipv6net.IP,
		})
	}
	return nil
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.status",description="Status of the interface"
//+kubebuilder:printcolumn:name="IPv4",type="string",JSONPath=".status.ipv4Address",description="IPv4 address of the interface"
//+kubebuilder:printcolumn:name="IPv6",type="string",JSONPath=".status.ipv6Address",description="IPv6 address of the interface"

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
