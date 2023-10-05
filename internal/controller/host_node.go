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

package controller

import (
	"context"
	"fmt"

	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	v1 "github.com/webmeshproj/api/v1"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnet/endpoints"
	meshtransport "github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	netutil "github.com/webmeshproj/webmesh/pkg/meshnet/util"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
	meshnode "github.com/webmeshproj/webmesh/pkg/meshnode"
	meshplugins "github.com/webmeshproj/webmesh/pkg/plugins"
	meshstorage "github.com/webmeshproj/webmesh/pkg/storage"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cnitypes "github.com/webmeshproj/webmesh-cni/internal/types"
)

// SetNetworkState sets the network configuration to the reconciler to make it ready to reconcile requests.
func (r *PeerContainerReconciler) StartHostNode(ctx context.Context, results meshstorage.BootstrapResults) error {
	log := log.FromContext(ctx)
	log.Info("Setting up host node")
	if r.WireGuardPort == 0 {
		r.WireGuardPort = wireguard.DefaultListenPort
	}
	r.meshDomain = results.MeshDomain
	r.networkV4 = results.NetworkV4
	r.networkV6 = results.NetworkV6
	r.nodes = make(map[types.NamespacedName]meshnode.Node)
	r.ipam = meshplugins.NewBuiltinIPAM(meshplugins.IPAMConfig{Storage: r.Provider.MeshDB()})
	// Detect the current endpoints on the machine.
	log.V(1).Info("Detecting host endpoints")
	eps, err := endpoints.Detect(ctx, endpoints.DetectOpts{
		DetectPrivate:        true, // Required for finding endpoints for other containers on the local node.
		DetectIPv6:           true, // Make configurable?
		AllowRemoteDetection: r.RemoteEndpointDetection,
		SkipInterfaces:       []string{}, // Make configurable?
	})
	if err != nil {
		// Try again on the next reconcile.
		return fmt.Errorf("failed to detect endpoints: %w", err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	encoded, err := key.PublicKey().Encode()
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}
	var ipv4Addr, ipv6Addr string
	// If the container does not have an IPv4 address and we are not disabling
	// IPv4, use the default plugin to allocate one.
	log.Info("Allocating a mesh IPv4 address")
	alloc, err := r.ipam.Allocate(ctx, &v1.AllocateIPRequest{
		NodeID: r.NodeName,
		Subnet: r.networkV4.String(),
	})
	if err != nil {
		return fmt.Errorf("failed to allocate IPv4 address: %w", err)
	}
	ipv4Addr = alloc.GetIp()
	log.Info("Allocating a mesh IPv6 address")
	ipv6Addr = netutil.AssignToPrefix(r.networkV6, key.PublicKey()).String()
	log.Info("Joining the mesh")
	hostNode := NewNode(logging.NewLogger(r.HostNodeLogLevel, "json"), meshnode.Config{
		Key:             key,
		NodeID:          r.NodeName,
		ZoneAwarenessID: r.NodeName,
		DisableIPv4:     r.DisableIPv4,
		DisableIPv6:     r.DisableIPv6,
	})
	connectCtx, cancel := context.WithTimeout(ctx, r.ConnectTimeout)
	defer cancel()
	err = hostNode.Connect(connectCtx, meshnode.ConnectOptions{
		StorageProvider: &NoOpStorageCloser{r.Provider},
		MaxJoinRetries:  10,
		JoinRoundTripper: meshtransport.JoinRoundTripperFunc(func(ctx context.Context, req *v1.JoinRequest) (*v1.JoinResponse, error) {
			// TODO: Check for pre-existing peers and return them.
			return &v1.JoinResponse{
				AddressIPv4: ipv4Addr,
				AddressIPv6: ipv6Addr,
				NetworkIPv4: r.networkV4.String(),
				NetworkIPv6: r.networkV6.String(),
				MeshDomain:  r.meshDomain,
			}, nil
		}),
		LeaveRoundTripper: meshtransport.LeaveRoundTripperFunc(func(ctx context.Context, req *v1.LeaveRequest) (*v1.LeaveResponse, error) {
			// TODO: Actually leave the cluster.
			return &v1.LeaveResponse{}, nil
		}),
		NetworkOptions: meshnet.Options{
			ListenPort:      r.WireGuardPort,
			InterfaceName:   cnitypes.IfNameFromID(r.NodeName),
			ForceReplace:    true,
			MTU:             r.MTU,
			ZoneAwarenessID: r.NodeName,
			DisableIPv4:     r.DisableIPv4,
			DisableIPv6:     r.DisableIPv6,
			// Maybe by configuration?
			RecordMetrics:         false,
			RecordMetricsInterval: 0,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to connect to mesh: %w", err)
	}
	select {
	case <-connectCtx.Done():
		return ctx.Err()
	case <-hostNode.Ready():
	}
	// Register ourselves with the mesh.
	log.Info("Host node is ready, registering with mesh")
	wireguardPort, err := hostNode.Network().WireGuard().ListenPort()
	if err != nil {
		defer hostNode.Close(ctx)
		return fmt.Errorf("failed to get wireguard listen port: %w", err)
	}
	var wgeps []string
	for _, ep := range eps.AddrPorts(uint16(wireguardPort)) {
		wgeps = append(wgeps, ep.String())
	}
	peer := meshtypes.MeshNode{
		MeshNode: &v1.MeshNode{
			Id:                 r.NodeName,
			PublicKey:          encoded,
			PrimaryEndpoint:    eps.FirstPublicAddr().String(),
			WireguardEndpoints: wgeps,
			ZoneAwarenessID:    r.NodeName,
			PrivateIPv4:        ipv4Addr,
			PrivateIPv6:        ipv6Addr,
		},
	}
	err = r.Provider.MeshDB().Peers().Put(ctx, peer)
	if err != nil {
		defer hostNode.Close(ctx)
		return fmt.Errorf("failed to register with mesh: %w", err)
	}
	// Put a default gateway route for ourselves.
	err = r.Provider.MeshDB().Networking().PutRoute(ctx, meshtypes.Route{
		Route: &v1.Route{
			Name: fmt.Sprintf("%s-default-gw", r.NodeName),
			Node: r.NodeName,
			// This should be more configurable.
			DestinationCIDRs: func() []string {
				out := []string{"0.0.0.0/0", "::/0"}
				for _, ep := range eps {
					out = append(out, ep.String())
				}
				return out
			}(),
		},
	})
	if err != nil {
		defer hostNode.Close(ctx)
		return fmt.Errorf("failed to register default gateway route: %w", err)
	}
	ifName := hostNode.Network().WireGuard().Name()
	_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/forwarding", ifName), "1")
	_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv4/conf/%s/forwarding", ifName), "1")
	err = hostNode.Network().Firewall().AddMasquerade(ctx, ifName)
	if err != nil {
		defer hostNode.Close(ctx)
		return fmt.Errorf("failed to add masquerade rule: %w", err)
	}
	r.host = hostNode
	r.ready.Store(true)
	return nil
}
