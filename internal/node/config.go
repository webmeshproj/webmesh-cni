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

package node

import (
	"errors"
	"os"
	"time"

	"github.com/spf13/pflag"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"

	"github.com/webmeshproj/webmesh-cni/internal/types"
)

// Config contains the options for the host node.
type Config struct {
	// NodeID is the ID of the node.
	NodeID string `koanf:"node-id"`
	// Namespace is the namespace of the node.
	Namespace string `koanf:"namespace,omitempty"`
	// LockDuration is the duration to hold locks for when allocating addresses.
	LockDuration time.Duration `koanf:"lock-duration,omitempty"`
	// LockAcquireTimeout is the timeout for acquiring locks when allocating addresses.
	LockAcquireTimeout time.Duration `koanf:"lock-acquire-timeout,omitempty"`
	// ConnectTimeout is the timeout for connecting the host webmesh node to the network.
	ConnectTimeout time.Duration `koanf:"connect-timeout,omitempty"`
	// Network is the network options for the host webmesh node.
	Network NetworkConfig `koanf:"network,omitempty"`
	// Services is the service options for the host webmesh node.
	Services ServiceConfig `koanf:"services,omitempty"`
	// LogLevel is the log level for the host webmesh node.
	LogLevel string `koanf:"log-level,omitempty"`
}

func (o *Config) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.NodeID, prefix+"node-id", os.Getenv(types.NodeNameEnvVar), "The ID of the node")
	fs.StringVar(&o.Namespace, prefix+"namespace", os.Getenv(types.PodNamespaceEnvVar), "The namespace of the node")
	fs.DurationVar(&o.LockDuration, prefix+"lock-duration", 10*time.Second, "The duration to hold locks for when allocating addresses")
	fs.DurationVar(&o.LockAcquireTimeout, prefix+"lock-acquire-timeout", 5*time.Second, "The timeout for acquiring locks when allocating addresses")
	fs.DurationVar(&o.ConnectTimeout, prefix+"connect-timeout", 30*time.Second, "The timeout for connecting the host webmesh node to the network")
	fs.StringVar(&o.LogLevel, prefix+"log-level", "info", "The log level for the host webmesh node")
	o.Network.BindFlags(prefix+"network.", fs)
	o.Services.BindFlags(prefix+"services.", fs)
}

func (o *Config) Validate() error {
	if o.NodeID == "" {
		return errors.New("node-id must be set")
	}
	if o.Namespace == "" {
		return errors.New("namespace must be set")
	}
	if o.ConnectTimeout <= 0 {
		return errors.New("connect-timeout must be positive")
	}
	if o.LockDuration <= 0 {
		return errors.New("lock-duration must be positive")
	}
	if o.LockAcquireTimeout <= 0 {
		return errors.New("lock-acquire-timeout must be positive")
	}
	if err := o.Network.Validate(); err != nil {
		return err
	}
	if err := o.Services.Validate(); err != nil {
		return err
	}
	return nil
}

// NetworkConfig contains the options for the network.
type NetworkConfig struct {
	// RemoteEndpointDetection enables remote endpoint detection for wireguard endpoints.
	RemoteEndpointDetection bool `koanf:"remote-endpoint-detection,omitempty"`
	// MTU is the MTU of the host wireguard interface.
	MTU int `koanf:"mtu,omitempty"`
	// WireGuardPort is the port to use for the host wireguard interface.
	WireGuardPort int `koanf:"wireguard-port,omitempty"`
	// IPv4CIDR is the IPv4 CIDR to use for the network.
	IPv4CIDR string `koanf:"ipv4-cidr,omitempty"`
	// ClusterDomain is the cluster domain to use for the network.
	ClusterDomain string `koanf:"cluster-domain,omitempty"`
	// DisableIPv4 disables IPv4 on the host webmesh node.
	DisableIPv4 bool `koanf:"disable-ipv4,omitempty"`
	// DisableIPv6 disables IPv6 on the host webmesh node.
	DisableIPv6 bool `koanf:"disable-ipv6,omitempty"`
}

func (n *NetworkConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.BoolVar(&n.RemoteEndpointDetection, prefix+"remote-endpoint-detection", false, "Enable remote endpoint detection for wireguard endpoints")
	fs.IntVar(&n.MTU, prefix+"mtu", system.DefaultMTU, "The MTU of the host wireguard interface")
	fs.IntVar(&n.WireGuardPort, prefix+"wireguard-port", wireguard.DefaultListenPort, "The port to use for the host wireguard interface")
	fs.StringVar(&n.IPv4CIDR, prefix+"ipv4-cidr", os.Getenv(types.PodCIDREnvVar), "The IPv4 CIDR to use for the network")
	fs.StringVar(&n.ClusterDomain, prefix+"cluster-domain", os.Getenv(types.ClusterDomainEnvVar), "The cluster domain to use for the network")
	fs.BoolVar(&n.DisableIPv4, prefix+"disable-ipv4", false, "Disable IPv4 on the host webmesh node")
	fs.BoolVar(&n.DisableIPv6, prefix+"disable-ipv6", false, "Disable IPv6 on the host webmesh node")
}

func (n *NetworkConfig) Validate() error {
	if n.IPv4CIDR == "" {
		return errors.New("ipv4-cidr must be set")
	}
	if n.ClusterDomain == "" {
		return errors.New("cluster-domain must be set")
	}
	if n.DisableIPv4 && n.DisableIPv6 {
		return errors.New("cannot disable both IPv4 and IPv6")
	}
	if n.WireGuardPort < 0 || n.WireGuardPort > 65535 {
		return errors.New("wireguard-port must be between 0 and 65535")
	}
	if n.MTU < 0 || n.MTU > 65535 {
		return errors.New("mtu must be between 0 and 65535")
	}
	return nil
}

// ServiceConfig contains the options for exposing mesh services on the CNI node.
type ServiceConfig struct {
	// Enabled enables the host webmesh node to expose mesh services.
	Enabled bool `koanf:"enabled,omitempty"`
	// ListenPort is the port to use for the host webmesh node.
	ListenPort int `koanf:"listen-port,omitempty"`
}

func (s *ServiceConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.BoolVar(&s.Enabled, prefix+"enabled", false, "Enable the host webmesh node to expose mesh services")
	fs.IntVar(&s.ListenPort, prefix+"listen-port", 8443, "The port to use for the host webmesh node API")
}

func (s *ServiceConfig) Validate() error {
	if !s.Enabled {
		return nil
	}
	if s.ListenPort < 0 || s.ListenPort > 65535 {
		return errors.New("listen-port must be between 0 and 65535")
	}
	return nil
}
