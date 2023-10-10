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

package host

import (
	"errors"
	"os"
	"time"

	"github.com/spf13/pflag"
	"github.com/webmeshproj/webmesh/pkg/config"

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
	// Auth are configuration options for authenticating with other nodes.
	Auth config.AuthOptions `koanf:"auth,omitempty"`
	// WireGuard are configurations for the WireGuard interface.
	WireGuard config.WireGuardOptions `koanf:"wireguard,omitempty"`
	// Services is the service options for the host webmesh node.
	Services config.ServiceOptions `koanf:"services,omitempty"`
	// Plugins is the plugin options for the host webmesh node.
	Plugins config.PluginOptions `koanf:"plugins,omitempty"`
	// Network is the network options for the host webmesh node.
	Network NetworkConfig `koanf:"network,omitempty"`
	// LogLevel is the log level for the host webmesh node.
	LogLevel string `koanf:"log-level,omitempty"`
}

// NewDefaultConfig returns a new default configuration for the host webmesh node.
func NewDefaultConfig() Config {
	return Config{
		NodeID:             os.Getenv(types.NodeNameEnvVar),
		Namespace:          os.Getenv(types.PodNamespaceEnvVar),
		LockDuration:       time.Second * 10,
		LockAcquireTimeout: time.Second * 5,
		ConnectTimeout:     time.Second * 30,
		Auth:               config.NewAuthOptions(),
		WireGuard:          config.NewWireGuardOptions(),
		Services:           config.NewServiceOptions(true),
		Plugins:            config.NewPluginOptions(),
		Network:            NewNetworkConfig(),
		LogLevel:           "info",
	}
}

func (o *Config) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.NodeID, prefix+"node-id", o.NodeID, "The ID of the node")
	fs.StringVar(&o.Namespace, prefix+"namespace", o.Namespace, "The namespace of the node")
	fs.DurationVar(&o.LockDuration, prefix+"lock-duration", o.LockDuration, "The duration to hold locks for when allocating addresses")
	fs.DurationVar(&o.LockAcquireTimeout, prefix+"lock-acquire-timeout", o.LockAcquireTimeout, "The timeout for acquiring locks when allocating addresses")
	fs.DurationVar(&o.ConnectTimeout, prefix+"connect-timeout", o.ConnectTimeout, "The timeout for connecting the host webmesh node to the network")
	fs.StringVar(&o.LogLevel, prefix+"log-level", o.LogLevel, "The log level for the host webmesh node")
	o.Auth.BindFlags(prefix+"auth.", fs)
	o.WireGuard.BindFlags(prefix+"wireguard.", fs)
	o.Network.BindFlags(prefix+"network.", fs)
	o.Services.BindFlags(prefix+"services.", fs)
	o.Plugins.BindFlags(prefix+"plugins.", fs)
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
	if err := o.WireGuard.Validate(); err != nil {
		return err
	}
	return nil
}

// NetworkConfig contains the options for the network.
type NetworkConfig struct {
	// RemoteEndpointDetection enables remote endpoint detection for wireguard endpoints.
	RemoteEndpointDetection bool `koanf:"remote-endpoint-detection,omitempty"`
	// IPv4CIDR is the IPv4 CIDR to use for the network.
	IPv4CIDR string `koanf:"ipv4-cidr,omitempty"`
	// ClusterDomain is the cluster domain to use for the network.
	ClusterDomain string `koanf:"cluster-domain,omitempty"`
	// DisableIPv4 disables IPv4 on the host webmesh node.
	DisableIPv4 bool `koanf:"disable-ipv4,omitempty"`
	// DisableIPv6 disables IPv6 on the host webmesh node.
	DisableIPv6 bool `koanf:"disable-ipv6,omitempty"`
}

func NewNetworkConfig() NetworkConfig {
	return NetworkConfig{
		RemoteEndpointDetection: false,
		IPv4CIDR:                os.Getenv(types.PodCIDREnvVar),
		ClusterDomain:           os.Getenv(types.ClusterDomainEnvVar),
		DisableIPv4:             false,
		DisableIPv6:             false,
	}
}

func (n *NetworkConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.BoolVar(&n.RemoteEndpointDetection, prefix+"remote-endpoint-detection", n.RemoteEndpointDetection, "Enable remote endpoint detection for wireguard endpoints")
	fs.StringVar(&n.IPv4CIDR, prefix+"ipv4-cidr", n.IPv4CIDR, "The IPv4 CIDR to use for the network")
	fs.StringVar(&n.ClusterDomain, prefix+"cluster-domain", n.ClusterDomain, "The cluster domain to use for the network")
	fs.BoolVar(&n.DisableIPv4, prefix+"disable-ipv4", n.DisableIPv4, "Disable IPv4 on the host webmesh node")
	fs.BoolVar(&n.DisableIPv6, prefix+"disable-ipv6", n.DisableIPv6, "Disable IPv6 on the host webmesh node")
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
	return nil
}