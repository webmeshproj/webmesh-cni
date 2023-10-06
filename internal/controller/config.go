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
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/spf13/pflag"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"

	"github.com/webmeshproj/webmesh-cni/internal/types"
)

// Config is the configuration for the the webmesh-cni controllers.
type Config struct {
	// Manager is the configuration for the controller manager.
	Manager ManagerConfig `koanf:"manager"`
	// Storage is the configuration for the storage provider.
	Storage StorageConfig `koanf:"storage"`
	// HostNode is the configuration for the host webmesh node.
	HostNode HostNodeConfig `koanf:"host-node"`
	// Network is the configuration for the network.
	Network NetworkConfig `koanf:"network"`
}

// ManagerConfig is the configuration for the controller manager.
type ManagerConfig struct {
	// NodeName is the name of this node.
	NodeName string `koanf:"node-name"`
	// Namespace is where we expect to share resources with other controllers.
	Namespace string `koanf:"namespace"`
	// MetricsAddress is the address to bind the metrics server to.
	MetricsAddress string `koanf:"metrics-address"`
	// ProbeAddress is the address to bind the health probe server to.
	ProbeAddress string `koanf:"probe-address"`
	// ReconcileTimeout is the timeout for reconciling a container's interface.
	ReconcileTimeout time.Duration `koanf:"reconcile-timeout"`
	// IPAMLockDuration is the duration of the IPAM lock.
	IPAMLockDuration time.Duration `koanf:"ipam-lock-duration"`
	// IPAMLockTimeout is the timeout for attempting to acquire an IPAM lock.
	// This must be less than the reconcile timeout.
	IPAMLockTimeout time.Duration `koanf:"ipam-lock-timeout"`
	// ShutdownTimeout is the timeout for shutting down the node.
	ShutdownTimeout time.Duration `koanf:"shutdown-timeout"`
}

// StorageConfig is the configuration for the storage provider.
type StorageConfig struct {
	// LeaderElectionLeaseDuration is the duration that non-leader candidates
	// will wait to force acquire leadership.
	LeaderElectLeaseDuration time.Duration `koanf:"leader-elect-lease-duration"`
	// LeaderElectRenewDeadline is the duration that the acting master will retry
	// refreshing leadership before giving up.
	LeaderElectRenewDeadline time.Duration `koanf:"leader-elect-renew-deadline"`
	// LeaderElectRetryPeriod is the duration the LeaderElector clients should wait
	// between tries of actions.
	LeaderElectRetryPeriod time.Duration `koanf:"leader-elect-retry-period"`
	// CacheSyncTimeout is the amount of time to wait for the client cache to sync
	// before starting the controller.
	CacheSyncTimeout time.Duration `koanf:"cache-sync-timeout"`
}

// HostNode is the configuration for the host webmesh node.
type HostNodeConfig struct {
	// GRPCListenPort is the port to use for the host webmesh node.
	GRPCListenPort int `koanf:"grpc-listen-port,omitempty"`
	// RemoteEndpointDetection enables remote endpoint detection for wireguard endpoints.
	RemoteEndpointDetection bool `koanf:"remote-endpoint-detection,omitempty"`
	// MTU is the MTU of the host wireguard interface.
	MTU int `koanf:"mtu,omitempty"`
	// WireGuardPort is the port to use for the host wireguard interface.
	WireGuardPort int `koanf:"wireguard-port,omitempty"`
	// ConnectTimeout is the timeout for connecting the host webmesh node to the network.
	ConnectTimeout time.Duration `koanf:"connect-timeout,omitempty"`
	// DisableIPv4 disables IPv4 on the host webmesh node.
	DisableIPv4 bool `koanf:"disable-ipv4,omitempty"`
	// DisableIPv6 disables IPv6 on the host webmesh node.
	DisableIPv6 bool `koanf:"disable-ipv6,omitempty"`
	// LogLevel is the log level for the host webmesh node.
	LogLevel string `koanf:"log-level,omitempty"`
}

// NetworkConfig is the configuration for the network.
type NetworkConfig struct {
	// PodCIDR is the CIDR for the pod network.
	PodCIDR string `koanf:"pod-cidr"`
	// ClusterDomain is the domain for the cluster.
	ClusterDomain string `koanf:"cluster-domain"`
}

func (c *Config) BindFlags(fs *pflag.FlagSet) {
	c.Manager.BindFlags("manager.", fs)
	c.Storage.BindFlags("storage.", fs)
	c.HostNode.BindFlags("host-node.", fs)
	c.Network.BindFlags("network.", fs)
}

func (c *ManagerConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&c.NodeName, prefix+"node-name", os.Getenv(types.NodeNameEnvVar), "The name of this node.")
	fs.StringVar(&c.Namespace, prefix+"namespace", os.Getenv(types.PodNamespaceEnvVar), "The namespace to use for shared resources.")
	fs.DurationVar(&c.ReconcileTimeout, prefix+"reconcile-timeout", 15*time.Second, "The timeout for reconciling a container's interface.")
	fs.DurationVar(&c.IPAMLockDuration, prefix+"ipam-lock-duration", 10*time.Second, "The duration of the IPAM lock.")
	fs.DurationVar(&c.IPAMLockTimeout, prefix+"ipam-lock-timeout", 5*time.Second, "The timeout for attempting to acquire an IPAM lock.")
	fs.StringVar(&c.MetricsAddress, prefix+"metrics-address", ":8080", "The address the metric endpoint binds to.")
	fs.StringVar(&c.ProbeAddress, prefix+"probe-address", ":8081", "The address the probe endpoint binds to.")
	fs.DurationVar(&c.ShutdownTimeout, prefix+"shutdown-timeout", 10*time.Second, "The timeout for shutting down the node.")
}

func (c *HostNodeConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.IntVar(&c.GRPCListenPort, prefix+"grpc-listen-port", 8443, "The port to use for the host webmesh node.")
	fs.BoolVar(&c.RemoteEndpointDetection, prefix+"remote-endpoint-detection", false, "Enable remote endpoint detection for wireguard endpoints.")
	fs.IntVar(&c.MTU, prefix+"mtu", system.DefaultMTU, "The MTU of the host wireguard interface.")
	fs.IntVar(&c.WireGuardPort, prefix+"wireguard-port", wireguard.DefaultListenPort, "The port to use for the host wireguard interface.")
	fs.DurationVar(&c.ConnectTimeout, prefix+"connect-timeout", 10*time.Second, "The timeout for connecting the host webmesh node to the network.")
	fs.BoolVar(&c.DisableIPv4, prefix+"disable-ipv4", false, "Disable IPv4 on the host webmesh node.")
	fs.BoolVar(&c.DisableIPv6, prefix+"disable-ipv6", false, "Disable IPv6 on the host webmesh node.")
	fs.StringVar(&c.LogLevel, prefix+"log-level", "info", "The log level for the host webmesh node.")
}

func (c *StorageConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.DurationVar(&c.LeaderElectLeaseDuration, prefix+"leader-elect-lease-duration", 15*time.Second, "The duration that non-leader candidates will wait to force acquire leadership.")
	fs.DurationVar(&c.LeaderElectRenewDeadline, prefix+"leader-elect-renew-deadline", 10*time.Second, "The duration that the acting master will retry refreshing leadership before giving up.")
	fs.DurationVar(&c.LeaderElectRetryPeriod, prefix+"leader-elect-retry-period", 2*time.Second, "The duration the LeaderElector clients should wait between tries of actions.")
	fs.DurationVar(&c.CacheSyncTimeout, prefix+"cache-sync-timeout", 10*time.Second, "The amount of time to wait for the client cache to sync before starting the controller.")
}

func (c *NetworkConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&c.PodCIDR, prefix+"pod-cidr", os.Getenv(types.PodCIDREnvVar), "The CIDR for the pod network.")
	fs.StringVar(&c.ClusterDomain, prefix+"cluster-domain", os.Getenv(types.ClusterDomainEnvVar), "The domain for the cluster.")
}

func (c *Config) Validate() error {
	if c.Manager.Namespace == "" {
		var err error
		c.Manager.Namespace, err = types.GetInClusterNamespace()
		if err != nil {
			return fmt.Errorf("namespace not set and unable to get in-cluster namespace: %w", err)
		}
	}
	if c.Manager.NodeName == "" {
		return fmt.Errorf("node name not set")
	}
	if c.Manager.IPAMLockTimeout >= c.Manager.ReconcileTimeout {
		return fmt.Errorf("ipam lock timeout must be less than reconcile timeout")
	}
	if c.Network.ClusterDomain == "" {
		c.Network.ClusterDomain = "cluster.local"
	}
	if c.Network.PodCIDR == "" {
		return fmt.Errorf("pod cidr not set")
	}
	_, err := netip.ParsePrefix(c.Network.PodCIDR)
	if err != nil {
		return fmt.Errorf("invalid pod cidr: %w", err)
	}
	return nil
}
