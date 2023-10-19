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

package config

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh-cni/internal/host"
	"github.com/webmeshproj/webmesh-cni/internal/metadata"
)

// Config is the configuration for the the webmesh-cni controllers.
type Config struct {
	// Manager is the configuration for the controller manager.
	Manager ManagerConfig `koanf:"manager"`
	// Storage is the configuration for the storage provider.
	Storage StorageConfig `koanf:"storage"`
	// Host is the configuration for the host webmesh node.
	Host host.Config `koanf:"host"`
}

// ManagerConfig is the configuration for the controller manager.
type ManagerConfig struct {
	// RemoteEndpointDetection enables remote endpoint detection for peer containers.
	RemoteEndpointDetection bool `koanf:"remote-endpoint-detection"`
	// MetricsAddress is the address to bind the metrics server to.
	MetricsAddress string `koanf:"metrics-address"`
	// ProbeAddress is the address to bind the health probe server to.
	ProbeAddress string `koanf:"probe-address"`
	// ReconcileTimeout is the timeout for reconciling a container's interface.
	ReconcileTimeout time.Duration `koanf:"reconcile-timeout"`
	// MaxConcurrentReconciles is the maximum number of concurrent reconciles.
	// Most of the reconcilers take exclusive locks, so this will only apply
	// to reconcilers as a whole.
	MaxConcurrentReconciles int `koanf:"max-concurrent-reconciles"`
	// ShutdownTimeout is the timeout for shutting down the node.
	ShutdownTimeout time.Duration `koanf:"shutdown-timeout"`
	// ClusterDNSSelector is the selector used for trying to find pods that provide DNS
	// for the cluster.
	ClusterDNSSelector map[string]string `koanf:"cluster-dns-selector,omitempty"`
	// ClusterDNSNamespace is the namespace to search for cluster DNS pods.
	ClusterDNSNamespace string `koanf:"cluster-dns-namespace,omitempty"`
	// ClusterDNSPortSelector is the name of the port assumed to be the DNS port.
	ClusterDNSPortSelector string `koanf:"cluster-dns-port-selector,omitempty"`
	// EnableMetadataServer enables a metadata server on the node that containers
	// can use to query information about themselves.
	EnableMetadataServer bool `koanf:"enable-metadata-server"`
	// MetadataAddress is the address to bind the metadata server to.
	MetadataAddress string `koanf:"metadata-address"`
	// EnableMetadataIDTokens enables ID token endpoints on the metadata server
	// for helping facilitate authentication between containers.
	EnableMetadataIDTokens bool `koanf:"enable-metadata-id-tokens"`
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

// NewDefaultConfig returns a new default configuration for the webmesh-cni controllers.
func NewDefaultConfig() Config {
	return Config{
		Manager: ManagerConfig{
			RemoteEndpointDetection: false,
			MetricsAddress:          ":8080",
			ProbeAddress:            ":8081",
			ReconcileTimeout:        15 * time.Second,
			ShutdownTimeout:         30 * time.Second,
			MaxConcurrentReconciles: 1,
			ClusterDNSSelector: map[string]string{
				"k8s-app": "kube-dns",
			},
			ClusterDNSNamespace:    "kube-system",
			ClusterDNSPortSelector: "dns",
			EnableMetadataServer:   true,
			MetadataAddress:        metadata.DefaultServerAddress.String(),
			EnableMetadataIDTokens: false,
		},
		Storage: StorageConfig{
			LeaderElectLeaseDuration: 15 * time.Second,
			LeaderElectRenewDeadline: 10 * time.Second,
			LeaderElectRetryPeriod:   2 * time.Second,
			CacheSyncTimeout:         10 * time.Second,
		},
		Host: host.NewDefaultConfig(),
	}
}

func (c *Config) BindFlags(fs *pflag.FlagSet) {
	c.Manager.BindFlags("manager.", fs)
	c.Storage.BindFlags("storage.", fs)
	c.Host.BindFlags("host.", fs)
}

func (c *ManagerConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.BoolVar(&c.RemoteEndpointDetection, prefix+"remote-endpoint-detection", c.RemoteEndpointDetection, "Enable remote endpoint detection for peer containers.")
	fs.DurationVar(&c.ReconcileTimeout, prefix+"reconcile-timeout", c.ReconcileTimeout, "The timeout for reconciling a container's interface.")
	fs.StringVar(&c.MetricsAddress, prefix+"metrics-address", c.MetricsAddress, "The address the metric endpoint binds to.")
	fs.StringVar(&c.ProbeAddress, prefix+"probe-address", c.ProbeAddress, "The address the probe endpoint binds to.")
	fs.DurationVar(&c.ShutdownTimeout, prefix+"shutdown-timeout", c.ShutdownTimeout, "The timeout for shutting down the node.")
	fs.IntVar(&c.MaxConcurrentReconciles, prefix+"max-concurrent-reconciles", c.MaxConcurrentReconciles, "The maximum number of concurrent reconciles.")
	fs.StringToStringVar(&c.ClusterDNSSelector, prefix+"cluster-dns-selector", c.ClusterDNSSelector, "The selector used for trying to find pods that provide DNS for the cluster")
	fs.StringVar(&c.ClusterDNSNamespace, prefix+"cluster-dns-namespace", c.ClusterDNSNamespace, "The namespace to search for cluster DNS pods")
	fs.StringVar(&c.ClusterDNSPortSelector, prefix+"cluster-dns-port-selector", c.ClusterDNSPortSelector, "The name of the port assumed to be the DNS port")
	fs.BoolVar(&c.EnableMetadataServer, prefix+"enable-metadata-server", c.EnableMetadataServer, "Enable a metadata server on the node that containers can use to query information about themselves.")
	fs.StringVar(&c.MetadataAddress, prefix+"metadata-address", c.MetadataAddress, "The address the metadata server binds to.")
	fs.BoolVar(&c.EnableMetadataIDTokens, prefix+"enable-metadata-id-tokens", c.EnableMetadataIDTokens, "Enable ID token endpoints on the metadata server for helping facilitate authentication between containers.")
}

func (c *StorageConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.DurationVar(&c.LeaderElectLeaseDuration, prefix+"leader-elect-lease-duration", c.LeaderElectLeaseDuration, "The duration that non-leader candidates will wait to force acquire leadership.")
	fs.DurationVar(&c.LeaderElectRenewDeadline, prefix+"leader-elect-renew-deadline", c.LeaderElectRenewDeadline, "The duration that the acting master will retry refreshing leadership before giving up.")
	fs.DurationVar(&c.LeaderElectRetryPeriod, prefix+"leader-elect-retry-period", c.LeaderElectRetryPeriod, "The duration the LeaderElector clients should wait between tries of actions.")
	fs.DurationVar(&c.CacheSyncTimeout, prefix+"cache-sync-timeout", c.CacheSyncTimeout, "The amount of time to wait for the client cache to sync before starting the controller.")
}

func (c *Config) Validate() error {
	if err := c.Manager.Validate(); err != nil {
		return fmt.Errorf("manager config: %w", err)
	}
	if err := c.Host.Validate(); err != nil {
		return fmt.Errorf("network config: %w", err)
	}
	return nil
}

func (c *ManagerConfig) Validate() error {
	if c.ReconcileTimeout <= 0 {
		return fmt.Errorf("reconcile timeout must be positive")
	}
	if c.EnableMetadataServer {
		_, err := netip.ParseAddrPort(c.MetadataAddress)
		if err != nil {
			return fmt.Errorf("invalid metadata address: %w", err)
		}
	}
	return nil
}
