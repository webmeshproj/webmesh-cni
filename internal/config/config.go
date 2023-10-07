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
	"time"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh-cni/internal/node"
)

// Config is the configuration for the the webmesh-cni controllers.
type Config struct {
	// Manager is the configuration for the controller manager.
	Manager ManagerConfig `koanf:"manager"`
	// Storage is the configuration for the storage provider.
	Storage StorageConfig `koanf:"storage"`
	// HostNode is the configuration for the host webmesh node.
	Host node.Config `koanf:"host"`
}

// ManagerConfig is the configuration for the controller manager.
type ManagerConfig struct {
	// RemoteEndpointDetection enables remote endpoint detection for peer contains.
	RemoteEndpointDetection bool `koanf:"remote-endpoint-detection"`
	// MetricsAddress is the address to bind the metrics server to.
	MetricsAddress string `koanf:"metrics-address"`
	// ProbeAddress is the address to bind the health probe server to.
	ProbeAddress string `koanf:"probe-address"`
	// ReconcileTimeout is the timeout for reconciling a container's interface.
	ReconcileTimeout time.Duration `koanf:"reconcile-timeout"`
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

func (c *Config) BindFlags(fs *pflag.FlagSet) {
	c.Manager.BindFlags("manager.", fs)
	c.Storage.BindFlags("storage.", fs)
	c.Host.BindFlags("host.", fs)
}

func (c *ManagerConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.BoolVar(&c.RemoteEndpointDetection, prefix+"remote-endpoint-detection", false, "Enable remote endpoint detection for peer containers.")
	fs.DurationVar(&c.ReconcileTimeout, prefix+"reconcile-timeout", 15*time.Second, "The timeout for reconciling a container's interface.")
	fs.StringVar(&c.MetricsAddress, prefix+"metrics-address", ":8080", "The address the metric endpoint binds to.")
	fs.StringVar(&c.ProbeAddress, prefix+"probe-address", ":8081", "The address the probe endpoint binds to.")
	fs.DurationVar(&c.ShutdownTimeout, prefix+"shutdown-timeout", 10*time.Second, "The timeout for shutting down the node.")
}

func (c *StorageConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.DurationVar(&c.LeaderElectLeaseDuration, prefix+"leader-elect-lease-duration", 15*time.Second, "The duration that non-leader candidates will wait to force acquire leadership.")
	fs.DurationVar(&c.LeaderElectRenewDeadline, prefix+"leader-elect-renew-deadline", 10*time.Second, "The duration that the acting master will retry refreshing leadership before giving up.")
	fs.DurationVar(&c.LeaderElectRetryPeriod, prefix+"leader-elect-retry-period", 2*time.Second, "The duration the LeaderElector clients should wait between tries of actions.")
	fs.DurationVar(&c.CacheSyncTimeout, prefix+"cache-sync-timeout", 10*time.Second, "The amount of time to wait for the client cache to sync before starting the controller.")
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
	return nil
}
