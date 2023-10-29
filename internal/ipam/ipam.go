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

// Package IPAM provides IPv4 address allocation against the mesh database.
package ipam

import (
	"context"
	"fmt"
	"net/netip"

	v1 "github.com/webmeshproj/api/go/v1"
	meshplugins "github.com/webmeshproj/webmesh/pkg/plugins"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
	"k8s.io/client-go/rest"
)

// Allocator is the interface for an IPAM allocator.
type Allocator interface {
	// Allocate allocates an IP address for the given node ID.
	Allocate(ctx context.Context, nodeID meshtypes.NodeID) (netip.Prefix, error)
	// Locker returns the underlying Locker. Locks should be acquired before
	// calls to allocate. They are provided as separate methods to ensure
	// the caller has time to write the allocation to the DB. Allocate simply
	// observes the current state and respond with an available address.
	Locker() Locker
}

// Config is the configuration for the allocator.
type Config struct {
	// IPAM is the IPAM configuration.
	IPAM meshplugins.IPAMConfig
	// Lock is the lock configuration.
	Lock LockConfig
	// Network is the IPv4 network to allocate addresses in.
	Network netip.Prefix
}

var (
	// ErrNoNetwork is returned when no network is configured.
	ErrNoNetwork = fmt.Errorf("no network configured")
	// ErrNoStorage is returned when no storage is configured.
	ErrNoStorage = fmt.Errorf("no storage configured")
)

// NewAllocator creates a new IPAM allocator. The given configuration
// will be copied and modified.
func NewAllocator(cfg *rest.Config, conf Config) (Allocator, error) {
	if conf.Network == (netip.Prefix{}) {
		return nil, ErrNoNetwork
	}
	if conf.IPAM.Storage == nil {
		return nil, ErrNoStorage
	}
	lock, err := NewLock(rest.CopyConfig(cfg), conf.Lock)
	if err != nil {
		return nil, err
	}
	ipam := meshplugins.NewBuiltinIPAM(conf.IPAM)
	return &allocator{
		ipam:    ipam,
		lock:    lock,
		network: conf.Network,
	}, nil
}

type allocator struct {
	ipam    *meshplugins.BuiltinIPAM
	lock    Locker
	network netip.Prefix
}

func (a *allocator) Allocate(ctx context.Context, nodeID meshtypes.NodeID) (netip.Prefix, error) {
	alloc, err := a.ipam.Allocate(ctx, &v1.AllocateIPRequest{
		NodeID: nodeID.String(),
		Subnet: a.network.String(),
	})
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.ParsePrefix(alloc.GetIp())
}

func (a *allocator) Locker() Locker {
	return a.lock
}
