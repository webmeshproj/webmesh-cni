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
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/webmeshproj/webmesh/pkg/meshnet"
	meshtestutil "github.com/webmeshproj/webmesh/pkg/meshnet/testutil"
	meshnode "github.com/webmeshproj/webmesh/pkg/meshnode"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
)

// MockNode is a mock mesh node exposing the methods used by the peercontainer
// reconciler.
type MockNode struct {
	nodeID      meshtypes.NodeID
	config      meshnode.Config
	connectOpts meshnode.ConnectOptions
	started     atomic.Bool
	nw          meshnet.Manager
	mu          sync.Mutex
}

// NewMockNode returns a new mock node.
func NewMockNode(log *slog.Logger, opts meshnode.Config) Node {
	return &MockNode{
		nodeID: meshtypes.NodeID(opts.NodeID),
		config: opts,
	}
}

// ID returns the node ID.
func (m *MockNode) ID() meshtypes.NodeID {
	return m.nodeID
}

// Started returns true if the node is started.
func (m *MockNode) Started() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.started.Load()
}

// Ready returns a channel that is closed when the node is ready.
func (m *MockNode) Ready() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		for !m.Started() {
		}
	}()
	return ch
}

// Connect connects the node to the mesh.
func (m *MockNode) Connect(_ context.Context, opts meshnode.ConnectOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectOpts = opts
	m.nw = meshtestutil.NewManager(meshnet.Options{
		InterfaceName:       m.connectOpts.NetworkOptions.InterfaceName,
		ListenPort:          m.connectOpts.NetworkOptions.ListenPort,
		Modprobe:            m.connectOpts.NetworkOptions.Modprobe,
		PersistentKeepAlive: m.connectOpts.NetworkOptions.PersistentKeepAlive,
		ForceTUN:            m.connectOpts.NetworkOptions.ForceTUN,
		MTU:                 m.connectOpts.NetworkOptions.MTU,
		ZoneAwarenessID:     m.config.ZoneAwarenessID,
		DisableIPv4:         m.config.DisableIPv4,
		DisableIPv6:         m.config.DisableIPv6,
	}, m.nodeID)
	m.started.Store(true)
	return nil
}

// Network returns the meshnet.Network for this node.
func (m *MockNode) Network() meshnet.Manager {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started.Load() {
		return nil
	}
	return m.nw
}

// Close closes the node.
func (m *MockNode) Close(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started.Store(false)
	return nil
}
