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

package metadata

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/webmeshproj/storage-provider-k8s/provider"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Ensure we implement the oauth2.ClientStore interface.
var _ oauth2.ClientStore = &ClientStore{}
var _ oauth2.ClientInfo = &ClientInfo{}

// ClientStore implements an oauth2.ClientStore based on the network storage
// and keys knowwn for local nodes.
type ClientStore struct {
	storage *provider.Provider
	keys    NodeKeyResolver
	domain  string
	mu      sync.Mutex
}

// NewClientStore creates a new ClientStore.
func NewClientStore(storage *provider.Provider, keys NodeKeyResolver) *ClientStore {
	return &ClientStore{
		storage: storage,
		keys:    keys,
	}
}

// GetByID implements oauth2.ClientStore.GetByID.
func (c *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	log := log.FromContext(ctx).WithName("oauth-client-store")
	log.V(1).Info("Looking up client by ID", "id", id)
	if c.domain == "" {
		log.V(1).Info("Fetching current cluster domain")
		netstate, err := c.storage.MeshDB().MeshState().GetMeshState(ctx)
		if err != nil {
			log.Error(err, "Error fetching mesh state")
			return nil, err
		}
		c.domain = netstate.Domain()
	}
	peer, err := c.storage.MeshDB().Peers().Get(ctx, types.NodeID(id))
	if err != nil {
		if !errors.IsNotFound(err) {
			log.Error(err, "Error looking up peer")
		} else {
			log.Info("Peer not found for ID", "id", id)
		}
		return nil, err
	}
	key, ok := c.keys.LookupPrivateKey(ctx, peer.NodeID())
	if !ok {
		log.V(1).Info("Request is not from a local node, we don't have their key")
		return nil, fmt.Errorf("no secret found for peer %s", peer.NodeID())
	}
	encoded, err := key.Encode()
	if err != nil {
		return nil, err
	}
	return &ClientInfo{
		peer:       peer,
		key:        key,
		encodedKey: encoded,
		domain:     c.domain,
	}, nil
}

// ClientInfo is an oauth2.ClientInfo that wraps a peer and key.
type ClientInfo struct {
	peer       types.MeshNode
	key        crypto.PrivateKey
	encodedKey string
	domain     string
}

func (c ClientInfo) GetID() string {
	return c.key.ID()
}

func (c ClientInfo) GetSecret() string {
	return c.encodedKey
}

func (c ClientInfo) GetDomain() string {
	return c.domain
}

func (c ClientInfo) IsPublic() bool {
	return c.peer.GetPrimaryEndpoint() != ""
}

func (c ClientInfo) GetUserID() string {
	return c.peer.GetId()
}
