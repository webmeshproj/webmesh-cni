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
	"net/netip"
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
	addr    netip.AddrPort
	mu      sync.Mutex
}

// NewClientStore creates a new ClientStore.
func NewClientStore(storage *provider.Provider, keys NodeKeyResolver, addr netip.AddrPort) *ClientStore {
	return &ClientStore{
		storage: storage,
		keys:    keys,
		addr:    addr,
	}
}

// GetByID implements oauth2.ClientStore.GetByID.
func (c *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	log := log.FromContext(ctx).WithName("oauth-client-store")
	log.V(1).Info("Looking up client by ID", "id", id)
	var peer types.MeshNode
	var err error
	// Check if we can decode the ID as a public key.
	pubkey, err := crypto.PubKeyFromID(id)
	if err == nil {
		peer, err = c.storage.MeshDB().Peers().GetByPubKey(ctx, pubkey)
	} else {
		// If not, try to look it up as a node ID.
		peer, err = c.storage.MeshDB().Peers().Get(ctx, types.NodeID(id))
	}
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
		log.V(1).Info("We don't have the key for this node")
		return nil, fmt.Errorf("no secret found for peer %s", peer.NodeID())
	}
	encoded, err := key.Encode()
	if err != nil {
		return nil, err
	}
	return &ClientInfo{
		id:         peer.GetId(),
		encodedKey: encoded,
		domain:     fmt.Sprintf("http://%s", c.addr.String()),
	}, nil
}

// ClientInfo is an oauth2.ClientInfo that wraps a peer and key.
type ClientInfo struct {
	id         string
	encodedKey string
	domain     string
}

func (c ClientInfo) GetID() string {
	return c.id
}

func (c ClientInfo) GetSecret() string {
	return c.encodedKey
}

func (c ClientInfo) GetDomain() string {
	return c.domain
}

func (c ClientInfo) IsPublic() bool {
	return false
}

func (c ClientInfo) GetUserID() string {
	return c.id
}
