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
	"net/netip"
	"sync"

	"github.com/go-logr/logr"
	"github.com/webmeshproj/storage-provider-k8s/provider"
	"github.com/zitadel/oidc/pkg/op"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/webmeshproj/webmesh-cni/internal/host"
)

// Ensure we implement the op.Storage interface.
var _ op.Storage = &OIDCStorage{}

// OIDCStorage implements the op.Storage interface.
type OIDCStorage struct {
	OIDCStorageOptions
	log logr.Logger
	mu  sync.RWMutex
}

// OIDCStorageOptions contains options for creating a new OIDCStorage.
type OIDCStorageOptions struct {
	Host    host.Node
	Storage *provider.Provider
	Keys    NodeKeyResolver
	Laddr   netip.AddrPort
}

// NewOIDCStorage creates a new OIDCStorage.
func NewOIDCStorage(opts OIDCStorageOptions) *OIDCStorage {
	return &OIDCStorage{
		OIDCStorageOptions: opts,
		log:                ctrl.Log.WithName("oidc-storage"),
	}
}

// Health returns the current health status of the storage.
func (o *OIDCStorage) Health(ctx context.Context) error {
	return nil
}

// debug is a helper for logging debug messages.
func (o *OIDCStorage) debug(msg string, keysAndValues ...any) {
	o.log.V(1).Info(msg, keysAndValues...)
}
