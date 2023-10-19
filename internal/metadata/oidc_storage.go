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

	"github.com/zitadel/oidc/pkg/op"
)

// Ensure we implement the op.Storage interface.
var _ op.Storage = &OIDCStorage{}

// OIDCStorage implements the op.Storage interface.
type OIDCStorage struct{}

// Health returns the current health status of the storage.
func (o *OIDCStorage) Health(ctx context.Context) error {
	return nil
}
