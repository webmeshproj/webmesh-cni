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

	"github.com/go-oauth2/oauth2/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/webmeshproj/storage-provider-k8s/provider"

	"github.com/webmeshproj/webmesh-cni/internal/host"
)

// AccessTokenGenerator generates JWT tokens with open id claims
// according to network metadata.
type AccessTokenGenerator struct {
	Host    host.Node
	Storage *provider.Provider
}

// NewAccessTokenGenerator creates a new AccessTokenGenerator.
func NewAccessTokenGenerator(host host.Node, storage *provider.Provider) *AccessTokenGenerator {
	return &AccessTokenGenerator{
		Host:    host,
		Storage: storage,
	}
}

type WebmeshClaims struct {
	jwt.RegisteredClaims
	Groups []string `json:"groups,omitempty"`
}

func (a *AccessTokenGenerator) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	return
}
