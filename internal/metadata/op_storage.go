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

	"github.com/zitadel/oidc/pkg/oidc"
	"github.com/zitadel/oidc/pkg/op"
	"gopkg.in/square/go-jose.v2"
)

// GetClientByClientID implements the op.Storage interface and will be called whenever information
// (type, redirect_uris, etc.) about the client behind the client_id is needed.
func (o *OIDCStorage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	return nil, nil
}

// AuthorizeClientIDSecret implements the op.Storage interface and will be called for validating the
// client_id, client_secret on token or introspection requests.
func (o *OIDCStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	return nil
}

// SetUserinfoFromScopes implements the op.Storage interface.
// Provide an empty implementation and use SetUserinfoFromRequest instead.
func (o *OIDCStorage) SetUserinfoFromScopes(ctx context.Context, userinfo oidc.UserInfoSetter, userID, clientID string, scopes []string) error {
	return nil
}

// SetUserinfoFromRequests implements the op.CanSetUserinfoFromRequest interface. It will be called for the
// creation of an id_token.
func (s *OIDCStorage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, token op.IDTokenRequest, scopes []string) error {
	return nil
}

// SetUserinfoFromToken implements the op.Storage interface and will be called for the userinfo endpoint.
func (o *OIDCStorage) SetUserinfoFromToken(ctx context.Context, userinfo oidc.UserInfoSetter, tokenID, subject, origin string) error {
	return nil
}

// SetIntrospectionFromToken implements the op.Storage interface and will be called for the introspection endpoint.
func (o *OIDCStorage) SetIntrospectionFromToken(ctx context.Context, userinfo oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	return nil
}

// GetPrivateClaimsFromScopes implements the op.Storage interface and will be called for the creation of a JWT access
// token to assert claims for custom scopes.
func (o *OIDCStorage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	return nil, nil
}

// GetKeyByIDAndClientID implements the op.Storage interface and will be called to validate the signatures of a JWT
// (JWT Profile Grant and Authentication).
func (o *OIDCStorage) GetKeyByIDAndUserID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, nil
}

// ValidateJWTProfileScopes implements the op.Storage interface and will be called to validate the scopes of a
// JWT Profile Authorization Grant request.
func (o *OIDCStorage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return nil, nil
}
