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
	"time"

	"github.com/zitadel/oidc/pkg/oidc"
	"github.com/zitadel/oidc/pkg/op"
	"gopkg.in/square/go-jose.v2"
)

// CreateAuthRequest implements the op.Storage interface and will be called after parsing and validation of
// the authentication request.
func (o *OIDCStorage) CreateAuthRequest(context.Context, *oidc.AuthRequest, string) (op.AuthRequest, error) {
	return nil, nil
}

// AuthRequestByID implements the op.Storage interface and will be called after the Login UI redirects
// back to the OIDC endpoint.
func (o *OIDCStorage) AuthRequestByID(context.Context, string) (op.AuthRequest, error) {
	return nil, nil
}

// AuthRequestByCode implements the op.Storage interface and will be called after parsing and validation
// of the token request (in an authorization code flow).
func (o *OIDCStorage) AuthRequestByCode(context.Context, string) (op.AuthRequest, error) {
	return nil, nil
}

// SaveAuthCode implements the op.Storage interface it will be called after the authentication has been
// successful and before redirecting the user agent to the redirect_uri (in an authorization code flow).
func (o *OIDCStorage) SaveAuthCode(context.Context, string, string) error {
	return nil
}

// DeleteAuthRequest implements the op.Storage interface and will be called after creating the token
// response (id and access tokens) for a valid:
// - authentication request (in an implicit flow)
// - token request (in an authorization code flow)
func (o *OIDCStorage) DeleteAuthRequest(context.Context, string) error {
	return nil
}

// CreateAccessToken implements the op.Storage interface and will be called for all requests able to
// return an access token (Authorization Code Flow, Implicit Flow, JWT Profile, etc.).
func (o *OIDCStorage) CreateAccessToken(context.Context, op.TokenRequest) (accessTokenID string, expiration time.Time, err error) {
	return
}

// CreateAccessAndRefreshTokens implements the op.Storage interface and will be called for all requests
// able to return an access and refresh token (Authorization Code Flow, Refresh Token Request).
func (o *OIDCStorage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshTokenID string, expiration time.Time, err error) {
	return
}

// TokenRequestByRefreshToken implements the op.Storage interface and will be called after parsing and validation
// of the refresh token request.
func (o *OIDCStorage) TokenRequestByRefreshToken(ctx context.Context, refreshTokenID string) (op.RefreshTokenRequest, error) {
	return nil, nil
}

// TerminateSession implements the op.Storage interface and will be called after the user signed out, therefore
// the access and refresh token of the user of this client must be removed.
func (o *OIDCStorage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	return nil
}

// RevokeToken implements the op.Storage interface and will be called after parsing and validation of the token
// revocation request.
func (o *OIDCStorage) RevokeToken(ctx context.Context, tokenOrTokenID string, userID string, clientID string) *oidc.Error {
	return nil
}

// GetSigningKey implements the op.Storage interface and will be called when creating the OpenID Provider.
func (o *OIDCStorage) GetSigningKey(context.Context, chan<- jose.SigningKey) {

}

// KeySet implements the op.Storage interface and will be called to get the current (public) keys, among
// others for the keys_endpoint or for validating access_tokens on the userinfo_endpoint.
func (o *OIDCStorage) GetKeySet(context.Context) (*jose.JSONWebKeySet, error) {
	return nil, nil
}
