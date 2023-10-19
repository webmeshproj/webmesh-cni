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
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// IDTokenServer is the server for ID tokens. It can create identification
// tokens for clients to use to access other services in the cluster.
type IDTokenServer struct{ *Server }

// IDClaims are the claims for an ID token.
type IDClaims struct {
	jwt.Claims `json:",inline"`
	Groups     []string `json:"groups"`
	Scopes     []string `json:"scopes"`
}

// ServeHTTP implements http.Handler and will handle token issuance and validation.
func (i *IDTokenServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rlog := log.FromContext(r.Context())
	rlog.Info("Serving metadata request", "path", r.URL.Path)
	switch r.URL.Path {
	case "/id-tokens/issue":
		i.issueToken(w, r)
	case "/id-tokens/validate":
		i.validateToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (i *IDTokenServer) issueToken(w http.ResponseWriter, r *http.Request) {
	rlog := log.FromContext(r.Context())
	rlog.Info("Issuing ID token")
	info, err := i.getPeerInfoFromRequest(r)
	if err != nil {
		i.returnError(w, err)
		return
	}
	sig, err := i.newSigner()
	if err != nil {
		i.returnError(w, err)
		return
	}
	pubkey, err := crypto.DecodePublicKey(info.Peer.GetPublicKey())
	if err != nil {
		i.returnError(w, err)
		return
	}
	cl := IDClaims{
		Claims: jwt.Claims{
			Issuer:    i.Host.ID().String(),
			Subject:   info.Peer.GetId(),
			Audience:  i.audience(),
			Expiry:    jwt.NewNumericDate(time.Now().UTC().Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now().UTC()),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ID:        pubkey.ID(),
		},
		Groups: []string{},
		Scopes: []string{"webmesh", "groups"},
	}
	groups, err := i.Storage.MeshDB().RBAC().ListGroups(r.Context())
	if err == nil {
		for _, g := range groups {
			if g.ContainsNode(info.Peer.NodeID()) {
				cl.Groups = append(cl.Groups, g.GetName())
			}
		}
	} else {
		rlog.Error(err, "Failed to list groups, skipping")
	}
	raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
	if err != nil {
		i.returnError(w, err)
		return
	}
	out := map[string]any{
		"token":   raw,
		"expires": cl.Expiry.Time().Format(time.RFC3339),
	}
	i.returnJSON(w, out)
}

func (i *IDTokenServer) validateToken(w http.ResponseWriter, r *http.Request) {
	rlog := log.FromContext(r.Context())
	rlog.Info("Validating ID token")
	token := r.Header.Get("Authorization")
	if token == "" {
		i.returnError(w, fmt.Errorf("missing Authorization header"))
		return
	}
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		i.returnError(w, err)
		return
	}
	issuer, ok := tok.Headers[0].ExtraHeaders["iss"].(string)
	if !ok {
		// Assume the issuer is the host ID.
		issuer = i.Host.ID().String()
	}
	var pubkey ed25519.PublicKey
	switch issuer {
	case i.Host.ID().String():
		rlog.V(1).Info("Token was signed by the local host")
		pubkey = i.publicKey()
	default:
		rlog.V(1).Info("Token was signed by a peer node", "issuer", issuer)
		issuingPeer, err := i.Storage.MeshDB().Peers().Get(r.Context(), types.NodeID(issuer))
		if err != nil {
			i.returnError(w, err)
			return
		}
		wmkey, err := crypto.DecodePublicKey(issuingPeer.GetPublicKey())
		if err != nil {
			i.returnError(w, err)
			return
		}
		pubkey = ed25519.PublicKey(wmkey.Bytes())
	}
	var cl IDClaims
	if err := tok.Claims(pubkey, &cl); err != nil {
		i.returnError(w, err)
		return
	}
	expected := jwt.Expected{
		// Optional fields to validate based on the query.
		ID:      r.URL.Query().Get("id"),
		Subject: r.URL.Query().Get("subject"),
		Issuer:  r.URL.Query().Get("issuer"),
		// Ensure it's the audience we expect.
		Audience: i.audience(),
		// Ensure the token is not expired.
		Time: time.Now().UTC(),
	}
	if err := cl.Validate(expected); err != nil {
		i.returnError(w, err)
		return
	}
	i.returnJSON(w, cl)
}

func (i *IDTokenServer) newSigner() (jose.Signer, error) {
	return jose.NewSigner(i.signingKey(), i.signingOptions())
}

func (i *IDTokenServer) signingKey() jose.SigningKey {
	return jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       i.privateKey(),
	}
}

func (i *IDTokenServer) signingOptions() *jose.SignerOptions {
	return (&jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			"kid": "webmesh",
			"iss": i.Host.ID().String(),
		},
	}).WithType("JWT")
}

func (i *IDTokenServer) privateKey() ed25519.PrivateKey {
	return ed25519.PrivateKey(i.Host.Node().Key().Bytes())
}

func (i *IDTokenServer) publicKey() ed25519.PublicKey {
	return ed25519.PublicKey(i.Host.Node().Key().PublicKey().Bytes())
}

func (i *IDTokenServer) audience() jwt.Audience {
	return jwt.Audience{strings.TrimSuffix(i.Host.Node().Domain(), ".")}
}