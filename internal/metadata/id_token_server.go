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
	"github.com/webmeshproj/webmesh/pkg/storage/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// IDTokenServer is the server for ID tokens. It can create identification
// tokens for clients to use to access other services in the cluster.
type IDTokenServer struct{ *Server }

// SignerHeader is the header specifying which node signed the token.
const SignerHeader = "cni"

// Now is a function that returns the current time. It is used to override
// the time used for token validation.
var Now = time.Now

// IDClaims are the claims for an ID token.
type IDClaims struct {
	jwt.Claims `json:",inline"`
	Groups     []string `json:"groups"`
}

// ServeHTTP implements http.Handler and will handle token issuance and validation.
func (i *IDTokenServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rlog := log.FromContext(r.Context())
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")
	if r.Method == http.MethodOptions {
		// Handle CORS preflight requests.
		rlog.Info("Serving CORS preflight request", "path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		return
	}
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
	peerkey, err := info.Peer.DecodePublicKey()
	if err != nil {
		i.returnError(w, err)
		return
	}
	cl := IDClaims{
		Claims: jwt.Claims{
			Issuer:    i.Host.ID().String(),
			Subject:   info.Peer.GetId(),
			Audience:  i.audience(),
			Expiry:    jwt.NewNumericDate(Now().UTC().Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(Now().UTC()),
			IssuedAt:  jwt.NewNumericDate(Now().UTC()),
			ID: func() string {
				if info.Peer.GetId() == peerkey.ID() {
					// Don't include the ID if it's the same as the subject.
					// Saves space and makes it easier to read.
					return ":sub"
				}
				return peerkey.ID()
			}(),
		},
		Groups: []string{},
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
		"id":      peerkey.ID(),
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
	issuer := i.Host.ID().String()
	if len(tok.Headers) > 0 {
		peer, ok := tok.Headers[0].ExtraHeaders[SignerHeader].(string)
		if ok {
			issuer = peer
		}
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
		wmkey, err := issuingPeer.DecodePublicKey()
		if err != nil {
			i.returnError(w, err)
			return
		}
		pubkey = wmkey.AsNative()
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
		Time: Now().UTC(),
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
			SignerHeader: i.Host.ID().String(),
		},
	}).WithType("JWT")
}

func (i *IDTokenServer) privateKey() ed25519.PrivateKey {
	return i.Host.Node().Key().AsNative()
}

func (i *IDTokenServer) publicKey() ed25519.PublicKey {
	return i.Host.Node().Key().PublicKey().AsNative()
}

func (i *IDTokenServer) audience() jwt.Audience {
	return jwt.Audience{strings.TrimSuffix(i.Host.Node().Domain(), ".")}
}
