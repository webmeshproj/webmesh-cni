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
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// IDTokenServer is the server for ID tokens. It can create identification
// tokens for clients to use to access other services in the cluster.
type IDTokenServer struct{ *Server }

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
	cl := IDClaims{
		Claims: jwt.Claims{
			Issuer:    i.Host.ID().String(),
			Subject:   info.Peer.GetId(),
			Audience:  jwt.Audience{i.Host.Node().Domain()},
			Expiry:    jwt.NewNumericDate(time.Now().UTC().Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now().UTC()),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		},
		Groups: []string{},
		Scopes: []string{"webmesh"},
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
}

func (i *IDTokenServer) newSigner() (jose.Signer, error) {
	return jose.NewSigner(jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       ed25519.PrivateKey(i.Host.Node().Key().Bytes()),
	}, (&jose.SignerOptions{}).WithType("JWT"))
}

type IDClaims struct {
	jwt.Claims `json:",inline"`
	Groups     []string `json:"groups,omitempty"`
	Scopes     []string `json:"scopes,omitempty"`
}
