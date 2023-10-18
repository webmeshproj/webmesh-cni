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

// Package metadata contains the container metadata server.
package metadata

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-logr/logr"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/jmespath/go-jmespath"
	"github.com/webmeshproj/storage-provider-k8s/provider"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet/netutil"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/webmeshproj/webmesh-cni/internal/host"
)

// DefaultServerAddress is the default address for the metadata server.
var DefaultServerAddress = netip.MustParseAddrPort("169.254.169.254:80")

// Options are the options for the container metadata server.
type Options struct {
	// Address is the address to bind the metadata server to.
	// Defaults to DefaultMetadataAddress.
	Address netip.AddrPort
	// Host is the host node to use for the metadata server.
	Host host.Node
	// Storage is the storage provider to use for the metadata server.
	Storage *provider.Provider
	// KeyResolver is the key resolver to use for the metadata server.
	KeyResolver NodeKeyResolver
	// EnableOauth is true if oauth is enabled on the metadata server.
	EnableOauth bool
}

// NodeKeyResolver is an interface that can retrieve the private key of
// a node hosted on this server.
type NodeKeyResolver interface {
	LookupPrivateKey(ctx context.Context, nodeID types.NodeID) (crypto.PrivateKey, bool)
}

// Server is the container metadata server.
type Server struct {
	Options
	srv   *http.Server
	oauth *server.Server
	log   logr.Logger
}

// NewServer creates a new container metadata server.
func NewServer(opts Options) *Server {
	addr := opts.Address
	if !addr.IsValid() {
		addr = DefaultServerAddress
	}
	srv := &Server{
		Options: opts,
		log:     ctrl.Log.WithName("metadata-server"),
	}
	mux := http.NewServeMux()
	mux.Handle("/", srv)
	if opts.EnableOauth {
		manager := manage.NewDefaultManager()
		manager.MustTokenStorage(store.NewMemoryTokenStore())
		manager.MapClientStorage(NewClientStore(opts.Storage, opts.KeyResolver))
		srv.oauth = server.NewDefaultServer(manager)
		srv.oauth.SetAllowGetAccessRequest(true)
		srv.oauth.SetClientInfoHandler(srv.getClientInfoFromRequest)
		srv.oauth.SetInternalErrorHandler(func(err error) (re *errors.Response) {
			srv.log.Error(err, "Internal oauth error")
			return
		})
		srv.oauth.SetResponseErrorHandler(func(re *errors.Response) {
			srv.log.Error(fmt.Errorf("oauth response error: %s", re.Error.Error()), "Oauth response error")
		})
		mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
			err := srv.oauth.HandleAuthorizeRequest(w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
		})
		mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			err := srv.oauth.HandleTokenRequest(w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		})
	}
	srv.srv = &http.Server{
		Addr:    addr.String(),
		Handler: mux,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return log.IntoContext(ctx, srv.log.WithValues("remoteAddr", c.RemoteAddr()))
		},
	}
	return srv
}

// ListenAndServe starts the container metadata server. It blocks until the server
// is shutdown. If addr is empty, the default address of 169.254.169.254:80 is used.
func (s *Server) ListenAndServe() error {
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("start metadata server: %w", err)
	}
	return nil
}

// Shutdown shuts down the container metadata server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// ServeHTTP implements the http.Handler interface and serves the container metadata
// based on the source IP address.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get the peer container based on the source IP address.
	rlog := log.FromContext(r.Context())
	rlog.Info("Serving metadata request", "path", r.URL.Path)
	peerInfo, err := s.getPeerInfoFromRequest(r)
	if err != nil {
		s.log.Error(err, "Failed to get peer from request")
		s.returnError(w, err)
		return
	}
	// We behave like a typical metadata server and return a response
	// based on the path of the request.
	// This is done by marshaling to JSON and treating the path like
	// a jmespath.
	data, err := peerInfo.Peer.MarshalProtoJSON()
	if err != nil {
		s.returnError(w, err)
		return
	}
	switch r.URL.Path {
	case "/":
		// We return the available keys for the metadata server.
		// This is a bit of a hack but we marshal the peer to JSON
		// then back to a mapstructure to get the keys.
		rlog.Info("Serving metadata keys")
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			s.returnError(w, err)
			return
		}
		for k := range m {
			fmt.Fprintln(w, k)
		}
		// Append the privateKey key if the request is local or we have a key resolver.
		if (peerInfo.Local || s.KeyResolver != nil) && !peerInfo.Remote {
			fmt.Fprintln(w, "privateKey")
		}
		return
	default:
		path := strings.TrimPrefix(r.URL.Path, "/")
		path = strings.Replace(path, "/", ".", -1)
		if path == "privateKey" && !peerInfo.Remote {
			// Special case where if this is a self lookup from a local container.
			// We should have their private key.
			var privkey crypto.PrivateKey
			if peerInfo.Local {
				privkey = s.Host.Node().Key()
			} else {
				if s.KeyResolver == nil {
					s.returnError(w, fmt.Errorf("no key resolver"))
					return
				}
				var ok bool
				privkey, ok = s.KeyResolver.LookupPrivateKey(r.Context(), peerInfo.Peer.NodeID())
				if !ok {
					s.returnError(w, fmt.Errorf("no private key found for node %s", peerInfo.Peer.NodeID()))
					return
				}
			}
			encoded, err := privkey.Encode()
			if err != nil {
				s.returnError(w, err)
				return
			}
			fmt.Fprintln(w, encoded)
			return
		}
		// Treat it like a jmespath
		var jsondata any
		if err := json.Unmarshal(data, &jsondata); err != nil {
			s.returnError(w, err)
			return
		}
		result, err := jmespath.Search(path, jsondata)
		if err != nil {
			s.returnError(w, err)
			return
		}
		switch v := result.(type) {
		case string:
			// Return as raw string
			fmt.Fprintln(w, v)
		case int, int32, int64, uint, uint32, uint64, float32, float64:
			// Return as raw int
			fmt.Fprintln(w, v)
		case []byte:
			// Return as base64 encoded string
			fmt.Fprintln(w, base64.StdEncoding.EncodeToString(v))
		default:
			// Return as JSON
			out, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				s.returnError(w, err)
				return
			}
			fmt.Fprintln(w, string(out))
		}
	}
}

func (s *Server) getClientInfoFromRequest(r *http.Request) (clientID string, clientSecret string, err error) {
	// We pull the client information from the source of the request.
	info, err := s.getPeerInfoFromRequest(r)
	if err != nil {
		return "", "", err
	}
	if info.Remote {
		// We don't have a secret from the request, though the user could provide it in a header.
		return string(info.Peer.NodeID()), "", nil
	}
	// We have a secret.
	var key crypto.PrivateKey
	if info.Local {
		key = s.Host.Node().Key()
	} else {
		if s.KeyResolver == nil {
			return "", "", fmt.Errorf("no key resolver")
		}
		var ok bool
		key, ok = s.KeyResolver.LookupPrivateKey(r.Context(), info.Peer.NodeID())
		if !ok {
			return "", "", fmt.Errorf("no private key found for node %s", info.Peer.NodeID())
		}
	}
	encoded, err := key.Encode()
	if err != nil {
		return "", "", err
	}
	return string(info.Peer.NodeID()), encoded, nil
}

// PeerRequestInfo is the information about the peer that is requesting
// the metadata.
type PeerRequestInfo struct {
	// Peer is the peer that is requesting the metadata.
	Peer types.MeshNode
	// Local is true if the request is from the local node.
	Local bool
	// Remote is true if the request is from a remote node.
	Remote bool
}

// getPeerFromRequest returns the peer container based on the source IP address.
func (s *Server) getPeerInfoFromRequest(r *http.Request) (info PeerRequestInfo, err error) {
	rlog := log.FromContext(r.Context())
	isLocal := strings.HasPrefix(r.RemoteAddr, s.Address.Addr().String())
	lookupIP := r.URL.Query().Get("lookup")
	switch {
	case isLocal:
		rlog.V(1).Info("Request is from the local node")
		info.Local = true
		info.Peer, err = s.Storage.MeshDB().Peers().Get(r.Context(), s.Host.ID())
		return
	case lookupIP != "":
		// This is a request to resolve information about a remote node
		info.Remote = true
		var addr netip.Addr
		addr, err = netip.ParseAddr(lookupIP)
		if err != nil {
			return
		}
		rlog.V(1).Info("Request is to lookup a remote node", "lookupIP", addr)
		if addr.Is4() {
			info.Peer, err = s.Storage.Datastore().GetPeerByIPv4Addr(r.Context(), netip.PrefixFrom(addr, 32))
		} else {
			info.Peer, err = s.Storage.Datastore().GetPeerByIPv6Addr(r.Context(), netip.PrefixFrom(addr, netutil.DefaultNodeBits))
		}
		return
	}
	raddrport, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return info, fmt.Errorf("parse remote address: %w", err)
	}
	raddr := raddrport.Addr()
	switch {
	case raddr.Is4():
		info.Peer, err = s.Storage.Datastore().GetPeerByIPv4Addr(r.Context(), netip.PrefixFrom(raddr, 32))
	case raddr.Is6():
		info.Peer, err = s.Storage.Datastore().GetPeerByIPv6Addr(r.Context(), netip.PrefixFrom(raddr, netutil.DefaultNodeBits))
	default:
		err = fmt.Errorf("unknown IP address type: %s", raddr)
	}
	return
}

func (s *Server) returnError(w http.ResponseWriter, err error) {
	errmsg := map[string]string{
		"error": err.Error(),
	}
	out, err := json.MarshalIndent(errmsg, "", "  ")
	if err != nil {
		s.log.Error(err, "Failed to marshal error message")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Error(w, string(out), http.StatusInternalServerError)
}
