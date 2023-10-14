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
	"fmt"
	"net/http"

	"github.com/webmeshproj/storage-provider-k8s/provider"
)

// DefaultMetadataAddress is the default address for the metadata server.
const DefaultMetadataAddress = "169.254.169.254:80"

// Options are the options for the container metadata server.
type Options struct {
	// Address is the address to bind the metadata server to.
	// Defaults to DefaultMetadataAddress.
	Address string
	// Storage is the storage provider to use for the metadata server.
	Storage *provider.Provider
}

// Server is the container metadata server.
type Server struct {
	Options
}

// NewServer creates a new container metadata server.
func NewServer(opts Options) *Server {
	return &Server{opts}
}

// ListenAndServe starts the container metadata server. It blocks until the server
// is shutdown. If addr is empty, the default address of 169.254.169.254:80 is used.
func (s *Server) ListenAndServe() error {
	addr := s.Address
	if addr == "" {
		addr = DefaultMetadataAddress
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: s,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("start metadata server: %w", err)
	}
	return nil
}

// ServeHTTP implements the http.Handler interface and serves the container metadata
// based on the source IP address.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
}
