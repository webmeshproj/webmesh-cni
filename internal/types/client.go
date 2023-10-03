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

package types

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	storagev1 "github.com/webmeshproj/storage-provider-k8s/api/storage/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	meshcniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
)

const (
	// CNIFieldOwner is the field owner for CNI objects.
	CNIFieldOwner = "webmesh-cni"
)

var (
	// ErrPeerContainerNotFound is returned when a container is not found.
	ErrPeerContainerNotFound = fmt.Errorf("peer container not found")
)

// IsPeerContainerNotFound returns true if the given error is a peer container not found error.
func IsPeerContainerNotFound(err error) bool {
	return errors.Is(err, ErrPeerContainerNotFound)
}

// Client is the client for the CNI plugin.
type Client struct {
	client.Client
	conf *NetConf
}

// ClientConfig is the configuration for the CNI client.
type ClientConfig struct {
	NetConf    *NetConf
	RestConfig *rest.Config
}

// NewClientForConfig creates a new client from the given configuration.
func NewClientForConfig(conf ClientConfig) (*Client, error) {
	scheme := runtime.NewScheme()
	err := clientgoscheme.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	err = apiextensions.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	err = storagev1.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	err = meshcniv1.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	client, err := client.New(conf.RestConfig, client.Options{
		Scheme: scheme,
		Cache: &client.CacheOptions{
			DisableFor: storagev1.CustomObjects,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	return &Client{
		Client: client,
		conf:   conf.NetConf,
	}, nil
}

// Ping will make sure the client can contact the API server using
// the given timeout.
func (c *Client) Ping(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Try to list peer containers from the API server.
	err := c.Client.List(ctx, &meshcniv1.PeerContainerList{}, &client.ListOptions{
		Limit: 1,
	})
	if err != nil {
		return fmt.Errorf("failed to list peer containers: %w", err)
	}
	return nil
}

// CreatePeerContainerIfNotExists attempts to retrieve the peer container for the given args.
// If it does not exist, it will create it.
func (c *Client) CreatePeerContainerIfNotExists(ctx context.Context, args *skel.CmdArgs) error {
	_, err := c.GetPeerContainer(ctx, args)
	if err != nil {
		if IsPeerContainerNotFound(err) {
			return c.CreatePeerContainer(ctx, args)
		}
		return err
	}
	return nil
}

// GetPeerContainer attempts to retrieve the peer container for the given args.
func (c *Client) GetPeerContainer(ctx context.Context, args *skel.CmdArgs) (*meshcniv1.PeerContainer, error) {
	var container meshcniv1.PeerContainer
	err := c.Client.Get(ctx, c.conf.ObjectKeyFromArgs(args), &container)
	if err != nil {
		if client.IgnoreNotFound(err) == nil {
			return nil, fmt.Errorf("%w: %v", ErrPeerContainerNotFound, err)
		}
		return nil, fmt.Errorf("failed to get peer container: %w", err)
	}
	return &container, nil
}

// CreatePeerContainer attempts to create the peer container for the given args.
func (c *Client) CreatePeerContainer(ctx context.Context, args *skel.CmdArgs) error {
	container := c.conf.ContainerFromArgs(args)
	err := c.Patch(ctx, &container, client.Apply, client.ForceOwnership, client.FieldOwner(CNIFieldOwner))
	if err != nil {
		return fmt.Errorf("failed to apply peer container: %w", err)
	}
	return nil
}

// DeletePeerContainer attempts to delete the peer container for the given args.
func (c *Client) DeletePeerContainer(ctx context.Context, args *skel.CmdArgs) error {
	container := c.conf.ContainerFromArgs(args)
	err := c.Delete(ctx, &container)
	if err != nil && client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("failed to delete peer container: %w", err)
	}
	return nil
}
