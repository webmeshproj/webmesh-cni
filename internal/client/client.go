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

// Package client contains the client for the CNI plugin and its resource definitions.
package client

import (
	"context"
	"time"

	storagev1 "github.com/webmeshproj/storage-provider-k8s/api/storage/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
)

// Pass through types for easier access.

var (
	Apply          = client.Apply
	ForceOwnership = client.ForceOwnership
	IgnoreNotFound = client.IgnoreNotFound
)

type (
	ObjectKey  = client.ObjectKey
	FieldOwner = client.FieldOwner
)

// Client is the client for the CNI plugin.
type Client struct {
	client.Client
}

// NewOrDie creates a new client from the given kubeconfig or panics.
func NewOrDie() *Client {
	cfg := ctrl.GetConfigOrDie()
	client, err := NewForConfig(cfg)
	if err != nil {
		panic(err)
	}
	return client
}

// NewFromKubeconfig creates a new client from the given kubeconfig.
func NewFromKubeconfig(kubeconfig string) (*Client, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	return NewForConfig(cfg)
}

// NewForConfig creates a new client from the given configuration.
func NewForConfig(cfg *rest.Config) (*Client, error) {
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
	err = cniv1.AddToScheme(scheme)
	if err != nil {
		return nil, err
	}
	client, err := client.New(cfg, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, err
	}
	return &Client{
		Client: client,
	}, nil
}

// Ping will make sure the client can contact the API server using
// the given timeout.
func (c *Client) Ping(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Try to fetch the description of the cniv1.PeerContainer resource.
	// This will fail if the API server is not reachable.
	var crd apiextensions.CustomResourceDefinition
	return c.Get(ctx, client.ObjectKey{
		Name: "peercontainers.cni.webmesh.io",
	}, &crd)
}
