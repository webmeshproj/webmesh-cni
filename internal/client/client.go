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
	storagev1 "github.com/webmeshproj/storage-provider-k8s/api/storage/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
)

// Client is the client for the CNI plugin.
type Client struct {
	client.Client
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