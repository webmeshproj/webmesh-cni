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

package config

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/knadh/koanf/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ConfigMapProvider is a provider for koanf that reads in configurations
// from the given config map.
type ConfigMapProvider struct {
	cfg *rest.Config
	obj client.ObjectKey
}

// NewConfigMapProvider returns a new configmap provider.
func NewConfigMapProvider(cfg *rest.Config, obj client.ObjectKey) koanf.Provider {
	return &ConfigMapProvider{}
}

// Read returns the entire configuration as raw []bytes to be parsed.
// with a Parser.
func (c *ConfigMapProvider) ReadBytes() ([]byte, error) {
	data, err := c.Read()
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// Read returns the parsed configuration as a nested map[string]interface{}.
// It is important to note that the string keys should not be flat delimited
// keys like `parent.child.key`, but nested like `{parent: {child: {key: 1}}}`.
func (c *ConfigMapProvider) Read() (map[string]any, error) {
	cm, err := c.getConfigMap()
	if err != nil {
		return nil, err
	}
	out := make(map[string]any)
	for k, v := range cm.Data {
		var val any
		switch {
		case v == "true":
			val = true
		case v == "false":
			val = false
		case v == "null":
			val = nil
		default:
			// Check if its valid JSON
			if err := json.Unmarshal([]byte(v), &val); err == nil {
				continue
			}
			// Check if it can be parsed as a number
			if n, err := strconv.Atoi(v); err == nil {
				val = n
				continue
			}
			// Check if it can be parsed as a duration
			if d, err := time.ParseDuration(v); err == nil {
				val = d
				continue
			}
		}
		fields := strings.Split(k, ".")
		if len(fields) == 1 {
			out[k] = val
			continue
		}
		toSet := out
		for _, f := range fields {
			if _, ok := toSet[f]; !ok {
				toSet[f] = make(map[string]any)
			}
			toSet = toSet[f].(map[string]any)
		}
		toSet[fields[len(fields)-1]] = val
	}
	return out, nil
}

func (c *ConfigMapProvider) getConfigMap() (*corev1.ConfigMap, error) {
	cli, err := c.newClient()
	if err != nil {
		return nil, err
	}
	var cm corev1.ConfigMap
	err = cli.Get(context.Background(), c.obj, &cm)
	if err != nil {
		return nil, fmt.Errorf("failed to get configmap: %w", err)
	}
	return &cm, nil
}

func (c *ConfigMapProvider) newClient() (client.Client, error) {
	scheme := runtime.NewScheme()
	err := clientgoscheme.AddToScheme(scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to add client-go scheme: %w", err)
	}
	cli, err := client.New(c.cfg, client.Options{
		Scheme: scheme,
		Cache: &client.CacheOptions{
			DisableFor: []client.Object{&corev1.ConfigMap{}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	return client.NewNamespacedClient(cli, c.obj.Namespace), nil
}
