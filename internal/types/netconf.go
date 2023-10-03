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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	meshcniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
	"github.com/webmeshproj/webmesh-cni/internal/client"
)

// NetConf is the configuration for the CNI plugin.
type NetConf struct {
	// NetConf is the typed configuration for the CNI plugin.
	cnitypes.NetConf `json:",inline"`

	// Kubernetes is the configuration for the Kubernetes API server and
	// information about the node we are running on.
	Kubernetes Kubernetes `json:"kubernetes"`
	// Interface is the configuration for the interface.
	Interface Interface `json:"interface"`
	// LogLevel is the log level for the plugin and managed interfaces.
	LogLevel string `json:"logLevel"`
}

// Interface is the configuration for a single interface.
type Interface struct {
	// MTU is the MTU to set on interfaces.
	MTU int `json:"mtu"`
	// DisableIPv4 is whether to disable IPv4 on the interface.
	DisableIPv4 bool `json:"disableIPv4"`
	// DisableIPv6 is whether to disable IPv6 on the interface.
	DisableIPv6 bool `json:"disableIPv6"`
}

// Kubernetes is the configuration for the Kubernetes API server and
// information about the node we are running on.
type Kubernetes struct {
	// Kubeconfig is the path to the kubeconfig file.
	Kubeconfig string `json:"kubeconfig"`
	// NodeName is the name of the node we are running on.
	NodeName string `json:"nodeName"`
	// K8sAPIRoot is the root URL of the Kubernetes API server.
	K8sAPIRoot string `json:"k8sAPIRoot"`
	// Namespace is the namespace to use for the plugin.
	Namespace string `json:"namespace"`
}

// LoadConfigFromArgs loads the configuration from the given CNI arguments.
func LoadConfigFromArgs(cmd *skel.CmdArgs) (*NetConf, error) {
	var conf NetConf
	err := json.Unmarshal(cmd.StdinData, &conf)
	if err != nil {
		return nil, fmt.Errorf("failed to load netconf from stdin data: %w", err)
	}
	if conf.Kubernetes.Kubeconfig == "" {
		conf.Kubernetes.Kubeconfig = DefaultKubeconfigPath
	}
	return &conf, nil
}

// NewLogger creates a new logger for the plugin.
func (n *NetConf) NewLogger() *slog.Logger {
	var writer io.Writer = os.Stderr
	var level slog.Level
	switch n.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	case "silent":
		writer = io.Discard
	default:
		level = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
	}))
}

// ObjectKeyFromArgs creates a new object key for the given container ID.
func (n *NetConf) ObjectKeyFromArgs(args *skel.CmdArgs) client.ObjectKey {
	return client.ObjectKey{
		Name:      args.ContainerID,
		Namespace: n.Kubernetes.Namespace,
	}
}

// ContainerFromArgs creates a skeleton container object for the given container arguments.
func (n *NetConf) ContainerFromArgs(args *skel.CmdArgs) meshcniv1.PeerContainer {
	desiredIfName := "wmesh" + args.ContainerID[:min(8, len(args.ContainerID))] + "0"
	return meshcniv1.PeerContainer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "PeerContainer",
			APIVersion: meshcniv1.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      args.ContainerID,
			Namespace: n.Kubernetes.Namespace,
		},
		Spec: meshcniv1.PeerContainerSpec{
			NodeID:      meshtypes.TruncateID(args.ContainerID),
			Netns:       args.Netns,
			IfName:      desiredIfName,
			NodeName:    n.Kubernetes.NodeName,
			MTU:         n.Interface.MTU,
			DisableIPv4: n.Interface.DisableIPv4,
			DisableIPv6: n.Interface.DisableIPv6,
			LogLevel:    n.LogLevel,
		},
	}
}
