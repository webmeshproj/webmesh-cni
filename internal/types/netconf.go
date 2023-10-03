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
	"strings"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	meshsys "github.com/webmeshproj/webmesh/pkg/meshnet/system"
	meshtypes "github.com/webmeshproj/webmesh/pkg/storage/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"

	meshcniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
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

// SetDefaults sets the default values for the configuration.
// It returns the configuration for convenience.
func (n *NetConf) SetDefaults() *NetConf {
	n.Kubernetes.Default()
	n.Interface.Default()
	if n.LogLevel == "" {
		n.LogLevel = "info"
	}
	return n
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

func (i *Interface) Default() {
	if i.MTU <= 0 {
		i.MTU = meshsys.DefaultMTU
	}
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

// Default sets the default values for the Kubernetes configuration.
func (k *Kubernetes) Default() {
	if k.Kubeconfig == "" {
		k.Kubeconfig = DefaultKubeconfigPath
	}
}

// LoadConfigFromFile loads the configuration from the given file.
func LoadConfigFromFile(path string) (*NetConf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	return LoadConfigFromArgs(&skel.CmdArgs{StdinData: data})
}

// LoadConfigFromArgs loads the configuration from the given CNI arguments.
func LoadConfigFromArgs(cmd *skel.CmdArgs) (*NetConf, error) {
	var conf NetConf
	err := json.Unmarshal(cmd.StdinData, &conf)
	if err != nil {
		return nil, fmt.Errorf("failed to load netconf from stdin data: %w", err)
	}
	return conf.SetDefaults(), nil
}

// NewLogger creates a new logger for the plugin.
func (n *NetConf) NewLogger(args *skel.CmdArgs) *slog.Logger {
	return slog.New(slog.NewJSONHandler(n.LogWriter(), &slog.HandlerOptions{
		AddSource: true,
		Level:     n.SlogLevel(),
	})).
		With("container", n.ObjectKeyFromArgs(args)).
		With("args", args).
		With("config", n)
}

// SlogLevel returns the slog.Level for the given log level string.
func (n *NetConf) SlogLevel() slog.Level {
	switch strings.ToLower(n.LogLevel) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// LogWriter reteurns the io.Writer for the plugin logger.
func (n *NetConf) LogWriter() io.Writer {
	var writer io.Writer = os.Stderr
	switch strings.ToLower(n.LogLevel) {
	case "silent", "off":
		writer = io.Discard
	}
	return writer
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

// NewClient creates a new client for the Kubernetes API server.
func (n *NetConf) NewClient(pingTimeout time.Duration) (*Client, error) {
	if n == nil {
		return nil, fmt.Errorf("netconf is nil")
	}
	restCfg, err := n.RestConfig()
	if err != nil {
		err = fmt.Errorf("failed to create REST config: %w", err)
		return nil, err
	}
	cli, err := NewClientForConfig(restCfg, *n)
	if err != nil {
		err = fmt.Errorf("failed to create client: %w", err)
		return nil, err
	}
	return cli, cli.Ping(pingTimeout)
}

// RestConfig returns the rest config for the Kubernetes API server.
func (n *NetConf) RestConfig() (*rest.Config, error) {
	cfg, err := clientcmd.BuildConfigFromKubeconfigGetter("", func() (*clientcmdapi.Config, error) {
		conf, err := clientcmd.LoadFromFile(n.Kubernetes.Kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig from file: %w", err)
		}
		return conf, nil
	})
	return cfg, err
}