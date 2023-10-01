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

package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniSpecVersion "github.com/containernetworking/cni/pkg/version"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
	"github.com/webmeshproj/webmesh-cni/internal/client"
)

//+kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list;watch
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/finalizers,verbs=update

// NetConf is the configuration for the CNI plugin.
type NetConf struct {
	// NetConf is the typed configuration for the CNI plugin.
	types.NetConf `json:"inline"`

	// MTU is the MTU to set on interfaces.
	MTU int `json:"mtu"`
	// Kubernetes is the configuration for the Kubernetes API server and
	// information about the node we are running on.
	Kubernetes Kubernetes `json:"kubernetes"`
	// LogLevel is the log level for the plugin.
	LogLevel string `json:"logLevel"`
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

// How long we wait to try to ping the API server before giving up.
const testConnectionTimeout = time.Second * 2

// A global logger set when configuration is loaded.
var log *slog.Logger

func init() {
	// This ensures that main runs only on main threansionsv1beta1 "k8s.io/api/extensions/v1beta1"d (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

// Main is the entrypoint for the webmesh-cni plugin.
func Main(version string) {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, cniSpecVersion.PluginSupports("0.1.0"), "Webmesh CNI plugin "+version)
}

// cmdAdd is the CNI ADD command handler.
func cmdAdd(args *skel.CmdArgs) error {
	conf, err := loadConfigAndLogger(args)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	log.Debug("New ADD request", "config", conf, "args", args)
	cli, err := client.NewFromKubeconfig(conf.Kubernetes.Kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	err = cli.Ping(testConnectionTimeout)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), testConnectionTimeout)
	defer cancel()
	container := &cniv1.PeerContainer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "PeerContainer",
			APIVersion: cniv1.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      args.ContainerID,
			Namespace: conf.Kubernetes.Namespace,
		},
		Spec: cniv1.PeerContainerSpec{
			ContainerID: args.ContainerID,
			Netns:       args.Netns,
			IfName:      args.IfName,
			NodeName:    conf.Kubernetes.NodeName,
		},
	}
	err = cli.Patch(ctx, container, client.Apply, client.ForceOwnership, client.FieldOwner("webmesh-cni"))
	// TODO: Wait for the PeerContainer to be ready and then give its interface to the container.
	return err
}

// cmdCheck is the CNI CHECK command handler.
func cmdCheck(args *skel.CmdArgs) error {
	conf, err := loadConfigAndLogger(args)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	log.Debug("New DEL request", "config", conf, "args", args)
	cli, err := client.NewFromKubeconfig(conf.Kubernetes.Kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	err = cli.Ping(testConnectionTimeout)
	// TODO: Check if the PeerContainer exists and is ready.
	return err
}

// cmdDel is the CNI DEL command handler.
func cmdDel(args *skel.CmdArgs) error {
	conf, err := loadConfigAndLogger(args)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	log.Debug("New DEL request", "config", conf, "args", args)
	cli, err := client.NewFromKubeconfig(conf.Kubernetes.Kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	err = cli.Ping(testConnectionTimeout)
	if err != nil {
		log.Error("Failed to ping API server", "error", err.Error())
		return err
	}
	// Delete the PeerContainer.
	container := &cniv1.PeerContainer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "PeerContainer",
			APIVersion: cniv1.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      args.ContainerID,
			Namespace: conf.Kubernetes.Namespace,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), testConnectionTimeout)
	defer cancel()
	err = cli.Delete(ctx, container)
	if err != nil {
		log.Error("Failed to delete PeerContainer", "error", err.Error())
	}
	return err
}

func loadConfigAndLogger(args *skel.CmdArgs) (*NetConf, error) {
	var conf NetConf
	err := json.Unmarshal(args.StdinData, &conf)
	if err != nil {
		return nil, err
	}
	var writer io.Writer = os.Stderr
	var level slog.Level
	switch conf.LogLevel {
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
	log = slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
	}))
	return &conf, nil
}
