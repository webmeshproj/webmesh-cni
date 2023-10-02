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
	"runtime/debug"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	cniSpecVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	meshcniv1 "github.com/webmeshproj/webmesh-cni/api/v1"
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

const (
	// TODO: Make these configurable.

	// How long we wait to try to ping the API server before giving up.
	testConnectionTimeout = time.Second * 2
	// How long we wait to try to create the peer container instance.
	createPeerContainerTimeout = time.Second * 2
	// How long to wait for the controller to setup the container interface.
	setupContainerInterfaceTimeout = time.Second * 10
)

// A global logger set when configuration is loaded.
var log = slog.Default()

func init() {
	// This ensures that main runs only on the main thread (thread group leader).
	// Since namespace ops (unshare, setns) are done for a single thread, we must
	// ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

// Main is the entrypoint for the webmesh-cni plugin.
func Main(version string) {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, cniSpecVersion.PluginSupports("0.3.1"), "Webmesh CNI plugin "+version)
}

// cmdAdd is the CNI ADD command handler.
func cmdAdd(args *skel.CmdArgs) (err error) {
	// Defer a panic recover, so that in case we panic we can still return
	// a proper error to the runtime.
	defer func() {
		if e := recover(); e != nil {
			msg := fmt.Sprintf("Webmesh CNI panicked during ADD: %s\nStack trace:\n%s", e, string(debug.Stack()))
			if err != nil {
				// If we're recovering and there was also an error, then we need to
				// present both.
				msg = fmt.Sprintf("%s: error=%s", msg, err)
			}
			err = fmt.Errorf(msg)
		}
		if err != nil {
			log.Error("Final result of CNI ADD was an error", "error", err.Error())
			cnierr := types.Error{
				Code:    100,
				Msg:     "falied to run ADD command",
				Details: err.Error(),
			}
			cnierr.Print()
			os.Exit(1)
		}
	}()
	conf, err := loadConfigAndLogger(args)
	if err != nil {
		err = fmt.Errorf("failed to load config: %w", err)
		return
	}
	log.Debug("New ADD request", "config", conf, "args", args)
	containerNs, err := ns.GetNS(args.Netns)
	if err != nil {
		err = fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
		return
	}
	defer containerNs.Close()
	cli, err := client.NewFromKubeconfig(conf.Kubernetes.Kubeconfig)
	if err != nil {
		err = fmt.Errorf("failed to create client: %w", err)
		return
	}
	err = cli.Ping(testConnectionTimeout)
	if err != nil {
		err = fmt.Errorf("failed to ping API server: %w", err)
		return
	}
	// Start building a container type.
	desiredIfName := "webmesh" + args.ContainerID[:min(9, len(args.ContainerID))]
	container := &meshcniv1.PeerContainer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "PeerContainer",
			APIVersion: meshcniv1.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      args.ContainerID,
			Namespace: conf.Kubernetes.Namespace,
		},
		Spec: meshcniv1.PeerContainerSpec{
			ContainerID: args.ContainerID,
			Netns:       args.Netns,
			IfName:      desiredIfName,
			NodeName:    conf.Kubernetes.NodeName,
			MTU:         conf.Interface.MTU,
			DisableIPv4: conf.Interface.DisableIPv4,
			DisableIPv6: conf.Interface.DisableIPv6,
			LogLevel:    conf.LogLevel,
		},
	}
	log.Info("Creating PeerContainer", "container", container)
	ctx, cancel := context.WithTimeout(context.Background(), createPeerContainerTimeout)
	defer cancel()
	err = cli.Patch(ctx, container, client.Apply, client.ForceOwnership, client.FieldOwner("webmesh-cni"))
	if err != nil {
		log.Error("Failed to create PeerContainer", "error", err.Error())
		return err
	}
	// Wait for the PeerContainer to be ready.
	ctx, cancel = context.WithTimeout(context.Background(), setupContainerInterfaceTimeout)
	defer cancel()
WaitForInterface:
	for {
		select {
		case <-ctx.Done():
			err = fmt.Errorf("timed out waiting for container interface to be ready")
			return
		case <-time.After(time.Second):
			// Try to fetch the container status
			err = cli.Get(ctx, client.ObjectKey{
				Name:      args.ContainerID,
				Namespace: conf.Kubernetes.Namespace,
			}, container)
			if err != nil {
				log.Error("Failed to get PeerContainer", "error", err.Error())
				continue
			}
			switch container.Status.Phase {
			case meshcniv1.InterfaceStatusCreated:
				log.Debug("Waiting for container interface to be ready", "phase", container.Status.Phase)
			case meshcniv1.InterfaceStatusStarting:
				log.Debug("Waiting for container interface to be ready", "phase", container.Status.Phase)
			case meshcniv1.InterfaceStatusRunning:
				log.Info("Container interface is ready", "phase", container.Status.Phase)
				break WaitForInterface
			case meshcniv1.InterfaceStatusFailed:
				log.Error("Container interface failed to start", "phase", container.Status.Phase, "error", container.Status.Error)
			}
		}
	}
	// Start building the result
	result := &cniv1.Result{
		CNIVersion: conf.CNIVersion,
		IPs: func() []*cniv1.IPConfig {
			var ips []*cniv1.IPConfig
			if container.Status.IPv4Address != "" {
				ipnet, err := netlink.ParseIPNet(container.Status.IPv4Address)
				if err != nil {
					log.Error("Failed to parse IPv4 address", "error", err.Error())
				} else {
					ips = append(ips, &cniv1.IPConfig{
						Address: *ipnet,
						Gateway: ipnet.IP, // Use system's default gateway or self?
					})
				}
			}
			if container.Status.IPv6Address != "" {
				ipnet, err := netlink.ParseIPNet(container.Status.IPv6Address)
				if err != nil {
					log.Error("Failed to parse IPv6 address", "error", err.Error())
				} else {
					ips = append(ips, &cniv1.IPConfig{
						Address: *ipnet,
						Gateway: ipnet.IP, // Use system's default gateway or self?
					})
				}
			}
			return ips
		}(),
		Routes: []*types.Route{}, // The mesh node handles route configurations.
		DNS:    conf.DNS,
	}
	// Move the wireguard interface to the container namespace.
	link, err := netlink.LinkByName(container.Status.InterfaceName)
	if err != nil {
		err = fmt.Errorf("failed to find %q: %v", container.Status.InterfaceName, err)
		return
	}
	contDev, err := moveLinkIn(link, containerNs, container.Status.InterfaceName)
	if err != nil {
		err = fmt.Errorf("move link to container namespace: %v", err)
		return
	}
	result.Interfaces = []*cniv1.Interface{{
		Name:    contDev.Attrs().Name,
		Mac:     contDev.Attrs().HardwareAddr.String(),
		Sandbox: containerNs.Path(),
	}}
	err = types.PrintResult(result, conf.CNIVersion)
	return
}

// cmdCheck is the CNI CHECK command handler.
// TODO: Use this to force a refresh of peers for a container.
func cmdCheck(args *skel.CmdArgs) (err error) {
	// Defer a panic recover, so that in case we panic we can still return
	// a proper error to the runtime.
	defer func() {
		if e := recover(); e != nil {
			msg := fmt.Sprintf("Webmesh CNI panicked during CHECK: %s\nStack trace:\n%s", e, string(debug.Stack()))
			if err != nil {
				// If we're recovering and there was also an error, then we need to
				// present both.
				msg = fmt.Sprintf("%s: error=%s", msg, err)
			}
			err = fmt.Errorf(msg)
		}
		if err != nil {
			log.Error("Final result of CNI CHECK was an error", "error", err.Error())
			cnierr := types.Error{
				Code:    100,
				Msg:     "falied to run CHECK command",
				Details: err.Error(),
			}
			cnierr.Print()
			os.Exit(1)
		}
	}()
	conf, err := loadConfigAndLogger(args)
	if err != nil {
		err = fmt.Errorf("failed to load config: %w", err)
		return
	}
	log.Debug("New CHECK request", "config", conf, "args", args)
	cli, err := client.NewFromKubeconfig(conf.Kubernetes.Kubeconfig)
	if err != nil {
		err = fmt.Errorf("failed to create client: %w", err)
		return
	}
	err = cli.Ping(testConnectionTimeout)
	// TODO: Check if the PeerContainer exists and is ready perhaps?
	// Most implementations do a dummy check like this.
	if err == nil {
		fmt.Println("OK")
	}
	return
}

// cmdDel is the CNI DEL command handler.
func cmdDel(args *skel.CmdArgs) (err error) {
	// Defer a panic recover, so that in case we panic we can still return
	// a proper error to the runtime.
	defer func() {
		if e := recover(); e != nil {
			msg := fmt.Sprintf("Webmesh CNI panicked during DEL: %s\nStack trace:\n%s", e, string(debug.Stack()))
			if err != nil {
				// If we're recovering and there was also an error, then we need to
				// present both.
				msg = fmt.Sprintf("%s: error=%s", msg, err)
			}
			err = fmt.Errorf(msg)
		}
		if err != nil {
			log.Error("Final result of CNI DEL was an error", "error", err.Error())
			cnierr := types.Error{
				Code:    100,
				Msg:     "falied to run DEL command",
				Details: err.Error(),
			}
			cnierr.Print()
			os.Exit(1)
		}
	}()
	conf, err := loadConfigAndLogger(args)
	if err != nil {
		err = fmt.Errorf("failed to load config: %w", err)
		return
	}
	log.Debug("New DEL request", "config", conf, "args", args)
	cli, err := client.NewFromKubeconfig(conf.Kubernetes.Kubeconfig)
	if err != nil {
		err = fmt.Errorf("failed to create client: %w", err)
		return
	}
	err = cli.Ping(testConnectionTimeout)
	if err != nil {
		err = fmt.Errorf("failed to ping API server: %w", err)
		return
	}
	// Remove the interface from the container namespace.
	if args.Netns != "" {
		var containerNs ns.NetNS
		containerNs, err = ns.GetNS(args.Netns)
		if err != nil {
			err = fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
			return
		}
		defer containerNs.Close()
		if err = moveLinkOut(containerNs, args.IfName); err != nil {
			err = fmt.Errorf("failed to move link out of container namespace: %w", err)
			return
		}
	}
	// Delete the PeerContainer.
	container := &meshcniv1.PeerContainer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "PeerContainer",
			APIVersion: meshcniv1.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      args.ContainerID,
			Namespace: conf.Kubernetes.Namespace,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), testConnectionTimeout)
	defer cancel()
	err = cli.Delete(ctx, container)
	if err != nil && client.IgnoreNotFound(err) != nil {
		log.Error("Failed to delete PeerContainer", "error", err.Error())
	}
	fmt.Println("OK")
	return
}

func loadConfigAndLogger(args *skel.CmdArgs) (*NetConf, error) {
	var conf NetConf
	err := json.Unmarshal(args.StdinData, &conf)
	if err != nil {
		return nil, err
	}
	var writer io.Writer = os.Stdout
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
