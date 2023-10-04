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
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	cniversion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/webmeshproj/webmesh-cni/internal/types"
	"github.com/webmeshproj/webmesh-cni/internal/version"
)

//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/finalizers,verbs=update

// TODO: Make these configurable.
const (
	// How long we wait to try to ping the API server before giving up.
	testConnectionTimeout = time.Second * 2
	// How long we wait to try to create the peer container instance.
	createPeerContainerTimeout = time.Second * 2
	// How long to wait for the controller to setup the container interface.
	setupContainerInterfaceTimeout = time.Second * 10
)

func init() {
	// This ensures that main runs only on the main thread (thread group leader).
	// Since namespace ops (unshare, setns) are done for a single thread, we must
	// ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

// Main is the entrypoint for the webmesh-cni plugin.
func Main(version version.BuildInfo) {
	skel.PluginMain(
		cmdAdd,
		cmdCheck,
		cmdDel,
		cniversion.PluginSupports("0.3.1"),
		"Webmesh CNI plugin "+version.Version,
	)
}

// cmdAdd is the CNI ADD command handler.
func cmdAdd(args *skel.CmdArgs) (err error) {
	// Defer a panic recover, so that in case we panic we can still return
	// a proper error to the runtime.
	log := slog.Default()
	result := &cniv1.Result{}
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
			cnierr := cnitypes.Error{
				Code:    100,
				Msg:     "failed to run ADD command",
				Details: err.Error(),
			}
			cnierr.Print()
			os.Exit(1)
		}
		log.Info("Returning CNI result", "result", result)
		err = cnitypes.PrintResult(result, result.CNIVersion)
		if err != nil {
			log.Error("Failed to print CNI result", "error", err.Error())
			cnierr := cnitypes.Error{
				Code:    100,
				Msg:     "failed to print CNI result",
				Details: err.Error(),
			}
			cnierr.Print()
			os.Exit(1)
		}
	}()
	conf, err := types.LoadNetConfFromArgs(args)
	if err != nil {
		err = fmt.Errorf("failed to load config: %w", err)
		return
	}
	log = conf.NewLogger(args)
	result.CNIVersion = conf.CNIVersion
	// Use the host DNS servers?
	// TODO: We can run a DNS server on the mesh node.
	result.DNS = conf.DNS
	log.Debug("Handling new ADD request")
	cli, err := conf.NewClient(testConnectionTimeout)
	if err != nil {
		err = fmt.Errorf("failed to create client: %w", err)
		return
	}
	// Check if we've already created a PeerContainer for this container.
	log.Debug("Ensuring PeerContainer exists")
	ctx, cancel := context.WithTimeout(context.Background(), createPeerContainerTimeout)
	defer cancel()
	err = cli.EnsureContainer(ctx, args)
	if err != nil {
		log.Error("Failed to ensure PeerContainer", "error", err.Error())
		err = fmt.Errorf("failed to ensure PeerContainer: %w", err)
		return
	}
	// Wait for the PeerContainer to be ready.
	// TODO: Put into client.
	log.Debug("Waiting for PeerContainer to be ready")
	ctx, cancel = context.WithTimeout(context.Background(), setupContainerInterfaceTimeout)
	defer cancel()
	peerContainer, err := cli.WaitForRunning(ctx, args)
	if err != nil {
		log.Error("Failed to wait for PeerContainer to be ready", "error", err.Error())
		err = fmt.Errorf("failed to wait for PeerContainer to be ready: %w", err)
		return
	}
	ifname := peerContainer.Status.InterfaceName
	// Parse the IP addresses from the container status.
	log.Debug("Building container interface result from status", "status", peerContainer.Status)
	err = peerContainer.AppendToResults(result)
	if err != nil {
		log.Error("Failed to build container interface result from status", "error", err.Error())
		err = fmt.Errorf("failed to build container interface result from status: %w", err)
		return
	}
	// Move the wireguard interface to the container namespace.
	log.Debug("Moving wireguard interface to container namespace")
	containerNs, err := ns.GetNS(args.Netns)
	if err != nil {
		err = fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
		return
	}
	defer containerNs.Close()
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		err = fmt.Errorf("failed to find %q: %v", ifname, err)
		return
	}
	contDev, err := moveLinkIn(link, containerNs, ifname)
	if err != nil {
		err = fmt.Errorf("move link to container namespace: %v", err)
		return
	}
	result.Interfaces = []*cniv1.Interface{{
		Name:    contDev.Attrs().Name,
		Mac:     contDev.Attrs().HardwareAddr.String(),
		Sandbox: containerNs.Path(),
	}}
	return
}

// cmdCheck is the CNI CHECK command handler.
// Most implementations do a dummy check like this.
// TODO: This should be used to check if there are new routes to track.
func cmdCheck(args *skel.CmdArgs) (err error) {
	// Defer a panic recover, so that in case we panic we can still return
	// a proper error to the runtime.
	log := slog.Default()
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
			cnierr := cnitypes.Error{
				Code:    100,
				Msg:     "failed to run CHECK command",
				Details: err.Error(),
			}
			cnierr.Print()
			os.Exit(1)
		}
	}()
	conf, err := types.LoadNetConfFromArgs(args)
	if err != nil {
		err = fmt.Errorf("failed to load config: %w", err)
		return
	}
	log = conf.NewLogger(args)
	log.Debug("Handling new CHECK request")
	_, err = conf.NewClient(testConnectionTimeout)
	if err != nil {
		err = fmt.Errorf("failed to create client: %w", err)
		return
	}
	fmt.Println("OK")
	return
}

// cmdDel is the CNI DEL command handler.
func cmdDel(args *skel.CmdArgs) (err error) {
	// Defer a panic recover, so that in case we panic we can still return
	// a proper error to the runtime.
	log := slog.Default()
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
			cnierr := cnitypes.Error{
				Code:    100,
				Msg:     "failed to run DEL command",
				Details: err.Error(),
			}
			cnierr.Print()
			os.Exit(1)
		}
	}()
	conf, err := types.LoadNetConfFromArgs(args)
	if err != nil {
		err = fmt.Errorf("failed to load config: %w", err)
		return
	}
	log = conf.NewLogger(args)
	log.Debug("Handling new DEL request")
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
	log.Debug("Deleting PeerContainer", "container", conf.ObjectKeyFromArgs(args))
	cli, err := conf.NewClient(testConnectionTimeout)
	if err != nil {
		err = fmt.Errorf("failed to create client: %w", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), testConnectionTimeout)
	defer cancel()
	err = cli.DeletePeerContainer(ctx, args)
	if err != nil && client.IgnoreNotFound(err) != nil {
		log.Error("Failed to delete PeerContainer", "error", err.Error())
	}
	fmt.Println("OK")
	return
}
