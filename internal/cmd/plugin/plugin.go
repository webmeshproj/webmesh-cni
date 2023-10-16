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
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	cniversion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/vishvananda/netlink"
	"github.com/webmeshproj/webmesh/pkg/version"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/webmeshproj/webmesh-cni/internal/types"
)

//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cni.webmesh.io,resources=peercontainers/finalizers,verbs=update

// TODO: Make these configurable.
const (
	// How long we wait to try to ping the API server before giving up.
	testConnectionTimeout = time.Second * 2
	// How long we wait to try to create the peer container instance.
	createPeerContainerTimeout = time.Second * 3
	// How long to wait for the controller to setup the container interface.
	setupContainerInterfaceTimeout = time.Second * 15
)

// Main is the entrypoint for the webmesh-cni plugin.
func Main(version version.BuildInfo) {
	// Defer a panic recover, so that in case we panic we can still return
	// a proper error to the runtime.
	defer func() {
		if e := recover(); e != nil {
			msg := fmt.Sprintf("Webmesh CNI panicked: %s\nStack trace:\n%s", e, string(debug.Stack()))
			cnierr := cnitypes.Error{
				Code:    100,
				Msg:     "Webmesh CNI panicked",
				Details: msg,
			}
			cnierr.Print()
			os.Exit(1)
		}
	}()
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
	log := slog.Default()
	result := &cniv1.Result{}
	defer func() {
		if err != nil {
			log.Error("Final result of CNI ADD was an error", "error", err.Error())
			cnierr := cnitypes.Error{
				Code:    100,
				Msg:     "error setting up interface",
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
	result.DNS = conf.DNS
	log.Debug("Handling new container add request")
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
	if len(peerContainer.Status.DNSServers) > 0 {
		// We need to create a special resolv conf for the network namespace.
		log.Debug("Creating resolv.conf for container namespace")
		resolvConfPath := filepath.Join("/etc/netns", filepath.Base(args.Netns), "resolv.conf")
		err := os.MkdirAll(filepath.Dir(resolvConfPath), 0755)
		if err != nil {
			err = fmt.Errorf("failed to create resolv.conf directory: %w", err)
			return err
		}
		resolvConf, err := os.Create(resolvConfPath)
		if err != nil {
			err = fmt.Errorf("failed to create resolv.conf: %w", err)
			return err
		}
		defer resolvConf.Close()
		for _, dnsServer := range peerContainer.Status.DNSServers {
			_, err = resolvConf.WriteString(fmt.Sprintf("nameserver %s\n", dnsServer))
			if err != nil {
				err = fmt.Errorf("failed to write to resolv.conf: %w", err)
				return err
			}
		}
	}
	// Get the interface details from the container namespace and ensure IP forwarding is enabled.
	log.Debug("Getting interface details from container namespace")
	containerNs, err := ns.GetNS(args.Netns)
	if err != nil {
		err = fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
		return
	}
	defer containerNs.Close()
	err = containerNs.Do(func(_ ns.NetNS) (err error) {
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			err = fmt.Errorf("failed to find %q: %v", ifname, err)
			return
		}
		result.Interfaces = []*cniv1.Interface{{
			Name:    link.Attrs().Name,
			Mac:     link.Attrs().HardwareAddr.String(),
			Sandbox: containerNs.Path(),
		}}
		if !conf.Interface.DisableIPv6 {
			log.Debug("Enabling IPv6 forwarding")
			_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/forwarding", link.Attrs().Name), "1")
		}
		if !conf.Interface.DisableIPv4 {
			log.Debug("Enabling IPv4 forwarding")
			_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv4/conf/%s/forwarding", link.Attrs().Name), "1")
		}
		return
	})
	return
}

// cmdCheck is the CNI CHECK command handler. Most implementations do a dummy check like this.
// TODO: This could be used to check if there are new routes to track.
func cmdCheck(args *skel.CmdArgs) (err error) {
	log := slog.Default()
	defer func() {
		if err != nil {
			log.Error("Final result of CNI CHECK was an error", "error", err.Error())
			cnierr := cnitypes.Error{
				Code:    100,
				Msg:     "error checking interface",
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
	log := slog.Default()
	defer func() {
		if err != nil {
			log.Error("Final result of CNI DEL was an error", "error", err.Error())
			cnierr := cnitypes.Error{
				Code:    100,
				Msg:     "error deleting interface",
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
		err = fmt.Errorf("failed to delete PeerContainer: %w", err)
		return
	}
	fmt.Println("OK")
	return
}
