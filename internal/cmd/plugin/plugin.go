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
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniSpecVersion "github.com/containernetworking/cni/pkg/version"
)

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
}

func init() {
	// This ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

// Main is the entrypoint for the webmesh-cni plugin.
func Main(version string) {
	skel.PluginMain(cmdAdd, cmdDummyCheck, cmdDel, cniSpecVersion.PluginSupports("0.1.0"), "Webmesh CNI plugin "+version)
}

// cmdAdd is the CNI ADD command handler.
func cmdAdd(args *skel.CmdArgs) (err error) {
	_, err = loadConfig(args)
	return err
}

// cmdDummyCheck is the CNI CHECK command handler.
func cmdDummyCheck(args *skel.CmdArgs) (err error) {
	fmt.Println("OK")
	return nil
}

// cmdDel is the CNI DEL command handler.
func cmdDel(args *skel.CmdArgs) (err error) {
	_, err = loadConfig(args)
	return err
}

func loadConfig(args *skel.CmdArgs) (*NetConf, error) {
	var conf NetConf
	err := json.Unmarshal(args.StdinData, &conf)
	if err != nil {
		return nil, err
	}
	return &conf, nil
}
