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
	"fmt"
	"runtime"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	cniSpecVersion "github.com/containernetworking/cni/pkg/version"
)

// How long we wait to see if we can contact the kubernetes API server for a command
// before giving up.
const testConnectionTimeout = 2 * time.Second

func init() {
	// this ensures that main runs only on main thread (thread group leader).
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
	return nil
}

// cmdDummyCheck is the CNI CHECK command handler.
func cmdDummyCheck(args *skel.CmdArgs) (err error) {
	fmt.Println("OK")
	return nil
}

// cmdDel is the CNI DEL command handler.
func cmdDel(args *skel.CmdArgs) (err error) {
	return nil
}
