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

// Package cni contains the plugin implementation for the webmesh-cni.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/webmeshproj/webmesh-cni/internal/cmd/install"
	"github.com/webmeshproj/webmesh-cni/internal/cmd/node"
	"github.com/webmeshproj/webmesh-cni/internal/cmd/plugin"
	"github.com/webmeshproj/webmesh-cni/internal/version"
)

func init() {
	// This ensures that main runs only on the main thread (thread group leader).
	// Since namespace ops (unshare, setns) are done for a single thread, we must
	// ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func main() {
	// We run the entrypoint based on how we were invoked.
	version := version.GetBuildInfo()
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version.PrettyJSON(func() string {
			switch filepath.Base(os.Args[0]) {
			case "webmesh":
				return "webmesh-cni"
			case "webmesh-cni-node", "webmesh-node":
				return "webmesh-cni-node"
			case "webmesh-cni-install":
				return "webmesh-cni-install"
			default:
				return filepath.Base(os.Args[0])
			}
		}()))
		os.Exit(0)
	}
	switch filepath.Base(os.Args[0]) {
	case "webmesh":
		plugin.Main(version)
	case "webmesh-cni":
		// This is a package installation. Run either install or node
		// depending on the first argument.
		var cmd string
		if len(os.Args) > 1 {
			cmd = os.Args[1]
			// Pop the command from the args.
			if len(os.Args) > 2 {
				os.Args = append(os.Args[:1], os.Args[2:]...)
			} else {
				os.Args = os.Args[:1]
			}
		}
		switch cmd {
		case "install":
			install.Main(version)
		case "node":
			node.Main(version)
		default:
			// Default to the plugin.
			plugin.Main(version)
		}
	case "webmesh-cni-node", "webmesh-node":
		node.Main(version)
	case "webmesh-cni-install":
		install.Main(version)
	default:
		// Default to the plugin.
		plugin.Main(version)
	}
}
