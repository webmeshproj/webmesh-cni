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
	"os"

	"github.com/webmeshproj/webmesh-cni/internal/cmd/install"
	"github.com/webmeshproj/webmesh-cni/internal/cmd/node"
	"github.com/webmeshproj/webmesh-cni/internal/cmd/plugin"
	"github.com/webmeshproj/webmesh-cni/internal/version"
)

func main() {
	// We run the entrypoint based on how we were invoked.
	exec, err := os.Executable()
	if err != nil {
		panic(err)
	}
	switch exec {
	case "webmesh":
		plugin.Main(version.Version)
	case "webmesh-cni-node":
		node.Main(version.Version)
	case "webmesh-cni-install":
		install.Main(version.Version)
	default:
		panic("unknown executable")
	}
}
