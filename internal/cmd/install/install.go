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

// Package install contains the entrypoint for the webmesh-cni install component.
package install

import (
	"log"
	"os"

	"github.com/webmeshproj/webmesh-cni/internal/types"
	"github.com/webmeshproj/webmesh-cni/internal/version"
)

// Main ensures the CNI binaries and configuration are installed on the host system.
func Main(version version.BuildInfo) {
	log.Printf("installing webmesh-cni, version: %+v", version)
	conf, err := types.LoadInstallOptionsFromEnv()
	if err != nil {
		log.Println("error loading install options from environment:", err)
		os.Exit(1)
	}
	err = conf.RunInstall()
	if err != nil {
		log.Println("error running install:", err)
		os.Exit(1)
	}
	log.Println("webmesh-cni install complete!")
}
