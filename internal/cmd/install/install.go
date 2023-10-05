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
	"flag"
	"log"
	"os"

	"github.com/webmeshproj/webmesh-cni/internal/types"
	"github.com/webmeshproj/webmesh-cni/internal/version"
)

// Main ensures the CNI binaries and configuration are installed on the host system.
func Main(version version.BuildInfo) {
	conf := types.LoadInstallOptionsFromEnv()
	conf.BindFlags(flag.CommandLine)
	flag.Parse()
	log.Printf("installing webmesh-cni, version: %s", version.String())
	err := conf.Validate()
	if err != nil {
		log.Println("install options are invalid:", err)
		os.Exit(1)
	}
	log.Printf("installing webmesh-cni with options:\n%s", conf.String())
	err = conf.RunInstall()
	if err != nil {
		log.Println("error running install:", err)
		os.Exit(1)
	}
	log.Println("webmesh-cni install complete!")
}
