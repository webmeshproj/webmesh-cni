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

// Package version contains the build-time version information.
package version

import (
	"github.com/webmeshproj/webmesh/pkg/version"
)

// Compile-time variables set by the build script.
var (
	Version   = "0.0.0"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// GetBuildInfo returns the build-time version information.
func GetBuildInfo() version.BuildInfo {
	return version.BuildInfo{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
	}
}
