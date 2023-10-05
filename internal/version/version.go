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

import "encoding/json"

// Compile-time variables set by the build script.
var (
	Version   = "0.0.0"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// BuildInfo contains the build-time version information.
type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
}

// GetBuildInfo returns the build-time version information.
func GetBuildInfo() BuildInfo {
	return BuildInfo{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
	}
}

// String returns a string representation of the build-time version information.
func (b BuildInfo) String() string {
	out, _ := json.Marshal(b)
	return string(out)
}
