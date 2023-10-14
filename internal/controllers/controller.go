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

// Package controllers contains the controllers for the webmesh-cni.
package controllers

//go:generate sh -x -c "go run sigs.k8s.io/controller-tools/cmd/controller-gen@latest rbac:roleName=webmesh-cni-role webhook paths='./...' output:rbac:artifacts:config=../../deploy/rbac"
