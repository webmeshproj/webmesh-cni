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

//go:generate sh -x -c "go run sigs.k8s.io/controller-tools/cmd/controller-gen@latest object:headerFile='boilerplate.go.txt' paths='./...'"
//go:generate sh -x -c "go run sigs.k8s.io/controller-tools/cmd/controller-gen@latest crd webhook paths='./...' output:crd:artifacts:config=../../deploy/crds"

// Package v1 contains API Schema definitions for the  v1 API group
// +kubebuilder:object:generate=true
// +groupName=cni.webmesh.io
package v1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// FieldOwner is the field owner for CNI objects.
const FieldOwner = "webmesh-cni"

var (
	// GroupVersion is group version used to register these objects
	GroupVersion = schema.GroupVersion{Group: "cni.webmesh.io", Version: "v1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
