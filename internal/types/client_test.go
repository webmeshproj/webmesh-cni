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

package types

import (
	"testing"
	"time"

	storagev1 "github.com/webmeshproj/storage-provider-k8s/api/storage/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestClient(t *testing.T) {
	_ = setupClientTest(t)
}

func setupClientTest(t *testing.T) *rest.Config {
	t.Helper()
	t.Log("Starting test environment")
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zap.Options{Development: true})))
	testenv := envtest.Environment{
		CRDInstallOptions:        envtest.CRDInstallOptions{},
		ErrorIfCRDPathMissing:    true,
		CRDs:                     storagev1.GetCustomResourceDefintions(),
		CRDDirectoryPaths:        []string{"../../deploy/crds"},
		ControlPlaneStartTimeout: time.Second * 30,
		ControlPlaneStopTimeout:  time.Second * 3,
	}
	cfg, err := testenv.Start()
	if err != nil {
		t.Fatal("Failed to start test environment", err)
	}
	t.Cleanup(func() {
		t.Log("Stopping test environment")
		err := testenv.Stop()
		if err != nil {
			t.Log("Failed to stop test environment", err)
		}
	})
	return cfg
}
