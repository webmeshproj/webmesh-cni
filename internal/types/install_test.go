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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/rest"
)

func TestInstallCNI(t *testing.T) {
	// Setup temp directories
	setSuidBit = func(string) error {
		return nil
	}
	getInstallRestConfig = func() (*rest.Config, error) {
		return &rest.Config{}, nil
	}
	i := NewTestInstallation(t, "TODO")
	opts := i.Options()
	err := opts.RunInstall()
	if err != nil {
		t.Fatal(err)
	}
	i.ValidateInstallation(t)
}

type TestInstallation struct {
	SourceDir        string
	SourceBinaryName string
	BinaryDestDir    string
	ConfDestDir      string
	ConfDestName     string
	ConfTemplate     string
	HostLocalNetDir  string
}

func NewTestInstallation(t *testing.T, confTemplate string) *TestInstallation {
	t.Helper()
	var i TestInstallation
	var err error
	i.ConfTemplate = confTemplate
	i.SourceDir, err = os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	// Write a fake source binary
	err = os.WriteFile(i.SourceDir+"/source-bin", []byte("test"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	i.SourceBinaryName = "source-bin"
	t.Cleanup(func() { os.RemoveAll(i.SourceDir) })
	i.BinaryDestDir, err = os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(i.BinaryDestDir) })
	i.ConfDestDir, err = os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	i.ConfDestName = "test-conf"
	t.Cleanup(func() { os.RemoveAll(i.ConfDestDir) })
	i.HostLocalNetDir, err = os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(i.HostLocalNetDir) })
	return &i
}

func (i *TestInstallation) Options() *InstallOptions {
	return &InstallOptions{
		SourceBinary:    filepath.Join(i.SourceDir, i.SourceBinaryName),
		BinaryDestBin:   i.BinaryDestDir,
		ConfDestDir:     i.ConfDestDir,
		ConfDestName:    i.ConfDestName,
		HostLocalNetDir: i.HostLocalNetDir,
		NetConfTemplate: i.ConfTemplate,
		NodeName:        "test-node",
		Namespace:       "test-namespace",
	}
}

func (i *TestInstallation) ValidateInstallation(t *testing.T) {
	t.Helper()
	// Check that the binary was copied
	installedBin := filepath.Join(i.BinaryDestDir, PluginBinaryName)
	data, err := os.ReadFile(installedBin)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("test")) {
		t.Fatal("Expected binary to be copied, got", string(data))
	}
	// Check that a kubeconfig exists.
	kubeconfigPath := filepath.Join(i.ConfDestDir, PluginKubeconfigName)
	_, err = os.Stat(kubeconfigPath)
	if err != nil {
		t.Fatal(err)
	}
	// Check that the config was written
	confPath := filepath.Join(i.ConfDestDir, i.ConfDestName)
	data, err = os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte(i.ConfTemplate)) {
		t.Fatal("Expected config to be written, got", string(data))
	}
}
