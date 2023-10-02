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
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	// KubernetesAPIEndpointEnvVar is the name of the environment variable that contains the Kubernetes API endpoint.
	KubernetesAPIEndpointEnvVar = "KUBERNETES_API_ENDPOINT"
	// NetConfEnvVar is the name of the environment variable that contains the CNI configuration.
	NetConfEnvVar = "CNI_NETWORK_CONFIG"
	// NetConfFileName is the name of the file that contains the CNI configuration.
	NetConfFileNameEnvVar = "CNI_CONF_NAME"
	// NodeNameEnvVar is the name of the environment variable that contains the node name.
	NodeNameEnvVar = "KUBERNETES_NODE_NAME"
	// BinaryDestBinEnvVar is the destination directory for the CNI binaries.
	BinaryDestBinEnvVar = "CNI_BIN_DIR"
	// BinaryDestConfEnvVar is the destination directory for the CNI configuration.
	BinaryDestConfEnvVar = "CNI_CONF_DIR"
	// PodNamespaceEnvVar is the name of the environment variable that contains the pod namespace.
	PodNamespaceEnvVar = "K8S_POD_NAMESPACE"
	// PluginBinaryName is the name of the plugin binary.
	PluginBinaryName = "webmesh"
)

// Main ensures the CNI binaries and configuration are installed on the host system.
func Main(version string) {
	log.Println("installing webmesh-cni")
	// Make sure all the required environment variables are set.
	if err := checkEnv(); err != nil {
		log.Println("error checking environment:", err)
		os.Exit(1)
	}
	// Get the current executable path
	exec, err := os.Executable()
	if err != nil {
		log.Println("error getting executable path:", err)
		os.Exit(1)
	}
	// Copy the binary to the destination directory.
	if err := installPluginBinary(exec, os.Getenv(BinaryDestBinEnvVar)); err != nil {
		log.Println("error copying binary:", err)
		os.Exit(1)
	}
	// Write a kubeconfig file to the destination directory.
	kubeconfigPath := filepath.Join(os.Getenv(BinaryDestBinEnvVar), "webmesh-kubeconfig")
	cfg := ctrl.GetConfigOrDie()
	clientconfig := clientcmdapi.Config{
		Kind:       "Config",
		APIVersion: "v1",
		Clusters: map[string]*clientcmdapi.Cluster{
			"webmesh-cni": {
				Server:                   os.Getenv("KUBERNETES_API_ENDPOINT"),
				TLSServerName:            cfg.ServerName,
				InsecureSkipTLSVerify:    cfg.Insecure,
				CertificateAuthority:     cfg.CAFile,
				CertificateAuthorityData: cfg.CertData,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"webmesh-cni": {
				ClientCertificate: cfg.CertFile,
				ClientKey:         cfg.KeyFile,
				Token:             cfg.BearerToken,
				Impersonate:       cfg.Impersonate.UserName,
				ImpersonateGroups: cfg.Impersonate.Groups,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"webmesh-cni": {
				Cluster:  "webmesh-cni",
				AuthInfo: "webmesh-cni",
			},
		},
		CurrentContext: "webmesh-cni",
	}
	if err := clientcmd.WriteToFile(clientconfig, kubeconfigPath); err != nil {
		log.Println("error writing kubeconfig:", err)
		os.Exit(1)
	}
	// Do necessary string replacements on the CNI configuration.
	conf := os.Getenv(NetConfEnvVar)
	conf = strings.Replace(conf, "__KUBERNETES_NODE_NAME__", os.Getenv(NodeNameEnvVar), -1)
	conf = strings.Replace(conf, "__K8S_POD_NAMESPACE__", os.Getenv(PodNamespaceEnvVar), -1)
	conf = strings.Replace(conf, "__KUBERNETES_API_ENDPOINT__", os.Getenv("KUBERNETES_API_ENDPOINT"), -1)
	conf = strings.Replace(conf, "__KUBECONFIG_FILEPATH__", kubeconfigPath, -1)
	// Write the CNI configuration to the destination directory.
	confPath := filepath.Join(os.Getenv(BinaryDestConfEnvVar), os.Getenv(NetConfFileNameEnvVar))
	if err := os.WriteFile(confPath, []byte(conf), 0644); err != nil {
		log.Println("error writing CNI configuration:", err)
		os.Exit(1)
	}
	log.Println("webmesh-cni install complete")
}

// installPluginBinary copies the binary to the destination directory.
func installPluginBinary(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("error opening binary: %w", err)
	}
	defer f.Close()
	// Create the destination directory if it doesn't exist.
	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("error creating destination directory: %w", err)
	}
	// Create the destination file.
	dst := filepath.Join(dest, PluginBinaryName)
	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("error creating destination file: %w", err)
	}
	defer out.Close()
	// Copy the binary to the destination file.
	if _, err := io.Copy(out, f); err != nil {
		return fmt.Errorf("error copying binary: %w", err)
	}
	// Make the destination file executable.
	if err := os.Chmod(dst, 0755); err != nil {
		return fmt.Errorf("error making destination file executable: %w", err)
	}
	return nil
}

// checkEnv ensures all the required environment variables are set.
func checkEnv() error {
	for _, envvar := range []string{
		KubernetesAPIEndpointEnvVar,
		NetConfEnvVar,
		NetConfFileNameEnvVar,
		NodeNameEnvVar,
		BinaryDestBinEnvVar,
		BinaryDestConfEnvVar,
		PodNamespaceEnvVar,
	} {
		if _, ok := os.LookupEnv(envvar); !ok {
			return fmt.Errorf("environment variable %q is not set", envvar)
		}
	}
	return nil
}