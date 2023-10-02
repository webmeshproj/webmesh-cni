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
	"runtime"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
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
	PodNamespaceEnvVar = "KUBERNETES_POD_NAMESPACE"
	// NodeNameReplaceStr is the string that will be replaced in the CNI configuration with the node name.
	NodeNameReplaceStr = "__KUBERNETES_NODE_NAME__"
	// PodNamespaceReplaceStr is the string that will be replaced in the CNI configuration with the pod namespace.
	PodNamespaceReplaceStr = "__KUBERNETES_POD_NAMESPACE__"
	// KubeAPIEndpointReplaceStr is the string that will be replaced in the CNI configuration with the Kubernetes API endpoint.
	APIEndpointReplaceStr = "__KUBERNETES_API_ENDPOINT__"
	// KubeconfigFilepathReplaceStr is the string that will be replaced in the CNI configuration with the kubeconfig filepath.
	KubeconfigFilepathReplaceStr = "__KUBECONFIG_FILEPATH__"
	// HostLocalNetDir is the directory containing host-local CNI plugins. We remove these plugins from the CNI configuration.
	HostLocalNetDir = "/var/lib/cni/networks"
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
	log.Println("using source executable path:", exec)
	// Clear any local host IPAM allocations that already exist.
	log.Println("clearing host-local IPAM allocations from", HostLocalNetDir)
	if err := clearHostLocalNetDir(); err != nil {
		log.Println("error clearing host-local IPAM allocations:", err)
		os.Exit(1)
	}
	// Copy the binary to the destination directory.
	destBin := os.Getenv(BinaryDestBinEnvVar)
	pluginBin := filepath.Join(destBin, PluginBinaryName)
	log.Println("installing plugin binary to -> ", pluginBin)
	if err := installPluginBinary(exec, pluginBin); err != nil {
		log.Printf("error installing binary to %s: %v", pluginBin, err)
		os.Exit(1)
	}
	err = os.Chdir(destBin)
	if err != nil {
		log.Printf("error changing directory to %s: %v", destBin, err)
		os.Exit(1)
	}
	for _, symlinkName := range []string{"loopback", "host-local"} {
		log.Println("creating symlink for ->", filepath.Join(destBin, symlinkName))
		err = os.Symlink(PluginBinaryName, symlinkName)
		if err != nil {
			log.Printf("error creating symlink for %s: %v", symlinkName, err)
			os.Exit(1)
		}
	}
	// Write a kubeconfig file to the destination directory.
	kubeconfigPath := filepath.Join(destBin, "webmesh-kubeconfig")
	cfg := ctrl.GetConfigOrDie()
	clientconfig := clientcmdapi.Config{
		Kind:       "Config",
		APIVersion: "v1",
		Clusters: map[string]*clientcmdapi.Cluster{
			"webmesh-cni": {
				Server:                   cfg.Host,
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
	log.Println("installing kubeconfig to destination -> ", kubeconfigPath)
	if err := clientcmd.WriteToFile(clientconfig, kubeconfigPath); err != nil {
		log.Println("error writing kubeconfig:", err)
		os.Exit(1)
	}
	// Do necessary string replacements on the CNI configuration.
	conf := os.Getenv(NetConfEnvVar)
	conf = strings.Replace(conf, NodeNameReplaceStr, os.Getenv(NodeNameEnvVar), -1)
	conf = strings.Replace(conf, PodNamespaceReplaceStr, os.Getenv(PodNamespaceEnvVar), -1)
	conf = strings.Replace(conf, APIEndpointReplaceStr, cfg.Host, -1)
	conf = strings.Replace(conf, KubeconfigFilepathReplaceStr, strings.TrimPrefix(kubeconfigPath, "/host"), -1)
	// Write the CNI configuration to the destination directory.
	confPath := filepath.Join(os.Getenv(BinaryDestConfEnvVar), os.Getenv(NetConfFileNameEnvVar))
	log.Println("effective CNI configuration ->\n", conf)
	log.Println("installing CNI configuration to -> ", confPath)
	if err := os.WriteFile(confPath, []byte(conf), 0644); err != nil {
		log.Println("error writing CNI configuration:", err)
		os.Exit(1)
	}
	log.Println("webmesh-cni install complete!")
}

// clearHostLocalNetDir removes any host-local CNI plugins from the CNI configuration.
func clearHostLocalNetDir() error {
	dir, err := os.ReadDir(HostLocalNetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("error reading host-local CNI directory: %w", err)
	}
	for _, file := range dir {
		// Skip parent directory.
		if file.Name() == filepath.Base(HostLocalNetDir) {
			continue
		}
		err = os.RemoveAll(filepath.Join(HostLocalNetDir, file.Name()))
		if err != nil {
			return fmt.Errorf("error removing host-local CNI plugin: %w", err)
		}
	}
	return nil
}

// installPluginBinary copies the binary to the destination directory.
func installPluginBinary(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("error opening binary: %w", err)
	}
	defer f.Close()
	// Create the destination directory if it doesn't exist.
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("error creating destination directory: %w", err)
	}
	// Create the destination file.
	out, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("error creating destination file: %w", err)
	}
	// Copy the binary to the destination file.
	if _, err := io.Copy(out, f); err != nil {
		return fmt.Errorf("error copying binary: %w", err)
	}
	err = out.Close()
	if err != nil {
		return fmt.Errorf("error closing destination file: %w", err)
	}
	// Make the destination file executable.
	if err := os.Chmod(dest, 0755); err != nil {
		return fmt.Errorf("error making destination file executable: %w", err)
	}
	return setSuidBit(dest)
}

// checkEnv ensures all the required environment variables are set.
func checkEnv() error {
	for _, envvar := range []string{
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

func setSuidBit(file string) error {
	if runtime.GOOS == "windows" {
		// chmod doesn't work on windows
		log.Println("chmod doesn't work on windows, skipping setSuidBit()")
		return nil
	}
	fi, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("failed to stat file: %s", err)
	}
	err = os.Chmod(file, fi.Mode()|os.FileMode(uint32(8388608)))
	if err != nil {
		return fmt.Errorf("failed to chmod file: %s", err)
	}
	return nil
}
