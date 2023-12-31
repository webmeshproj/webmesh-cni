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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mitchellh/mapstructure"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrl "sigs.k8s.io/controller-runtime"
)

// InstallOptions are the options for the install component.
type InstallOptions struct {
	// Kubeconfig is the kubeconfig to use for the plugin.
	Kubeconfig string `json:"kubeconfig" mapstructure:"kubeconfig"`
	// SourceBinary is the path to the source binary.
	SourceBinary string `json:"sourceBinary" mapstructure:"sourceBinary"`
	// BinaryDestBin is the destination directory for the CNI binaries.
	BinaryDestBin string `json:"binaryDestBin" mapstructure:"binaryDestBin"`
	// ConfDestDir is the destination directory for the CNI configuration.
	ConfDestDir string `json:"confDestDir" mapstructure:"confDestDir"`
	// ConfDestName is the name of the CNI configuration file.
	ConfDestName string `json:"confDestName" mapstructure:"confDestName"`
	// HostLocalNetDir is the directory containing host-local IPAM allocations.
	// We release these when we start for the first time.
	HostLocalNetDir string `json:"hostLocalNetDir" mapstructure:"hostLocalNetDir"`
	// NetConfTemplate is the template for the CNI configuration.
	NetConfTemplate string `json:"netConfTemplate" mapstructure:"netConfTemplate"`
	// NodeName is the name of the node we are running on.
	NodeName string `json:"nodeName" mapstructure:"nodeName"`
	// Namespace is the namespace to use for the plugin.
	Namespace string `json:"namespace" mapstructure:"namespace"`
	// DryRun is whether or not to run in dry run mode.
	DryRun bool `json:"dryRun" mapstructure:"dryRun"`
}

// String returns a string representation of the install options.
func (i *InstallOptions) String() string {
	mapstruct := map[string]any{}
	err := mapstructure.Decode(i, &mapstruct)
	if err != nil {
		return fmt.Sprintf("error decoding install options: %s", err.Error())
	}
	delete(mapstruct, "netConfTemplate")
	confTempl := map[string]any{}
	err = json.Unmarshal([]byte(i.NetConfTemplate), &confTempl)
	if err == nil {
		mapstruct["netConfTemplate"] = confTempl
	} else {
		mapstruct["netConfTemplate"] = "error parsing netconf template: " + err.Error()
	}
	out, _ := json.MarshalIndent(mapstruct, "", "  ")
	return string(out)
}

// BindFlags binds the install options to the given flag set.
func (i *InstallOptions) BindFlags(fs *flag.FlagSet) {
	fs.BoolVar(&i.DryRun, "dry-run", i.DryRun, "whether or not to run in dry run mode")
	fs.StringVar(&i.SourceBinary, "source-binary", i.SourceBinary, "path to the source binary (default: current executable)")
	fs.StringVar(&i.BinaryDestBin, "binary-dest-bin", i.BinaryDestBin, "destination directory for the CNI binaries")
	fs.StringVar(&i.ConfDestDir, "conf-dest-dir", i.ConfDestDir, "destination directory for the CNI configuration")
	fs.StringVar(&i.ConfDestName, "conf-dest-name", i.ConfDestName, "name of the CNI configuration file")
	fs.StringVar(&i.HostLocalNetDir, "host-local-net-dir", i.HostLocalNetDir, "directory containing host-local IPAM allocations to clear, leave this empty to disable")
	fs.StringVar(&i.NodeName, "node-name", i.NodeName, "name of the node we are running on")
	fs.StringVar(&i.Namespace, "namespace", i.Namespace, "namespace to use for the plugin")
	fs.Func("netconf-template", "template file for the CNI configuration", func(fname string) error {
		data, err := os.ReadFile(fname)
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
		i.NetConfTemplate = string(data)
		return nil
	})
}

// getExecutable is the function for retrieving the current executable.
// This is overridden in tests.
var getExecutable = os.Executable

// LoadInstallOptionsFromEnv loads the install options from the environment.
func LoadInstallOptionsFromEnv() *InstallOptions {
	var opts InstallOptions
	opts.Kubeconfig = envOrDefault(KubeconfigEnvVar, "")
	opts.NodeName = envOrDefault(NodeNameEnvVar, "")
	opts.HostLocalNetDir = envOrDefault(CNINetDirEnvVar, os.Getenv(CNINetDirEnvVar))
	opts.Namespace = envOrDefault(PodNamespaceEnvVar, DefaultNamespace)
	opts.BinaryDestBin = envOrDefault(DestBinEnvVar, DefaultDestBin)
	opts.ConfDestDir = envOrDefault(DestConfEnvVar, DefaultDestConfDir)
	opts.ConfDestName = envOrDefault(DestConfFileNameEnvVar, DefaultDestConfFilename)
	opts.NetConfTemplate = os.Getenv(NetConfTemplateEnvVar)
	opts.SourceBinary, _ = getExecutable()
	if dryrun, ok := os.LookupEnv(DryRunEnvVar); ok {
		opts.DryRun = dryrun == "true" || dryrun == "1"
	}
	return &opts
}

func envOrDefault(env, def string) string {
	if val, ok := os.LookupEnv(env); ok {
		return val
	}
	return def
}

func (i *InstallOptions) Default() {
	if i.SourceBinary == "" {
		i.SourceBinary, _ = getExecutable()
	}
	if i.BinaryDestBin == "" {
		i.BinaryDestBin = DefaultDestBin
	}
	if i.ConfDestDir == "" {
		i.ConfDestDir = DefaultDestConfDir
	}
	if i.ConfDestName == "" {
		i.ConfDestName = DefaultDestConfFilename
	}
	if i.Namespace == "" {
		i.Namespace, _ = GetInClusterNamespace()
	}
}

func (i *InstallOptions) Validate() error {
	i.Default()
	if i.SourceBinary == "" {
		return fmt.Errorf("source binary not set")
	}
	if i.BinaryDestBin == "" {
		return fmt.Errorf("binary destination directory not set")
	}
	if i.ConfDestDir == "" {
		return fmt.Errorf("configuration destination directory not set")
	}
	if i.ConfDestName == "" {
		return fmt.Errorf("configuration destination name not set")
	}
	if i.NetConfTemplate == "" {
		return fmt.Errorf("CNI configuration template not set")
	}
	if i.NodeName == "" {
		return fmt.Errorf("node name not set")
	}
	if i.Namespace == "" {
		return fmt.Errorf("%s not set and unable to get in-cluster namespace", PodNamespaceEnvVar)
	}
	err := json.Unmarshal([]byte(i.NetConfTemplate), &struct{}{})
	if err != nil {
		return fmt.Errorf("CNI configuration template is not proper JSON: %w", err)
	}
	return nil
}

// getInstallRestConfig is the function for retrieving the REST config during installation.
// This is overridden in tests.
var getInstallRestConfig = ctrl.GetConfig

// RunInstall is an alias for running all install steps.
func (i *InstallOptions) RunInstall() error {
	var apicfg *rest.Config
	var err error
	if i.Kubeconfig == "" {
		log.Println("no kubeconfig provided, trying to auto-detect")
		apicfg, err = getInstallRestConfig()
		if err != nil {
			log.Println("error getting kubeconfig:", err)
			return err
		}
	} else {
		log.Println("using kubeconfig provided at", i.Kubeconfig)
		apicfg, err = clientcmd.BuildConfigFromKubeconfigGetter("", func() (*clientcmdapi.Config, error) {
			return clientcmd.LoadFromFile(i.Kubeconfig)
		})
		if err != nil {
			log.Println("error getting kubeconfig:", err)
			return err
		}
	}
	// Clear any local host IPAM allocations that already exist.
	if i.HostLocalNetDir != "" {
		log.Println("clearing host-local IPAM allocations from", i.HostLocalNetDir)
		if !i.DryRun {
			err = i.ClearHostLocalIPAMAllocations()
			if err != nil {
				log.Println("error clearing host-local IPAM allocations:", err)
				return err
			}
		}
	}
	pluginBin := filepath.Join(i.BinaryDestBin, PluginBinaryName)
	log.Println("installing plugin binary to -> ", pluginBin)
	if !i.DryRun {
		err = i.InstallPlugin(pluginBin)
		if err != nil {
			log.Println("error installing plugin:", err)
			return err
		}
	}
	kubeconfigPath := filepath.Join(i.ConfDestDir, PluginKubeconfigName)
	log.Println("installing kubeconfig to destination -> ", kubeconfigPath)
	if !i.DryRun {
		err = i.InstallKubeconfig(kubeconfigPath)
		if err != nil {
			log.Println("error writing kubeconfig:", err)
			return err
		}
	}
	log.Println("rendering CNI configuration")
	netConf := i.RenderNetConf(apicfg.Host, strings.TrimPrefix(kubeconfigPath, "/host"))
	log.Println("effective CNI configuration ->\n", netConf)
	confPath := filepath.Join(i.ConfDestDir, i.ConfDestName)
	log.Println("installing CNI configuration to destination -> ", confPath)
	if !i.DryRun {
		err = i.InstallNetConf(confPath, netConf)
		if err != nil {
			log.Println("error writing netconf:", err)
			return err
		}
	}
	return nil
}

// ClearHostLocalIPAMAllocations removes any host-local CNI plugins from the CNI configuration.
func (i *InstallOptions) ClearHostLocalIPAMAllocations() error {
	dir, err := os.ReadDir(i.HostLocalNetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("error reading host-local CNI directory: %w", err)
	}
	for _, file := range dir {
		// Skip parent directory.
		if file.Name() == filepath.Base(i.HostLocalNetDir) {
			continue
		}
		err = os.RemoveAll(filepath.Join(i.HostLocalNetDir, file.Name()))
		if err != nil {
			return fmt.Errorf("error removing host-local CNI plugin: %w", err)
		}
	}
	return nil
}

// InstallPlugin installs the plugin.
func (i *InstallOptions) InstallPlugin(dest string) error {
	if err := installPluginBinary(i.SourceBinary, dest); err != nil {
		log.Printf("error installing binary to %s: %v", dest, err)
		return err
	}
	return nil
}

// InstallNetConf installs the CNI configuration.
func (i *InstallOptions) InstallNetConf(path string, config string) error {
	if err := os.WriteFile(path, []byte(config), 0644); err != nil {
		log.Println("error writing CNI configuration:", err)
		return err
	}
	return nil
}

// RenderNetConf renders the CNI configuration.
func (i *InstallOptions) RenderNetConf(apiEndpoint string, kubeconfig string) string {
	conf := i.NetConfTemplate
	conf = strings.Replace(conf, NodeNameReplaceStr, i.NodeName, -1)
	conf = strings.Replace(conf, PodNamespaceReplaceStr, i.Namespace, -1)
	conf = strings.Replace(conf, APIEndpointReplaceStr, apiEndpoint, -1)
	conf = strings.Replace(conf, KubeconfigFilepathReplaceStr, kubeconfig, -1)
	return conf
}

// InstallKubeconfig writes the kubeconfig file for the plugin.
func (i *InstallOptions) InstallKubeconfig(kubeconfigPath string) error {
	kubeconfig, err := i.GetKubeconfig()
	if err != nil {
		return fmt.Errorf("error getting kubeconfig: %w", err)
	}
	if err := clientcmd.WriteToFile(kubeconfig, kubeconfigPath); err != nil {
		log.Println("error writing kubeconfig:", err)
		return err
	}
	return nil
}

// GetKubeconfig tries to build a kubeconfig from the current in cluster
// configuration.
func (i *InstallOptions) GetKubeconfig() (clientcmdapi.Config, error) {
	// If our cert data is empty, convert it to the contents of the cert file.
	cfg, err := getInstallRestConfig()
	if err != nil {
		return clientcmdapi.Config{}, fmt.Errorf("error getting config: %w", err)
	}
	return KubeconfigFromRestConfig(cfg, i.Namespace)
}

// KubeconfigFromRestConfig returns a kubeconfig from the given rest config.
// It reads in any files and encodes them as base64 in the final configuration.
// GetKubeconfig tries to build a kubeconfig from the current in cluster
// configuration.
func KubeconfigFromRestConfig(cfg *rest.Config, namespace string) (clientcmdapi.Config, error) {
	if cfg.CAFile != "" {
		caData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return clientcmdapi.Config{}, fmt.Errorf("error reading certificate authority data: %w", err)
		}
		cfg.CAData = caData
	}
	// If our bearer token is a file, convert it to the contents of the file.
	if cfg.BearerTokenFile != "" {
		token, err := os.ReadFile(cfg.BearerTokenFile)
		if err != nil {
			return clientcmdapi.Config{}, fmt.Errorf("error reading bearer token: %w", err)
		}
		cfg.BearerToken = string(token)
	}
	// If our client certificate is a file, convert it to the contents of the file.
	if cfg.CertFile != "" {
		cert, err := os.ReadFile(cfg.CertFile)
		if err != nil {
			log.Println("error reading client certificate:", err)
			return clientcmdapi.Config{}, fmt.Errorf("error reading client certificate: %w", err)
		}
		cfg.CertData = cert
	}
	// Same for any key
	if cfg.KeyFile != "" {
		key, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			log.Println("error reading client key:", err)
			return clientcmdapi.Config{}, fmt.Errorf("error reading client key: %w", err)
		}
		cfg.KeyData = key
	}
	return clientcmdapi.Config{
		Kind:       "Config",
		APIVersion: "v1",
		Clusters: map[string]*clientcmdapi.Cluster{
			KubeconfigContextName: {
				Server:                   cfg.Host,
				TLSServerName:            cfg.ServerName,
				InsecureSkipTLSVerify:    cfg.Insecure,
				CertificateAuthorityData: cfg.CAData,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			KubeconfigContextName: {
				ClientCertificateData: cfg.CertData,
				ClientKeyData:         cfg.KeyData,
				Token:                 cfg.BearerToken,
				Impersonate:           cfg.Impersonate.UserName,
				ImpersonateGroups:     cfg.Impersonate.Groups,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			KubeconfigContextName: {
				Cluster:   KubeconfigContextName,
				AuthInfo:  KubeconfigContextName,
				Namespace: namespace,
			},
		},
		CurrentContext: KubeconfigContextName,
	}, nil
}

var setSuidBit = setSuidBitToFile

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

func setSuidBitToFile(file string) error {
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

// inClusterNamespacePath is the path to the namespace file in the pod.
// Declared as a variable for testing.
var inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// GetInClusterNamespace returns the namespace of the pod we are running in.
func GetInClusterNamespace() (string, error) {
	// Load the namespace file and return its content
	namespace, err := os.ReadFile(inClusterNamespacePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("namespace file does not exist, not running in-cluster")
		}
		return "", fmt.Errorf("error reading namespace file: %w", err)
	}
	return string(bytes.TrimSpace(namespace)), nil
}
