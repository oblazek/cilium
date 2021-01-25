package config

import (
	"github.com/cilium/cilium/plugins/cilium-openstack/defaults"
	"github.com/spf13/viper"
)

const (
	// CiliumAPI ...
	CiliumAPI = "cilium-api"

	// PluginMode ...
	PluginMode = "plugin-mode"

	// ClusterName ...
	ClusterName = "cluster-name"

	// DebugArg ...
	DebugArg = "debug"

	// ConfigDir ...
	ConfigDir = "config-dir"

	// ConfigFile ...
	ConfigFile = "config"

	// K8sAPIServer is the kubernetes api address server (for https use --k8s-kubeconfig-path instead)
	K8sAPIServer = "k8s-api-server"

	// K8sKubeConfigPath is the absolute path of the kubernetes kubeconfig file
	K8sKubeConfigPath = "k8s-kubeconfig-path"
)

// PluginConfig is the configuration used by cilium-openstack plugin
type PluginConfig struct {
	CiliumSockPath    string
	Debug             bool
	PluginMode        string
	ClusterName       string
	K8sKubeConfigPath string
	K8sAPIServer      string
}

var (
	// Config represents the plugin config
	Config = &PluginConfig{
		PluginMode: defaults.PluginMode,
	}
)

// Populate sets all options with the values from viper
func (c *PluginConfig) Populate() {
	c.CiliumSockPath = viper.GetString(CiliumAPI)
	c.Debug = viper.GetBool(DebugArg)
	c.PluginMode = viper.GetString(PluginMode)
	c.ClusterName = viper.GetString(ClusterName)
	c.K8sKubeConfigPath = viper.GetString(K8sKubeConfigPath)
	c.K8sAPIServer = viper.GetString(K8sAPIServer)
}
