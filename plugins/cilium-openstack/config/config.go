package config

import (
	"github.com/cilium/cilium/plugins/cilium-openstack/defaults"
	"github.com/spf13/viper"
)

const (
	// AmqpURI ...
	AmqpURI = "amqp-uri"

	// CiliumAPI ...
	CiliumAPI = "cilium-api"

	// PluginMode ...
	PluginMode = "plugin-mode"

	// ClusterName ...
	ClusterName = "cluster-name"

	// DebugArg ...
	DebugArg = "debug"

	// LogDriver sets logging endpoints to use for example syslog, fluentd
	LogDriver = "log-driver"

	// LogOpt sets log driver options for cilium
	LogOpt = "log-opt"

	// ConfigDir ...
	ConfigDir = "config-dir"

	// ConfigFile ...
	ConfigFile = "config"

	// AmqpTLSCertFile specifies the path to the public key file for the
	// amqp server. The file must contain PEM encoded data.
	AmqpTLSCertFile = "amqp-tls-cert-file"

	// AmqpTLSKeyFile specifies the path to the private key file for the
	// amqp server. The file must contain PEM encoded data.
	AmqpTLSKeyFile = "amqp-tls-key-file"

	// AmqpTLSClientCAFiles specifies the path to one or more client CA
	// certificates to use for TLS with mutual authentication (mTLS). The files
	// must contain PEM encoded data.
	AmqpTLSClientCAFiles = "amqp-tls-client-ca-files"

	// AmqpMaxRetries ...
	AmqpMaxRetries = "amqp-max-retries"
)

// PluginConfig is the configuration used by cilium-openstack plugin
type PluginConfig struct {
	AmqpURI        string
	CiliumSockPath string
	Debug          bool
	LogDriver      []string
	LogOpt         map[string]string
	PluginMode     string
	ClusterName    string
	AmqpMaxRetries uint32
}

var (
	// Config represents the plugin config
	Config = &PluginConfig{
		PluginMode:     defaults.PluginMode,
		AmqpMaxRetries: defaults.AmqpMaxRetries,
	}
)

// Populate sets all options with the values from viper
func (c *PluginConfig) Populate() {
	c.AmqpURI = viper.GetString(AmqpURI)
	c.CiliumSockPath = viper.GetString(CiliumAPI)
	c.Debug = viper.GetBool(DebugArg)
	c.LogDriver = viper.GetStringSlice(LogDriver)
	c.PluginMode = viper.GetString(PluginMode)
	c.ClusterName = viper.GetString(ClusterName)
	c.AmqpMaxRetries = viper.GetUint32(AmqpMaxRetries)

	if m := viper.GetStringMapString(LogOpt); len(m) != 0 {
		c.LogOpt = m
	}
}
