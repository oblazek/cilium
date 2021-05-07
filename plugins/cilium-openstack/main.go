// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/plugins/cilium-openstack/config"
	"github.com/cilium/cilium/plugins/cilium-openstack/defaults"
	"github.com/cilium/cilium/plugins/cilium-openstack/plugin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	binaryName = filepath.Base(os.Args[0])
	log        = logging.DefaultLogger.WithField(logfields.LogSubsys, binaryName)

	// RootCmd represents the base command when called without any subcommands
	RootCmd = &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cmd *cobra.Command, args []string) {

			initEnv(cmd)

			if err := plugin.NewPlugin(); err != nil {
				log.WithError(err).Fatal("Unable to create cilium-openstack driver")
			}
		},
	}
)

func main() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(option.InitConfig("Cilium", "cilium-openstack"))
	flags := RootCmd.Flags()

	// Environment bindings
	flags.BoolP(config.DebugArg, "D", false, "Enable debug messages")
	option.BindEnv(config.DebugArg)

	flags.String(config.CiliumAPI, "", "URI to server-side API")
	option.BindEnv(config.CiliumAPI)

	flags.String(config.AmqpURI, "", "URI to amqp server")
	option.BindEnv(config.AmqpURI)

	flags.String(config.PluginMode, defaults.PluginMode, "Mode in which this plugin should run")
	option.BindEnv(config.PluginMode)

	flags.String(config.ClusterName, "", "Name of the cluster where plugin is running")
	option.BindEnv(config.ClusterName)

	flags.String(config.ConfigFile, "", `Configuration file (default "$HOME/cilium-openstack.yaml")`)
	option.BindEnv(config.ConfigFile)

	flags.String(config.ConfigDir, "", `Configuration directory that contains a file for each option`)
	option.BindEnv(config.ConfigDir)

	flags.String(config.AmqpTLSCertFile, "", "Path to the public key file for the Amqp server. The file must contain PEM encoded data.")
	option.BindEnv(config.AmqpTLSCertFile)

	flags.String(config.AmqpTLSKeyFile, "", "Path to the private key file for the Amqp server. The file must contain PEM encoded data.")
	option.BindEnv(config.AmqpTLSKeyFile)

	flags.StringSlice(config.AmqpTLSClientCAFiles, []string{}, "Paths to one or more public key files of client CA certificates to use for TLS. The files must contain PEM encoded data.")
	option.BindEnv(config.AmqpTLSClientCAFiles)

	flags.Uint(config.AmqpMaxRetries, defaults.AmqpMaxRetries, "Maximum number of retries to consume an event.")
	option.BindEnv(config.AmqpMaxRetries)

	viper.BindPFlags(flags)
}

func initEnv(cmd *cobra.Command) {
	// Prepopulate option.Config with options from CLI.
	config.Config.Populate()

	option.LogRegisteredOptions(log)

	logging.SetupLogging(config.Config.LogDriver, logging.LogOptions(config.Config.LogOpt), binaryName, config.Config.Debug)
}
