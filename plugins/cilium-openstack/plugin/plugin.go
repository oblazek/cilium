package plugin

import (
	"context"
	"os"
	"time"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/defaults"
	endpointIDPkg "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/k8s"
	k8sconfig "github.com/cilium/cilium/pkg/k8s/config"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	libvirt "github.com/libvirt/libvirt-go-module"

	"github.com/cilium/cilium/plugins/cilium-openstack/config"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-openstack-plugin")

type plugin struct {
	ciliumClient *client.Client
	daemonStatus daemonStatus
	libvirtConn  *libvirt.Connect
	k8sClient    *k8s.K8sClient
	hostname     string
	// domainIfaceMappings contains domainName/ifaceUUID/bool mapping
	// true value means the domain is present (is created)
	domainIfaceMappings map[string]map[string]bool
}

type daemonStatus struct {
	ready bool
}

func endpointID(id string) string {
	return endpointIDPkg.NewID(endpointIDPkg.ContainerIdPrefix, id)
}

// NewPlugin listens for libvirt events and
// synchronizes state of each openstack instance to cilium API
// using CILIUM_SOCK.
func NewPlugin() error {
	if config.Config.CiliumSockPath == "" {
		config.Config.CiliumSockPath = client.DefaultSockPath()
	}

	c, err := client.NewClient(config.Config.CiliumSockPath)
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize new cilium daemon client")
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	p := &plugin{
		ciliumClient:        c,
		daemonStatus:        daemonStatus{},
		hostname:            hostname,
		domainIfaceMappings: make(map[string]map[string]bool),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	k8s.Configure(config.Config.K8sAPIServer, config.Config.K8sKubeConfigPath, defaults.K8sClientQPSLimit, defaults.K8sClientBurst)

	if err := k8s.Init(k8sconfig.NewDefaultConfiguration()); err != nil {
		log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
	}

	p.k8sClient = k8s.Client()

	go p.runDaemonChecker(ctx)

	if config.Config.PrometheusServeAddr != "" {
		log.Infof("Serving prometheus metrics on %s", config.Config.PrometheusServeAddr)
		_ = metrics.Enable(config.Config.PrometheusServeAddr)
	}

	// Bridge mode
	if config.Config.PluginMode == "bridge" {
		log.Info("Running in bridge mode")
		err := p.runBridgeDaemon()
		if err != nil {
			log.WithError(err).Fatal("Error while starting bridge daemon")
			return err
		}
	} else {
		log.Info("Running in driver mode")
	}

	return nil
}

func (p *plugin) runDaemonChecker(ctx context.Context) {
	params := daemon.NewGetHealthzParamsWithTimeout(5 * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		res, err := p.ciliumClient.Daemon.GetHealthz(params)
		if err != nil {
			p.daemonStatus.ready = false
			log.Info("Waiting for cilium daemon")
		} else if res != nil {
			if res.Payload.Cilium.State == "Ok" {
				if !p.daemonStatus.ready {
					log.Info("Connected to cilium daemon")
					p.daemonStatus.ready = true
				}
			} else {
				log.Info("Agent not ok yet")
				p.daemonStatus.ready = false
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// just wait to next tick
			continue
		}
	}
}

func (p *plugin) isDaemonReady() bool {
	return p.daemonStatus.ready
}
