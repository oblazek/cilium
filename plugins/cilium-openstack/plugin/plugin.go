package plugin

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/defaults"
	endpointIDPkg "github.com/cilium/cilium/pkg/endpoint/id"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/k8s"
	k8sconfig "github.com/cilium/cilium/pkg/k8s/config"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	libvirt "github.com/libvirt/libvirt-go-module"

	"github.com/cilium/cilium/plugins/cilium-openstack/config"
	k8sClient "github.com/cilium/cilium/plugins/cilium-openstack/pkg/k8s"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-openstack-plugin")

type plugin struct {
	ciliumClient        *client.Client
	clientStatus        clientStatus
	libvirtConn         *libvirt.Connect
	k8sClient           *k8sClient.Client
	conf                models.DaemonConfigurationStatus
	hostname            string
	domainIfaceMappings map[string]map[string]bool
}

type clientStatus struct {
	ready bool
	err   error
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
		log.WithError(err).Fatal("Error while starting cilium-client")
		return err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	p := &plugin{
		ciliumClient:        c,
		clientStatus:        clientStatus{},
		hostname:            hostname,
		domainIfaceMappings: make(map[string]map[string]bool),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	k8s.Configure(config.Config.K8sAPIServer, config.Config.K8sKubeConfigPath, defaults.K8sClientQPSLimit, defaults.K8sClientBurst)

	if err := k8s.Init(k8sconfig.NewDefaultConfiguration()); err != nil {
		log.WithError(err).Fatal("Unable to connect to Kubernetes apiserver")
	}

	p.k8sClient = k8sClient.New()

	go p.runClientChecker(ctx)

	if err := p.waitUntilClientIsReady(30 * time.Second); err != nil {
		log.WithError(err).Fatal("Unable to connect to cilium daemon")
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

func (p *plugin) waitUntilClientIsReady(duration time.Duration) error {
	if duration > 0 {
		log.Info("Waiting for cilium daemon to start up...")
	}
	t := time.Now().Add(duration)
	for duration == 0 || time.Until(t) > 0 {
		if p.clientStatus.ready {
			return nil
		}
		log.Info("Sleeping, as cilium daemon is not ready...")
		time.Sleep(1 * time.Second)
	}
	return p.clientStatus.err
}

func (p *plugin) runClientChecker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	prevReady := false

	for {
		res, err := p.ciliumClient.ConfigGet()
		if err != nil {
			log.WithError(err).Error("Client is not ready")
			p.clientStatus.ready = false
			p.clientStatus.err = err
		} else if res != nil {
			if res.Status.Addressing == nil || (res.Status.Addressing.IPV4 == nil && res.Status.Addressing.IPV6 == nil) {
				p.clientStatus.ready = false
				p.clientStatus.err = fmt.Errorf("Invalid addressing information from daemon")
			} else {
				if !prevReady {
					p.conf = *res.Status
					log.Info("Connected to cilium daemon")
				}
				p.clientStatus.ready = true
				p.clientStatus.err = err
			}
		}
		prevReady = p.clientStatus.ready

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// just wait to next tick
			continue
		}
	}
}
