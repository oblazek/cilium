package plugin

import (
	"os"
	"time"

	endpointIDPkg "github.com/cilium/cilium/pkg/endpoint/id"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/cilium/cilium/plugins/cilium-openstack/config"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cilium-openstack-plugin")

type plugin struct {
	mutex      lock.RWMutex
	client     *client.Client
	amqpClient *amqpClient
	conf       models.DaemonConfigurationStatus
	hostname   string
}

func endpointID(id string) string {
	return endpointIDPkg.NewID(endpointIDPkg.ContainerIdPrefix, id)
}

// NewPlugin listens for messages for the given Amqp URI and
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
		client:     c,
		hostname:   hostname,
		amqpClient: &amqpClient{},
	}

	maxTries := 10
	for tries := 0; tries < maxTries; tries++ {
		if res, err := c.ConfigGet(); err != nil {
			if tries == (maxTries - 1) {
				log.WithError(err).Fatal("Unable to connect to cilium daemon")
			} else {
				log.Info("Waiting for cilium daemon to start up...")
			}
			time.Sleep(time.Duration(tries) * time.Second)
		} else {
			if res.Status.Addressing == nil || (res.Status.Addressing.IPV4 == nil && res.Status.Addressing.IPV6 == nil) {
				log.Fatal("Invalid addressing information from daemon")
			}

			log.Info("Connected to cilium daemon")
			p.conf = *res.Status
			break
		}
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
