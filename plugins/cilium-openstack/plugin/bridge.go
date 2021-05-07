package plugin

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
	"github.com/streadway/amqp"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/plugins/cilium-openstack/config"
	"github.com/cilium/cilium/plugins/cilium-openstack/types"
)

type amqpClient struct {
	connection *amqp.Connection
}

func (c *amqpClient) Connect() error {
	conn, err := amqp.DialConfig(config.Config.AmqpURI, amqp.Config{})
	if err != nil {
		return err
	}
	c.connection = conn
	return nil
}

func (c *amqpClient) Channel() (*amqp.Channel, error) {
	if c.connection == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
	}
	ch, err := c.connection.Channel()
	if err != nil {
		return nil, err
	}

	return ch, nil
}

func (c *amqpClient) QueueDeclare(ch *amqp.Channel, queueName string) error {
	_, err := ch.QueueDeclare(
		queueName, // name
		false,     // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		return err
	}
	return nil
}

func (c *amqpClient) Close() error {
	if c.connection != nil {
		return c.connection.Close()
	}
	return nil
}

func (p *plugin) runBridgeDaemon() error {
	// Start a new amqp consumer and consume messages
	if err := p.amqpClient.Connect(); err != nil {
		return err
	}
	defer p.amqpClient.Close()

	ch, err := p.amqpClient.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()

	// declare compute queue
	computeQueueName := fmt.Sprintf("versioned_notifications_%s.info", p.hostname)
	if err := p.amqpClient.QueueDeclare(ch, computeQueueName); err != nil {
		return err
	}

	// declare controller queue
	controlQueueName := "versioned_notifications.info"
	if err := p.amqpClient.QueueDeclare(ch, controlQueueName); err != nil {
		return err
	}

	// Start consuming messages from message bus of a local compute
	computeEvents, err := ch.Consume(
		computeQueueName, // queue
		"",               // consumer
		false,            // auto-ack
		false,            // exclusive
		false,            // no-local
		false,            // no-wait
		nil,              // args
	)
	if err != nil {
		return err
	}

	// Start consuming messages from message bus of a local compute
	ctlEvents, err := ch.Consume(
		controlQueueName, // queue
		"",               // consumer
		false,            // auto-ack
		false,            // exclusive
		false,            // no-local
		false,            // no-wait
		nil,              // args
	)
	if err != nil {
		return err
	}

	log.Info("Starting openstack events watcher")

	// Handle messages based on EventType from compute
	forever := make(chan bool)
	go func() {
		for data := range computeEvents {
			log.Debugf("Consuming message from compute")
			if err := p.handleEvent(&data); err != nil {
				log.WithError(err).Debug("Failed to handle event")
			}
		}
	}()

	// Handle messages from controller(s)
	go func() {
		for data := range ctlEvents {
			log.Debugf("Consuming message from controller")
			if err := p.handleEvent(&data); err != nil {
				log.WithError(err).Debug("Failed to handle event")
			}
		}
	}()

	log.Infof("Cilium openstack plugin ready")
	<-forever
	return nil
}

func (p *plugin) handleEvent(data *amqp.Delivery) error {
	eventData := decodeData(data.Body)
	// check if this is event targeted for this host
	if eventData.Payload.NovaObjectData.Host != p.hostname {
		return nil
	}

	switch eventData.EventType {
	case types.CreateEvent:
		for i := uint32(1); i <= config.Config.AmqpMaxRetries; i++ {
			// try to create an endpoint and retry on fail, but only config.Config.AmqpMaxRetries times
			if err := p.createEndpoint(eventData); err != nil {
				time.Sleep(time.Duration(i) * time.Second)
				continue
			}
			break
		}
		// ack on success
		if err := data.Ack(false); err != nil {
			return err
		}

		// atm the only way to force cilium-agent to resolve identity for endpoint outside of k8s
		return p.updateEndpoint(eventData)
	case types.UpdateEvent:
		// types.UpdateEvent is sent also during instance spawning
		if eventData.Payload.NovaObjectData.StateUpdate.NovaObjectData.NewState == nil && eventData.Payload.NovaObjectData.StateUpdate.NovaObjectData.OldState != "building" {
			_ = p.updateEndpoint(eventData)
		}
	case types.DeleteEvent:
		// can be 404 if endpoint doesn't exist in cilium but no need to handle that
		_ = p.deleteEndpoint(eventData)
	}
	// ack successfuly handled events
	return data.Ack(false)
}

func decodeData(data []byte) osloMessageInner {
	var messageData osloMessageOuter
	err := json.Unmarshal(data, &messageData)
	if err != nil {
		log.Error("Unable to unmarshall data")
	}

	log.Debug(messageData)

	var messageInnerData osloMessageInner
	err = json.Unmarshal([]byte(messageData.OsloMessage), &messageInnerData)
	if err != nil {
		log.Error("Unable to unmarshall inner data")
	}
	return messageInnerData
}

func (p *plugin) createEndpoint(data osloMessageInner) error {
	var create osloMessageInner
	log.WithField(logfields.Request, logfields.Repr(&create)).Debug("Create endpoint request")

	ifaceName := data.Payload.NovaObjectData.IPAddresses[0].NovaObjectData.DeviceName
	ifaceData, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.WithFields(
			logrus.Fields{
				"endpoint-id": create.Payload.NovaObjectData.UUID,
				"error":       err,
			}).
			Error("Error while creating the endpoint")
		return err
	}

	addressPair := &models.AddressPair{}
	for _, ip := range data.Payload.NovaObjectData.IPAddresses {
		if ip.NovaObjectData.Version == 4 {
			addressPair.IPV4 = ip.NovaObjectData.Address
		} else {
			addressPair.IPV6 = ip.NovaObjectData.Address
		}
	}

	endpoint := &models.EndpointChangeRequest{
		SyncBuildEndpoint: false,
		DatapathConfiguration: &models.EndpointDatapathConfiguration{
			// this needs to be set to true since we still rely on
			// calico ipam and cilium would not restore this ep
			// in case it was forced to restart which can be quite
			// common
			ExternalIpam: true,
			// Arp passthrough has to be enabled for openstack vms
			RequireArpPassthrough: true,
			RequireDHCPMessages:   true,
		},
		State:          models.EndpointStateWaitingForIdentity,
		ContainerID:    data.Payload.NovaObjectData.UUID,
		ContainerName:  data.Payload.NovaObjectData.DisplayName,
		Mac:            data.Payload.NovaObjectData.IPAddresses[0].NovaObjectData.Mac,
		HostMac:        data.Payload.NovaObjectData.IPAddresses[0].NovaObjectData.Mac,
		InterfaceName:  ifaceName,
		InterfaceIndex: int64(ifaceData.Attrs().Index),
		Addressing:     addressPair,
	}

	if err := p.client.EndpointCreate(endpoint); err != nil {
		log.WithFields(
			logrus.Fields{
				"endpoint-id": create.Payload.NovaObjectData.UUID,
				"error":       err,
			}).
			Error("Error while creating the endpoint")
		return err
	}

	log.WithField(logfields.EndpointID, create.Payload.NovaObjectData.UUID).Debug("Created new endpoint")
	return nil
}

func (p *plugin) updateEndpoint(data osloMessageInner) error {
	log.Debugf("New labels: %v for endpoint %v", data.Payload.NovaObjectData.Metadata, data.Payload.NovaObjectData.UUID)

	var epID string
	if data.Payload.NovaObjectData.UUID == "" {
		return nil
	}
	epID = data.Payload.NovaObjectData.UUID

	lbls := p.getLabels(&data)

	ecr := &models.EndpointChangeRequest{
		SyncBuildEndpoint: false,
		State:             models.EndpointStateWaitingForIdentity,
		ContainerID:       epID,
		Labels:            lbls,
	}

	err := p.client.EndpointPatch(endpointID(epID), ecr)
	if err != nil {
		log.WithFields(
			logrus.Fields{
				"endpoint-id": epID,
				"labels":      lbls,
				"error":       err,
			}).
			Error("Error while patching the endpoint labels of an instance")
		return err
	}
	log.WithField(logfields.EndpointID, data.Payload.NovaObjectData.UUID).Debug("Patched endpoint succesfully")
	return nil
}

func (p *plugin) deleteEndpoint(data osloMessageInner) error {
	var epID = data.Payload.NovaObjectData.UUID

	err := p.client.EndpointDelete(endpointID(epID))
	if err != nil {
		log.WithFields(
			logrus.Fields{
				"endpoint-id": epID,
				"error":       err,
			}).
			Error("Error while deleting the endpoint")
		return err
	}
	log.WithField(logfields.EndpointID, data.Payload.NovaObjectData.UUID).Debug("Deleted endpoint succesfully")
	return nil
}

func (p *plugin) getLabels(data *osloMessageInner) models.Labels {
	lbls := data.Payload.NovaObjectData.Metadata

	// set instance labels and project name / namespace
	// there is currently no other option than to use const with k8s in it
	lbls[k8sConst.PodNamespaceLabel] = data.ContextProjectName
	lbls[k8sConst.PolicyLabelCluster] = config.Config.ClusterName

	return labels.Map2Labels(lbls, labels.LabelSourceOpenstack).GetModel()
}

type osloMessageOuter struct {
	OsloMessage string `json:"oslo.message"`
}

type osloMessageInner struct {
	Priority           string      `json:"priority"`
	EventType          string      `json:"event_type"`
	PublisherID        string      `json:"publisher_id"`
	ContextProjectName string      `json:"_context_project_name"`
	Payload            payloadData `json:"payload"`
}

type stateUpdatePayload struct {
	NovaObjectData stateUpdatePayloadData `json:"nova_object.data"`
}

type stateUpdatePayloadData struct {
	NewState *string `json:"new_task_state"`
	OldState string  `json:"old_state"`
}

type payloadData struct {
	NovaObjectName string                `json:"nova_object.name"`
	NovaObjectData instanceCreatePayload `json:"nova_object.data"`
}

type instanceCreatePayload struct {
	DisplayName  string             `json:"display_name"`
	InstanceName string             `json:"instance_name"`
	IPAddresses  []ipPayload        `json:"ip_addresses"`
	Hostname     string             `json:"host_name"`
	Host         string             `json:"host"`
	State        string             `json:"state"`
	UUID         string             `json:"uuid"`
	Metadata     map[string]string  `json:"metadata"`
	StateUpdate  stateUpdatePayload `json:"state_update"`
}

type ipPayload struct {
	NovaObjectData ipPayloadData `json:"nova_object.data"`
	NovaObjectName string        `json:"nova_object.name"`
}

type ipPayloadData struct {
	Address    string `json:"address"`
	DeviceName string `json:"device_name"`
	Mac        string `json:"mac"`
	Version    uint   `json:"version"`
}
