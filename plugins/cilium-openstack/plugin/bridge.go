package plugin

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/plugins/cilium-openstack/config"
	libvirt "github.com/libvirt/libvirt-go-module"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
)

// Structure `domain` (and structures used in it) is based on class LibvirtConfigGuestMetaNovaInstance and method `_get_guest_config_meta/format_dom` =>
// https://github.com/openstack/nova/blob/b8cc5704558d3c08fda9db2f1bb7fecb2bcd985d/nova/virt/libvirt/driver.py#L5596
// Might change a little based on openstack version and it's patches.
type domain struct {
	Name     string   `xml:"name"`
	UUID     string   `xml:"uuid"`
	Metadata metadata `xml:"metadata"`
	Devices  devices  `xml:"devices"`
}

type metadata struct {
	Instance instance `xml:"instance"`
}

type instance struct {
	Name     string `xml:"name"`
	Owner    owner  `xml:"owner"`
	Metadata []meta `xml:"metadata"`
	Ports    port   `xml:"ports"`
}

type owner struct {
	User    string `xml:"user"`
	Project string `xml:"project"`
}

type meta struct {
	Name string `xml:"name,attr"`
	Text string `xml:",chardata"`
}

type port struct {
	Port []portIP `xml:"port"`
}

type portIP struct {
	UUID       string `xml:"uuid,attr"`
	IP         []ip   `xml:"ip"`
	SecGroupID []sgID `xml:"sg"`
}

type ip struct {
	IPVersion string `xml:"ipVersion,attr"`
	Address   string `xml:"address,attr"`
}

type sgID struct {
	ID string `xml:"id,attr"`
}

type devices struct {
	Iface []iface `xml:"interface"`
}

type iface struct {
	Type   string `xml:"type,attr"`
	Mac    mac    `xml:"mac"`
	Target target `xml:"target"`
}

type mac struct {
	Address string `xml:"address,attr"`
}

type target struct {
	Dev string `xml:"dev,attr"`
}

func (p *plugin) cbLifecycle(c *libvirt.Connect, d *libvirt.Domain, event *libvirt.DomainEventLifecycle) {
	switch event.Event {
	case libvirt.DOMAIN_EVENT_DEFINED:
		if d != nil {
			err := p.registerDomain(*d)
			if err != nil {
				log.Error(err)
			}
		}
	case libvirt.DOMAIN_EVENT_UNDEFINED:
		if d != nil {
			err := p.unregisterDomain(*d)
			if err != nil {
				log.Error(err)
			}
		}
	default:
		return
	}

	log.Debugf("vm lifecycle changed")
}

func (p *plugin) cbMetadadaChanged(c *libvirt.Connect, d *libvirt.Domain, event *libvirt.DomainEventMetadataChange) {
	dom, err := d.GetName()
	if err != nil {
		log.Error(err)
	}

	log.Debugf("vm metadata changed: %s", dom)

	if d != nil {
		err = p.registerDomain(*d)
		if err != nil {
			log.Error(err)
		}
	}
}

func (p *plugin) runBridgeDaemon() error {
	ctx := context.Background()
	defer ctx.Done()

	// this is the standard way the libvirt library works
	// without this event's won't get captured
	libvirt.EventRegisterDefaultImpl()
	go func() {
		for {
			err := libvirt.EventRunDefaultImpl()
			if err != nil {
				log.Error(err)
			}
		}
	}()
	//

	conn, err := libvirt.NewConnect("qemu+unix:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
	}
	defer conn.Close()

	p.libvirtConn = conn

	// run once on startup, then handle each event
	p.dumpAndRegisterDomains(ctx)

	//go func() {
	//	ticker := time.NewTicker(5 * time.Minute)

	//	for {
	//		select {
	//		case <-ctx.Done():
	//			ticker.Stop()
	//		case <-ticker.C:
	//			//p.runPeriodicalEndpointCleanup(ctx)
	//		}
	//	}
	//}()

	_, err = conn.DomainEventLifecycleRegister(nil, p.cbLifecycle)
	if err != nil {
		log.Error("failed to register domain lifecycle event: ", err)
	}
	_, err = conn.DomainEventMetadataChangeRegister(nil, p.cbMetadadaChanged)
	if err != nil {
		log.Error("failed to register domain metadata changed event: ", err)
	}

	log.Infof("Cilium openstack plugin ready")

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)

	<-sigterm

	log.Info("Exiting due to signal")
	return nil
}

func (p *plugin) getLibvirtDumpedDomain(dom *libvirt.Domain) (*domain, error) {
	var domxml string
	var err error
	domxml, err = dom.GetXMLDesc(libvirt.DOMAIN_XML_SECURE)
	if err != nil {
		return nil, err
	}

	d := &domain{}

	// read our xml data as a byte array.
	byteValue := []byte(domxml)
	err = xml.Unmarshal(byteValue, d)
	return d, err
}

func (p *plugin) dumpAndRegisterDomains(ctx context.Context) {
	// list all domains / update existing endpoints
	domains, err := p.libvirtConn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)
	if err != nil {
		log.Fatalf("failed to retrieve domains: %v", err)
	}

	for _, d := range domains {
		dName, err := d.GetName()
		if err != nil {
			log.Errorf("failed to get domain name: ", err)
		}
		log.Debugf("Registering %s", dName)
		err = p.registerDomain(d)
		if err != nil {
			log.Error(err)
		}
	}
}

func (p *plugin) registerDomain(d libvirt.Domain) error {
	dom, err := p.getLibvirtDumpedDomain(&d)
	if err != nil {
		return fmt.Errorf("unable to domain dumpxml: %v", err)
	}

	return p.updateOrCreateDomain(dom)
}

func (p *plugin) unregisterDomain(d libvirt.Domain) error {
	name, err := d.GetName()
	if err != nil {
		return err
	}

	return p.deleteDomain(name)
}

func (p *plugin) runPeriodicalEndpointCleanup() {
	// TODO (oblazek)
	// if this plugin fails, user might detach or destroy vm
	// and as we might miss it, we need to get it from cilium
	// and clean it up
}

func (p *plugin) updateOrCreateDomain(dom *domain) error {
	var err error

	if _, ok := p.domainIfaceMappings[dom.Name]; !ok {
		// no domain to iface mapping exists, new vm
		p.domainIfaceMappings[dom.Name] = map[string]bool{}
	}
	// update existing endpoint as it's metadata might have changed
	// or create a new one
	for idx, iface := range dom.Metadata.Instance.Ports.Port {
		lbls := p.getPortBasedLabels(dom.Metadata.Instance, iface.SecGroupID)
		if _, ok := p.domainIfaceMappings[dom.Name][iface.UUID]; !ok {
			err = p.createNewEndpoint(iface.UUID, lbls, dom, idx)
			if err != nil {
				log.Warn(err)
			}
		}
		// labels might have been updated
		err = p.updateExistingEndpoint(iface.UUID, lbls)
		if err != nil {
			log.Warn(err)
		}
		// store domain<->iface mapping
		p.domainIfaceMappings[dom.Name][iface.UUID] = true
	}

	// need to loop across domainIfaceMappings as iface might have been removed
	// which means CEP has to be deleted
	if val, ok := p.domainIfaceMappings[dom.Name]; ok {
		for ifaceUUID, registered := range val {
			if !registered {
				p.deleteEndpoint(ifaceUUID)
				delete(p.domainIfaceMappings[dom.Name], ifaceUUID)
			} else {
				val[ifaceUUID] = false
			}
		}
		log.Debugf("Domain %s registered", dom.Name)
	}
	return err
}

func (p *plugin) deleteDomain(domName string) error {
	var err error
	if val, ok := p.domainIfaceMappings[domName]; ok {
		for ifaceUUID := range val {
			err = p.deleteEndpoint(ifaceUUID)
			if err != nil {
				log.Error(err)
			}
		}
	}
	delete(p.domainIfaceMappings, domName)
	return err

}

func (p *plugin) createNewEndpoint(uuid string, lbls models.Labels, domain *domain, idx int) error {
	ifaceName := domain.Devices.Iface[idx].Target.Dev
	ifaceData, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.WithFields(
			logrus.Fields{
				"endpoint-id": uuid,
				"error":       err,
			}).
			Error("Error while getting netlink data")
		return err
	}

	addressPair := &models.AddressPair{}

	// handle both IPs attached to this iface
	for _, ip := range domain.Metadata.Instance.Ports.Port[idx].IP {
		if ip.IPVersion == "4" {
			addressPair.IPV4 = ip.Address
		} else {
			addressPair.IPV6 = ip.Address
		}
	}

	// TODO (oblazek/bocim/jmraz) figure out why we cannot do EndpointCreate in 1 step (with labels)
	// but we have to do also EndpointPatch with lables to have Identity correctly assigned and to have State ready
	// otherwise we have endpoint stuck (until some e.g. label update) in waiting-for-identity and `<no label id>`
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
			// this has to be set to true for dhcp to work properly
			// and so that source IP exiting endpoint is not checked
			DisableSipVerification: true,
			// this means that icmpv6 NS handling is
			// skipped when leaving the ep which is what we need
			// for ipv6 to work correctly
			InstallEndpointRoute: true,
		},
		State:          models.EndpointStateWaitingForIdentity,
		ContainerID:    uuid,
		ContainerName:  uuid,
		Mac:            domain.Devices.Iface[idx].Mac.Address,
		HostMac:        domain.Devices.Iface[idx].Mac.Address,
		InterfaceName:  ifaceName,
		InterfaceIndex: int64(ifaceData.Attrs().Index),
		Addressing:     addressPair,
	}

	if err := p.ciliumClient.EndpointCreate(endpoint); err != nil {
		log.WithFields(
			logrus.Fields{
				"endpoint-id": uuid,
				"error":       err,
			}).
			Warn("Error while creating the endpoint")
		return err
	}

	log.WithField(logfields.EndpointID, uuid).Debug("Created new endpoint")
	return err
}

func (p *plugin) updateExistingEndpoint(domainUUID string, lbls models.Labels) error {
	log.Debugf("New labels: %v for endpoint %v", lbls, domainUUID)

	ecr := &models.EndpointChangeRequest{
		SyncBuildEndpoint: false,
		State:             models.EndpointStateWaitingForIdentity,
		ContainerID:       domainUUID,
		Labels:            lbls,
	}

	err := p.ciliumClient.EndpointPatch(endpointID(ecr.ContainerID), ecr)
	if err != nil && err.Error() == endpoint.NewPatchEndpointIDNotFound().Error() {
		log.WithFields(
			logrus.Fields{
				"endpoint-uuid": domainUUID,
				"labels":        lbls,
				"error":         err,
			}).
			Warn("Unable to patch endpoint, endpoint not found")
		return err
	}
	log.WithField(logfields.Endpoint, ecr.ContainerID).Debug("Patched endpoint succesfully")
	return nil
}

func (p *plugin) deleteEndpoint(domainUUID string) error {
	err := p.ciliumClient.EndpointDelete(endpointID(domainUUID))
	if err != nil {
		log.WithFields(
			logrus.Fields{
				"endpoint-id": domainUUID,
				"error":       err,
			}).
			Error("Error while deleting the endpoint")
		return err
	}
	log.WithField(logfields.EndpointID, domainUUID).Debug("Deleted endpoint succesfully")
	return nil
}

func (p *plugin) getPortBasedLabels(instanceMetadata instance, sgIDs []sgID) models.Labels {
	lbls := map[string]string{}
	for _, l := range instanceMetadata.Metadata {
		lbls[l.Name] = l.Text
	}

	for _, id := range sgIDs {
		lbls["sgID."+id.ID] = "true"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ns, err := p.k8sClient.GetNamespace(ctx, instanceMetadata.Owner.Project)
	if err != nil {
		log.Error("failed to get namespace from k8s: ", err)
	} else {
		nsMap := ns.GetLabels()
		if realm, ok := nsMap["scif.cz/realm"]; ok {
			lbls["realm"] = realm
		}
	}
	// set instance labels and project name / namespace
	// there is currently no other option than to use const with k8s in it
	lbls[k8sConst.PodNamespaceLabel] = instanceMetadata.Owner.Project
	lbls[k8sConst.PolicyLabelCluster] = config.Config.ClusterName

	return labels.Map2Labels(lbls, labels.LabelSourceOpenstack).GetModel()
}
