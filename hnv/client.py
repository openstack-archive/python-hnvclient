# Copyright 2017 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""This module contains all the available HNV resources."""

import re
import time
import uuid

from oslo_log import log as logging

from hnv.common import constant
from hnv.common import exception
from hnv.common import model
from hnv.common import utils
from hnv import config as hnv_config

LOG = logging.getLogger(__name__)
CONFIG = hnv_config.CONFIG


class _BaseHNVModel(model.Model):

    _endpoint = CONFIG.HNV.url

    resource_ref = model.Field(name="resource_ref", key="resourceRef",
                               is_property=False)
    """A relative URI to an associated resource."""

    resource_id = model.Field(name="resource_id", key="resourceId",
                              is_property=False,
                              default=lambda: str(uuid.uuid1()))
    """The resource ID for the resource. The value MUST be unique in
    the context of the resource if it is a top-level resource, or in the
    context of the direct parent resource if it is a child resource."""

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=False, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    grandparent_id = model.Field(
        name="grandparent_id", key="grandParentResourceID",
        is_property=False, is_required=False, is_read_only=True)
    """The grand parent resource ID field contains the resource ID that
    is associated with network objects that are ancestors of the parent
    of the necessary resource."""

    operation_id = model.Field(name="operation_id", key="operation-id",
                               is_property=False, is_required=False,
                               is_read_only=True)
    """The value of the x-ms-request-id header returned by the resource
    provider."""

    instance_id = model.Field(name="instance_id", key="instanceId",
                              is_property=False)
    """The globally unique Id generated and used internally by the Network
    Controller. The mapping resource that enables the client to map between
    the instanceId and the resourceId."""

    resource_metadata = model.Field(name="resource_metadata",
                                    key="resourceMetadata",
                                    is_property=False, is_required=False)
    """Structured data that the client provides to the server. This is an
    optional element but it is suggested that all clients fill in the data
    that is applicable to them."""

    etag = model.Field(name="etag", key="etag", is_property=False,
                       is_read_only=True)
    """An opaque string representing the state of the resource at the
    time the response was generated. This header is returned for
    requests that target a single entity. The Network Controller will
    also always return an etag in the response body. The etag is
    updated every time the resource is updated."""

    tags = model.Field(name="tags", key="tags", is_property=False,
                       is_required=False)

    provisioning_state = model.Field(name="provisioning_state",
                                     key="provisioningState",
                                     is_read_only=True, is_required=False)
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    configuration_state = model.Field(name="configuration_state",
                                      key="configurationState",
                                      is_read_only=True, is_required=False)
    """"Configuration state indicates any failures in processing state
    corresponding to the resource it is contained in."""

    def _reset_model(self, response):
        """Update the fields value with the received information."""

        # pylint: disable=no-member

        # Reset the model to the initial state
        self._provision_done = False    # Set back the provision flag
        self._changes.clear()           # Clear the changes

        # Process the raw data from the update response
        fields = self.process_raw_data(response)
        # Update the current model representation
        self._set_fields(fields)

        # Lock the current model
        self._provision_done = True

    @staticmethod
    def _get_client():
        """Create a new client for the HNV REST API."""
        return utils.get_client(url=CONFIG.HNV.url,
                                username=CONFIG.HNV.username,
                                password=CONFIG.HNV.password,
                                allow_insecure=CONFIG.HNV.https_allow_insecure,
                                ca_bundle=CONFIG.HNV.https_ca_bundle)

    @classmethod
    def _get_all(cls, parent_id=None, grandparent_id=None):
        """Retrives all the required resources."""
        client = cls._get_client()
        endpoint = cls._endpoint.format(resource_id="",
                                        parent_id=parent_id or "",
                                        grandparent_id=grandparent_id or "")
        resources = []
        while True:
            response = client.get_resource(endpoint)
            for raw_data in response.get("value", []):
                raw_data["parentResourceID"] = parent_id
                raw_data["grandParentResourceID"] = grandparent_id
                resources.append(cls.from_raw_data(raw_data))
            endpoint = response.get("nextLink")
            if not endpoint:
                break
        return resources

    @classmethod
    def _get(cls, resource_id, parent_id, grandparent_id):
        """"Retrieves the required resource."""
        client = cls._get_client()
        endpoint = cls._endpoint.format(resource_id=resource_id or "",
                                        parent_id=parent_id or "",
                                        grandparent_id=grandparent_id or "")
        raw_data = client.get_resource(endpoint)
        raw_data["parentResourceID"] = parent_id
        raw_data["grandParentResourceID"] = grandparent_id
        return cls.from_raw_data(raw_data)

    @classmethod
    def get(cls, resource_id=None, parent_id=None, grandparent_id=None):
        """Retrieves the required resources.

        :param resource_id:      The identifier for the specific resource
                                 within the resource type.
        :param parent_id:        The identifier for the specific ancestor
                                 resource within the resource type.
        :param grandparent_id:   The identifier that is associated with
                                 network objects that are ancestors of the
                                 parent of the necessary resource.
        """

        if not resource_id:
            return cls._get_all(parent_id, grandparent_id)
        else:
            return cls._get(resource_id, parent_id, grandparent_id)

    @classmethod
    def remove(cls, resource_id, parent_id=None, grandparent_id=None,
               wait=True, timeout=None):
        """Delete the required resource.

        :param resource_id:      The identifier for the specific resource
                                 within the resource type.
        :param parent_id:        The identifier for the specific ancestor
                                 resource within the resource type.
        :param grandparent_id:   The identifier that is associated with
                                 network objects that are ancestors of the
                                 parent of the necessary resource.
        :param wait:             Whether to wait until the operation is
                                 completed
        :param timeout:          The maximum amount of time required for this
                                 operation to be completed.

        If optional :param wait: is True and timeout is None (the default),
        block if necessary until the resource is available. If timeout is a
        positive number, it blocks at most timeout seconds and raises the
        `TimeOut` exception if no item was available within that time.

        Otherwise (block is false), return a resource if one is immediately
        available, else raise the `NotFound` exception (timeout is ignored
        in that case).
        """
        client = cls._get_client()
        endpoint = cls._endpoint.format(resource_id=resource_id or "",
                                        parent_id=parent_id or "",
                                        grandparent_id=grandparent_id or "")
        client.remove_resource(endpoint)

        elapsed_time = 0
        while wait:
            try:
                client.get_resource(endpoint)
            except exception.NotFound:
                break

            elapsed_time += CONFIG.HNV.retry_interval
            if timeout and elapsed_time > timeout:
                raise exception.TimeOut("The request timed out.")
            time.sleep(CONFIG.HNV.retry_interval)

    def refresh(self):
        """Get the latest representation of the current model."""
        client = self._get_client()
        endpoint = self._endpoint.format(
            resource_id=self.resource_id or "",
            parent_id=self.parent_id or "",
            grandparent_id=self.grandparent_id or "")
        response = client.get_resource(endpoint)
        self._reset_model(response)

    def commit(self, if_match=None, wait=True, timeout=None):
        """Apply all the changes on the current model.

        :param wait:    Whether to wait until the operation is completed
        :param timeout: The maximum amount of time required for this
                        operation to be completed.

        If optional :param wait: is True and timeout is None (the default),
        block if necessary until the resource is available. If timeout is a
        positive number, it blocks at most timeout seconds and raises the
        `TimeOut` exception if no item was available within that time.

        Otherwise (block is false), return a resource if one is immediately
        available, else raise the `NotFound` exception (timeout is ignored
        in that case).
        """
        if not self._changes:
            return

        super(_BaseHNVModel, self).commit(wait=wait, timeout=timeout)
        client = self._get_client()
        endpoint = self._endpoint.format(
            resource_id=self.resource_id or "",
            parent_id=self.parent_id or "",
            grandparent_id=self.grandparent_id or "")
        request_body = self.dump(include_read_only=False)
        response = client.update_resource(endpoint, data=request_body,
                                          if_match=if_match)

        elapsed_time = 0
        while wait:
            self.refresh()  # Update the representation of the current model
            if not self.provisioning_state:
                raise exception.ServiceException("The object doesn't contain "
                                                 "`provisioningState`.")
            elif self.provisioning_state == constant.FAILED:
                raise exception.ServiceException(
                    "Failed to complete the required operation.")
            elif self.provisioning_state == constant.SUCCEEDED:
                break

            elapsed_time += CONFIG.HNV.retry_interval
            if timeout and elapsed_time > timeout:
                raise exception.TimeOut("The request timed out.")
            time.sleep(CONFIG.HNV.retry_interval)
        else:
            self._reset_model(response)

        # NOTE(alexcoman): In order to keep backwards compatibility the
        # `method: commit` will return a reference to itself.
        # An example for that can be the following use case:
        # label = client.Model().commit()
        return self

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data.get("properties", {})

        raw_metadata = raw_data.get("resourceMetadata", None)
        if raw_metadata is not None:
            metadata = ResourceMetadata.from_raw_data(raw_metadata)
            raw_data["resourceMetadata"] = metadata

        raw_state = properties.get("configurationState", None)
        if raw_state is not None:
            configuration = ConfigurationState.from_raw_data(raw_state)
            properties["configurationState"] = configuration

        return super(_BaseHNVModel, cls).from_raw_data(raw_data)


class Resource(model.Model):

    """Model for the resource references."""

    _regexp = {}

    resource_ref = model.Field(name="resource_ref", key="resourceRef",
                               is_property=False, is_required=True)
    """A relative URI to an associated resource."""

    def __init__(self, **fields):
        super(Resource, self).__init__(**fields)
        if not self._regexp:
            self._load_models()

    def _load_models(self):
        models = globals().copy()
        for _, model_cls in models.iteritems():
            endpoint = getattr(model_cls, "_endpoint", None)
            if endpoint is not None:
                regexp = endpoint.format(
                    resource_id="(?P<resource_id>[^/]+)",
                    parent_id="(?P<parent_id>[^/]+)",
                    grandparent_id="(?P<grandparent_id>[^/]+)")
                regexp = re.sub("(/networking/v[0-9]+)/", "", regexp)
                self._regexp[model_cls] = re.compile(regexp)

    def get_resource(self):
        """Return the associated resource."""
        references = {"resource_id": None, "parent_id": None,
                      "grandparent_id": None}
        for model_cls, regexp in self._regexp.iteritems():
            match = regexp.search(self.resource_ref)
            if match is not None:
                references.update(match.groupdict())
                return model_cls.get(**references)

        raise exception.NotFound("No model available for %(resource_ref)r",
                                 resource_ref=self.resource_ref)


class ResourceMetadata(model.Model):

    """Model for Resource Metadata.

    Structured data that the client provides to the server. This is an
    optional element but it is suggested that all clients fill in the
    data that is applicable to them.
    """

    client = model.Field(name="client", key="client",
                         is_property=False, is_required=False)
    """Indicates the client that creates or updates the resource.
    Although this element is optional, it is strongly recommended that it
    contain an appropriate value."""

    tenant_id = model.Field(name="tenant_id", key="tenantId",
                            is_property=False, is_required=False)
    """The identifier of the tenant in the client environment.
    Provides linkage between the resource in the Network Controller
    and the tenant in the client network."""

    group_id = model.Field(name="group_id", key="groupId",
                           is_property=False, is_required=False)
    """The identifier of the group that the tenant belongs to within
    the client environment. This is usually used in environments that
    contain multiple tenants that are aggregated into groups that the
    client manages. This provides linkage between the resource in the
    Network Controller and the group that the tenant belongs to in the
    client network."""

    resource_name = model.Field(name="resource_name", key="resourceName",
                                is_property=False, is_required=False)
    """Indicates the globally unique name of the resource. If it
    is not assigned a value then it will be blank."""

    name = model.Field(name="name", key="name",
                       is_property=False, is_required=False)
    """Indicates the globally unique name of the resource. If it
    is not assigned a value then it will be blank."""

    original_href = model.Field(name="original_href", key="originalHref",
                                is_property=False, is_required=False)
    """The original URI of the resource if the client uses a URI based
    system to organize resources."""


class IPPools(_BaseHNVModel):

    """Model for IP Pools.

    The ipPools resource represents the range of IP addresses from which IP
    addresses will be allocated for nodes within a subnet. The subnet is a
    logical or physical subnet inside a logical network.

    The ipPools for a virtual subnet are implicit. The start and end IP
    addresses of the pool of the virtual subnet is based on the IP prefix
    of the virtual subnet.
    """

    _endpoint = ("/networking/v1/logicalNetworks/{grandparent_id}"
                 "/subnets/{parent_id}/ipPools/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    grandparent_id = model.Field(
        name="grandparent_id", key="grandParentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The grand parent resource ID field contains the resource ID that
    is associated with network objects that are ancestors of the parent
    of the necessary resource."""

    start_ip_address = model.Field(name="start_ip_address",
                                   key="startIpAddress",
                                   is_required=True, is_read_only=False)
    """Start IP address of the pool.
    Note: This is an inclusive value so it is a valid IP address from
    this pool."""

    end_ip_address = model.Field(name="end_ip_address", key="endIpAddress",
                                 is_required=True, is_read_only=False)
    """End IP address of the pool.
    Note: This is an inclusive value so it is a valid IP address from
    this pool."""

    usage = model.Field(name="usage", key="usage",
                        is_required=False, is_read_only=True)
    """Statistics of the usage of the IP pool."""


class LogicalSubnetworks(_BaseHNVModel):

    """Logical subnetworks model.

    The logicalSubnets resource consists of a subnet/VLAN pair.
    The vlan resource is required; however it MAY contain a value of zero
    if the subnet is not associated with a vlan.
    """

    _endpoint = ("/networking/v1/logicalNetworks/{parent_id}"
                 "/logicalSubnets/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    address_prefix = model.Field(name="address_prefix", key="addressPrefix")
    """Identifies the subnet id in form of ipAddresss/prefixlength."""

    vlan_id = model.Field(name="vlan_id", key="vlanID", is_required=True,
                          default=0)
    """Indicates the VLAN ID associated with the logical subnet."""

    routes = model.Field(name="routes", key="routes", is_required=False)
    """Indicates the routes that are contained in the logical subnet."""

    ip_pools = model.Field(name="ip_pools", key="ipPools",
                           is_required=False)
    """Indicates the IP Pools that are contained in the logical subnet."""

    dns_servers = model.Field(name="dns_servers", key="dnsServers",
                              is_required=False, default=list)
    """Indicates one or more DNS servers that are used for resolving DNS
    queries by devices or host connected to this logical subnet."""

    ip_configurations = model.Field(name="ip_configurations",
                                    key="ipConfigurations")
    """Indicates an array of IP configurations that are contained
    in the network interface."""

    network_interfaces = model.Field(name="network_interfaces",
                                     key="networkInterfaces",
                                     is_read_only=True)
    """Indicates an array of references to networkInterfaces resources
    that are attached to the logical subnet."""

    is_public = model.Field(name="is_public", key="isPublic")
    """Boolean flag specifying whether the logical subnet is a
    public subnet."""

    default_gateways = model.Field(name="default_gateways",
                                   key="defaultGateways")
    """A collection of one or more gateways for the subnet."""

    gateway_pools = model.Field(name="gateway_pools", key="gatewayPools",
                                is_required=False, is_read_only=True)
    """Indicates a collection of references to gatewayPools resources
    in which connections can be created. This information is populated
    at the time of subscription and can be changed only via the Service
    administrator portal."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        ip_pools = []
        properties = raw_data["properties"]
        for raw_content in properties.get("ipPools", []):
            raw_content["parentResourceID"] = raw_data["resourceId"]
            raw_content["grandParentResourceID"] = raw_data["parentResourceID"]
            ip_pools.append(IPPools.from_raw_data(raw_content))
        properties["ipPools"] = ip_pools

        ip_configurations = []
        raw_settings = properties.get("ipConfigurations", [])
        for raw_configuration in raw_settings:
            ip_configuration = IPConfiguration.from_raw_data(raw_configuration)
            ip_configurations.append(ip_configuration)
        properties["ipConfigurations"] = ip_configurations

        network_interfaces = []
        for raw_content in properties.get("networkInterfaces", []):
            resource = Resource.from_raw_data(raw_content)
            network_interfaces.append(resource)
        properties["networkInterfaces"] = network_interfaces

        return super(LogicalSubnetworks, cls).from_raw_data(raw_data)


class LogicalNetworks(_BaseHNVModel):

    """Logical networks model.

    The logicalNetworks resource represents a logical partition of physical
    network that is dedicated for a specific purpose.
    A logical network comprises of a collection of logical subnets.
    """

    _endpoint = "/networking/v1/logicalNetworks/{resource_id}"

    subnetworks = model.Field(name="subnetworks", key="subnets",
                              is_required=False, default=list)
    """Indicates the subnets that are contained in the logical network."""

    network_virtualization_enabled = model.Field(
        name="network_virtualization_enabled",
        key="networkVirtualizationEnabled", default=False, is_required=False)
    """Indicates if the network is enabled to be the Provider Address network
    for one or more virtual networks. Valid values are `True` or `False`.
    The default is `False`."""

    virtual_networks = model.Field(
        name="virtual_networks", key="virtualNetworks",
        is_read_only=True, default=list)
    """Indicates an array of virtualNetwork resources that are using
    the network."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data["properties"]

        subnetworks = []
        for raw_subnet in properties.get("subnets", []):
            raw_subnet["parentResourceID"] = raw_data["resourceId"]
            subnetworks.append(LogicalSubnetworks.from_raw_data(raw_subnet))
        properties["subnets"] = subnetworks

        virtual_networks = []
        for raw_network in properties.get("virtualNetworks", []):
            virtual_networks.append(Resource.from_raw_data(raw_network))
        properties["virtualNetworks"] = virtual_networks

        return super(LogicalNetworks, cls).from_raw_data(raw_data)


class IPConfiguration(_BaseHNVModel):

    """IP Configuration Model.

    This resource represents configuration information for IP addresses:
    allocation method, actual IP address, membership of a logical or virtual
    subnet, load balancing and access control information.
    """

    _endpoint = ("/networking/v1/networkInterfaces/{parent_id}"
                 "/ipConfigurations/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    access_controll_list = model.Field(name="access_controll_list",
                                       key="accessControlList",
                                       is_required=False)
    """Indicates a reference to an accessControlList resource that defines
    the ACLs in and out of the IP Configuration."""

    backend_address_pools = model.Field(
        name="backend_address_pools", key="loadBalancerBackendAddressPools",
        is_required=False, is_read_only=False)
    """Reference to backendAddressPools child resource of loadBalancers
    resource."""

    inbound_nat_rules = model.Field(
        name="loadBalancerInboundNatRules", key="loadBalancerInboundNatRules",
        is_required=False)
    """Reference to inboundNatRules child resource of loadBalancers
    resource."""

    private_ip_address = model.Field(
        name="private_ip_address", key="privateIPAddress",
        is_required=False)
    """Indicates the private IP address of the IP Configuration."""

    private_ip_allocation_method = model.Field(
        name="private_ip_allocation_method", key="privateIPAllocationMethod",
        is_required=False)
    """Indicates the allocation method (Static or Dynamic)."""

    public_ip_address = model.Field(
        name="public_ip_address", key="publicIpAddress",
        is_required=False)
    """Indicates the public IP address of the IP Configuration."""

    service_insertion = model.Field(
        name="service_insertion", key="serviceInsertion",
        is_required=False)
    """Indicates a reference to a serviceInsertion resource that defines
    the service insertion in and out of the IP Configuration."""

    subnet = model.Field(name="subnet", key="subnet", is_read_only=True)
    """Indicates a reference to the subnet resource that the IP Configuration
    is connected to."""


class DNSSettings(model.Model):

    """Model for DNS Setting for Network Interfaces."""

    dns_servers = model.Field(name="dns_servers", key="dnsServers",
                              is_property=False, is_required=False)
    """Indicates an array of IP Addresses that the network interface
    resource will use for the DNS servers."""


class QosSettings(model.Model):

    """Qos Settings Model."""

    outbound_reserved_value = model.Field(name="outbound_reserved_value",
                                          key="outboundReservedValue",
                                          is_required=False,
                                          is_property=False)
    """If outboundReservedMode is "absolute" then the value indicates the
    bandwidth, in Mbps, guaranteed to the virtual port for transmission
    (egress)."""

    outbound_maximum_mbps = model.Field(name="outbound_maximum_mbps",
                                        key="outboundMaximumMbps",
                                        is_required=False,
                                        is_property=False)
    """Indicates the maximum permitted send-side bandwidth, in Mbps,
    for the virtual port (egress)."""

    inbound_maximum_mbps = model.Field(name="inbound_maximum_mbps",
                                       key="inboundMaximumMbps",
                                       is_required=False,
                                       is_property=False)
    """Indicates the maximum permitted receive-side bandwidth for the
    virtual port (ingress) in Mbps."""


class PortSettings(model.Model):

    """Port Settings Model."""

    mac_spoofing = model.Field(name="mac_spoofing", key="macSpoofingEnabled",
                               is_required=False, is_property=False)
    """Specifies whether virtual machines can change the source MAC
    address in outgoing packets to one not assigned to them."""

    arp_guard = model.Field(name="arp_guard", key="arpGuardEnabled",
                            is_required=False, is_property=False)
    """Specifies whether ARP guard is enabled or not. ARP guard
    will allow only addresses specified in ArpFilter to pass through
    the port."""

    dhcp_guard = model.Field(name="dhcp_guard", key="dhcpGuardEnabled",
                             is_required=False, is_property=False)
    """Specifies the number of broadcast, multicast, and unknown
    unicast packets per second a virtual machine is allowed to
    send through the specified virtual network adapter."""

    storm_limit = model.Field(name="storm_limit", key="stormLimit",
                              is_required=False, is_property=False)
    """Specifies the number of broadcast, multicast, and unknown
    unicast packets per second a virtual machine is allowed to
    send through the specified virtual network adapter."""

    port_flow_limit = model.Field(name="port_flow_limit",
                                  key="portFlowLimit",
                                  is_required=False, is_property=False)
    """Specifies the maximum number of flows that can be executed
    for the port."""

    vmq_weight = model.Field(name="vmq_weight", key="vmqWeight",
                             is_required=False, is_property=False)
    """Specifies whether virtual machine queue (VMQ) is to be
    enabled on the virtual network adapter."""

    iov_weight = model.Field(name="iov_weight", key="iovWeight",
                             is_required=False, is_property=False)
    """Specifies whether single-root I/O virtualization (SR-IOV) is to
    be enabled on this virtual network adapter."""

    iov_interrupt_moderation = model.Field(name="iov_interrupt_moderation",
                                           key="iovInterruptModeration",
                                           is_required=False,
                                           is_property=False)
    """Specifies the interrupt moderation value for a single-root I/O
    virtualization (SR-IOV) virtual function assigned to a virtual
    network adapter."""

    iov_queue_pairs = model.Field(name="iov_queue_pairs",
                                  key="iovQueuePairsRequested",
                                  is_required=False, is_property=False)
    """Specifies the number of hardware queue pairs to be allocated
    to an SR-IOV virtual function."""

    qos_settings = model.Field(name="qos_settings", key="qosSettings",
                               is_required=False, is_property=False)

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        raw_settings = raw_data.get("qosSettings", {})
        qos_settings = QosSettings.from_raw_data(raw_settings)
        raw_data["qosSettings"] = qos_settings
        return super(PortSettings, cls).from_raw_data(raw_data)


class ConfigurationState(model.Model):

    """Model for configuration state."""

    uuid = model.Field(name="uuid", key="id",
                       is_property=False, is_required=False)
    status = model.Field(name="status", key="status",
                         is_property=False, is_required=False)
    last_update = model.Field(name="last_update", key="lastUpdatedTime",
                              is_property=False, is_required=False)
    detailed_info = model.Field(name="detailed_info", key="detailedInfo",
                                is_property=False, is_required=False)
    interface_errors = model.Field(name="interface_errors",
                                   key="virtualNetworkInterfaceErrors",
                                   is_property=False, is_required=False)
    host_errors = model.Field(name="host_erros", key="hostErrors",
                              is_property=False, is_required=False)


class NetworkInterfaces(_BaseHNVModel):

    """Network Interface Model.

    The networkInterfaces resource specifies the configuration of either
    a host virtual interface (host vNIC) or a virtual server NIC (VMNIC).
    """

    _endpoint = "/networking/v1/networkInterfaces/{resource_id}"

    dns_settings = model.Field(name="dns_settings", key="dnsSettings",
                               is_read_only=False)
    """Indicates the DNS settings of this network interface."""

    ip_configurations = model.Field(name="ip_configurations",
                                    key="ipConfigurations")
    """Indicates an array of IP configurations that are contained
    in the network interface."""

    is_host = model.Field(name="is_host",
                          key="isHostVirtualNetworkInterface")
    """True if this is a host virtual interface (host vNIC)
    False if this is a virtual server NIC (VMNIC)."""

    is_primary = model.Field(name="is_primary", key="isPrimary",
                             default=True, is_static=True)
    """`True` if this is the primary interface and the default
    value if the property is not set or `False` if this is a
    secondary interface."""

    is_multitenant_stack = model.Field(name="is_multitenant_stack",
                                       key="isMultitenantStack",
                                       default=False)
    """`True` if allows the NIC to be part of multiple virtual networks
    or `False` if the opposite."""

    internal_dns_name = model.Field(name="internal_dns_name",
                                    key="internalDnsNameLabel")
    """Determines the name that will be registered in iDNS
    when the iDnsServer resource is configured."""

    server = model.Field(name="server", key="server",
                         is_read_only=True)
    """Indicates a reference to the servers resource for the
    machine that is currently hosting the virtual machine to
    which this network interface belongs."""

    port_settings = model.Field(name="port_settings", key="portSettings")
    """A PortSettings object."""

    mac_address = model.Field(name="mac_address", key="privateMacAddress")
    """Indicates the private MAC address of this network interface."""

    mac_allocation_method = model.Field(name="mac_allocation_method",
                                        key="privateMacAllocationMethod")
    """Indicates the allocation scheme of the MAC for this
    network interface."""

    service_insertion_elements = model.Field(
        name="service_insertion_elements", key="serviceInsertionElements",
        is_read_only=True)
    """Indicates an array of serviceInsertions resources that
    this networkInterfaces resource is part of."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data["properties"]

        ip_configurations = []
        raw_settings = properties.get("ipConfigurations", [])
        for raw_configuration in raw_settings:
            ip_configuration = IPConfiguration.from_raw_data(raw_configuration)
            ip_configurations.append(ip_configuration)
        properties["ipConfigurations"] = ip_configurations

        raw_settings = properties.get("dnsSettings", {})
        dns_settings = DNSSettings.from_raw_data(raw_settings)
        properties["dnsSettings"] = dns_settings

        raw_settings = properties.get("portSettings", {})
        port_settings = PortSettings.from_raw_data(raw_settings)
        properties["portSettings"] = port_settings

        return super(NetworkInterfaces, cls).from_raw_data(raw_data)


class SubNetworks(_BaseHNVModel):

    """SubNetwork Model.

    The subnets resource is used to create Virtual Subnets (VSIDs) under
    a tenant's virtual network (RDID). The user can specify the addressPrefix
    to use for the subnets, the accessControl Lists to protect the subnets,
    the routeTable to be applied to the subnet, and optionally the service
    insertion to use within the subnet.
    """

    _endpoint = ("/networking/v1/virtualNetworks/{parent_id}"
                 "/subnets/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    address_prefix = model.Field(name="address_prefix", key="addressPrefix",
                                 is_required=True)
    """Indicates the address prefix that defines the subnet. The value is
    in the format of 0.0.0.0/0. This value must not overlap with other
    subnets in the virtual network and must fall in the addressPrefix defined
    in the virtual network."""

    access_controll_list = model.Field(name="access_controll_list",
                                       key="accessControlList",
                                       is_required=False)
    """Indicates a reference to an accessControlLists resource that defines
    the ACLs in and out of the subnet."""

    service_insertion = model.Field(name="service_insertion",
                                    key="serviceInsertion",
                                    is_required=False)
    """Indicates a reference to a serviceInsertions resource that defines the
    service insertion to be applied to the subnet."""

    route_table = model.Field(name="route_table", key="routeTable",
                              is_required=False)
    """Indicates a reference to a routeTable resource that defines the tenant
    routes to be applied to the subnet."""

    ip_configuration = model.Field(name="ip_configuration",
                                   key="ipConfigurations",
                                   is_read_only=False)
    """Indicates an array of references of networkInterfaces resources that
    are connected to the subnet."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data["properties"]

        ip_configurations = []
        for raw_config in properties.get("ipConfigurations", []):
            ip_configurations.append(IPConfiguration.from_raw_data(raw_config))
        properties["ipConfigurations"] = ip_configurations

        acl = properties.get("accessControlList")
        if acl:
            properties["accessControlList"] = Resource.from_raw_data(acl)

        return super(SubNetworks, cls).from_raw_data(raw_data)


class DHCPOptions(model.Model):

    """Model for DHCP options.

    Indicates the DHCP options used by servers in the virtual network.
    """

    dns_servers = model.Field(
        name="dns_servers", key="dnsServers",
        is_property=False, is_required=True, is_read_only=False)
    """Indicates an array of DNS servers that are being used by
    the virtual network."""


class AddressSpace(model.Model):

    """Indicates the address space of the virtual network."""

    address_prefixes = model.Field(
        name="address_prefixes", key="addressPrefixes",
        is_property=False, is_required=True, is_read_only=False)
    """Indicates the valid list of address prefixes that
    can make up this virtual network. The value is an array
    of address prefixes in the format of 0.0.0.0/0.
    The space cannot be shrunk if addresses are in use in a
    subnet belonging to the virtual network.
    """


class VirtualNetworks(_BaseHNVModel):

    """Virtual Network Model.

    This resource is used to create a virtual network using HNV for tenant
    overlays. The default encapsulation for virtualNetworks is Virtual
    Extensible LAN but this can be changed by updating the virtual
    NetworkManager resource. Similarly, the HNV Distributed Router is enabled
    by default but this can be overridden using the virtualNetworkManager
    resource.
    """

    _endpoint = "/networking/v1/virtualNetworks/{resource_id}"

    address_space = model.Field(name="address_space",
                                key="addressSpace",
                                is_required=True)
    """Indicates the address space of the virtual network."""

    dhcp_options = model.Field(name="dhcp_options", key="dhcpOptions",
                               is_required=False)
    """Indicates the DHCP options used by servers in the virtual
    network."""

    subnetworks = model.Field(name="subnetworks", key="subnets",
                              is_required=False, default=list)
    """Indicates the subnets that are on the virtual network."""

    logical_network = model.Field(name="logical_network",
                                  key="logicalNetwork",
                                  is_required=True)
    """Indicates a reference to the networks resource that is the
    underlay network which the virtual network runs on."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data["properties"]

        raw_content = properties.get("addressSpace", None)
        if raw_content is not None:
            address_space = AddressSpace.from_raw_data(raw_content)
            properties["addressSpace"] = address_space

        raw_content = properties.get("dhcpOptions")
        if raw_content is not None:
            dhcp_options = DHCPOptions.from_raw_data(raw_content)
            properties["dhcpOptions"] = dhcp_options

        raw_content = properties.get("logicalNetwork", None)
        if raw_content is not None:
            properties["logicalNetwork"] = Resource.from_raw_data(raw_content)

        subnetworks = []
        for raw_subnet in properties.get("subnets", []):
            raw_subnet["parentResourceID"] = raw_data["resourceId"]
            subnetworks.append(SubNetworks.from_raw_data(raw_subnet))
        properties["subnets"] = subnetworks

        return super(VirtualNetworks, cls).from_raw_data(raw_data)


class ACLRules(_BaseHNVModel):

    """ACL Rules Model.

    The aclRules resource describes the network traffic that is allowed
    or denied for a network interface of a virtual machine. Currently,
    only inbound rules are expressed.
    """

    _endpoint = ("/networking/v1/accessControlLists/{parent_id}"
                 "/aclRules/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    action = model.Field(name="action", key="action")
    """Indicates the action the ACL Rule will take. Valid values
    are: `Allow` and `Deny`."""

    destination_prefix = model.Field(name="destination_prefix",
                                     key="destinationAddressPrefix")
    """Indicates the CIDR value of destination IP or a pre-defined tag
    to which traffic is destined. You can specify 0.0.0.0/0 for IPv4
    all and ::/0 for IPv6 all traffic."""

    destination_port_range = model.Field(name="destination_port_range",
                                         key="destinationPortRange")
    """Indicates the destination port(s) that will trigger this ACL
    rule. Valid values include a single port, port range (separated by "-"),
    or "*" for all ports. All numbers are inclusive."""

    source_prefix = model.Field(name="source_prefix",
                                key="sourceAddressPrefix")
    """Indicates the CIDR value of source IP or a pre-defined TAG from
    which traffic is originating. You can specify 0.0.0.0/0 for IPv4 all
    and ::/0 forIPv6 all traffic."""

    source_port_range = model.Field(name="source_port_range",
                                    key="sourcePortRange")
    """Indicates the source port(s) that will trigger this ACL rule.
    Valid values include a single port, port range (separated by "-"),
    or "*" for all ports. All numbers are inclusive."""

    description = model.Field(name="description", key="description")
    """Indicates a description of the ACL rule."""

    logging = model.Field(name="logging", key="logging",
                          default="Enabled")
    """Indicates whether logging will be turned on for when this
    rule gets triggered. Valid values are `Enabled` or `Disabled`."""

    priority = model.Field(name="priority", key="priority")
    """Indicates the priority of the rule relative to the priority of
    other ACL rules. This is a unique numeric value in the context of
    an accessControlLists resource. Value from 101 - 65000 are user
    defined. Values 1 - 100 and 65001 - 65535 are reserved."""

    protocol = model.Field(name="protocol", key="protocol")
    """Indicates the protocol to which the ACL rule will apply.
    Valid values are `TCP` or `UDP`."""

    rule_type = model.Field(name="rule_type", key="type")
    """Indicates whether the rule is to be evaluated against ingress
    traffic (Inbound) or egress traffic (Outbound). Valid values are
    `Inbound` or `Outbound`."""


class AccessControlLists(_BaseHNVModel):

    """Access Constrol List Model.

    An accessControlLists resource contains a list of ACL rules.
    Access control list resources can be assigned to virtual subnets
    or IP configurations.

    An ACL can be associated with:
        * Subnets of a virtual or logical network. This means that all
        network interfaces (NICs) with IP configurations created in the
        subnet inherit the ACL rules in the Access Control List. Often,
        subnets are used for a specific architectural tier (frontend,
        middle tier, backend) in more complex applications. Assigning
        an ACL to subnets can thus be used to control the network flow
        between the different tiers.
        *IP configuration of a NIC. This means that the ACL will be
        applied to the parent network interface of the specified IP
        configuration.
    """

    _endpoint = "/networking/v1/accessControlLists/{resource_id}"

    acl_rules = model.Field(name="acl_rules", key="aclRules")
    """Indicates the rules in an access control list."""

    inbound_action = model.Field(name="inbound_action",
                                 key="inboundDefaultAction",
                                 default="Permit")
    """Indicates the default action for Inbound Rules. Valid values are
    `Permit` and `Deny`. The default value is `Permit`."""

    outbound_action = model.Field(name="outbound_action",
                                  key="outboundDefaultAction",
                                  default="Permit")
    """Indicates the default action for Outbound Rules. Valid values are
    `Permit` and `Deny`. The default value is `Permit`."""

    ip_configuration = model.Field(name="ip_configuration",
                                   key="ipConfigurations")
    """Indicates references to IP addresses of network interfaces
    resources this access control list is associated with."""

    subnets = model.Field(name="subnets", key="subnets")
    """Indicates an array of references to subnets resources this access
    control list is associated with."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data["properties"]

        subnetworks = []
        for raw_subnet in properties.get("subnets", []):
            subnetworks.append(Resource.from_raw_data(raw_subnet))
        properties["subnets"] = subnetworks

        acl_rules = []
        for raw_rule in properties.get("aclRules", []):
            raw_rule["parentResourceID"] = raw_data["resourceId"]
            acl_rules.append(ACLRules.from_raw_data(raw_rule))
        properties["aclRules"] = acl_rules

        return super(AccessControlLists, cls).from_raw_data(raw_data)


class VirtualSwtichQosSettings(model.Model):

    """Model for virtual switch QoS settings."""

    reservation_mode = model.Field(
        name="reservation_mode", key="reservationMode",
        is_required=False, is_property=False)
    """Specifies whether outboundReservedValue is applied as the absolute
    bandwidth (Mbps) or as a weighted value.
    Allowed values are `constant.ABSOLUTE` or `constant.WEIGHT`.
    """

    enable_software_revervations = model.Field(
        name="enable_software_revervations", key="enableSoftwareReservations",
        is_required=False, is_property=False)
    """True to enable software qos reservation."""

    enable_hardware_limits = model.Field(
        name="enable_hardware_limits", key="enableHardwareLimits",
        is_required=False, is_property=False)
    """Offloads Tx and Rx cap to hardware."""

    enable_hardware_reservations = model.Field(
        name="enable_hardware_reservations", key="enableHardwareReservations",
        is_required=False, is_property=False)
    """Offloads bandwith reservation to hardware."""

    link_speed_percentage = model.Field(
        name="link_speed_percentage", key="linkSpeedPercentage",
        is_required=False, is_property=False)
    """The percentage of the link speed to be used for calculating reservable
    bandwidth."""

    default_reservation = model.Field(
        name="default_reservation", key="defaultReservation",
        is_required=False, is_property=False, default=0)
    """The default value of the reservation to be used for Nics that do not
    have any reservation specified (0)."""


class VirtualSwitchManager(_BaseHNVModel):

    """Virtual switch manager model.

    The virtualSwitchManager resource is a singleton resource that
    configures the virtual switch properties on every server managed
    by the Network Controller (meaning that the NC has server resources for
    those machines).
    """

    _endpoint = "/networking/v1/virtualSwitchManager/configuration"

    qos_settings = model.Field(name="qos_settings", key="qosSettings",
                               is_required=False)

    def __init__(self, **fields):
        qos_settings = fields.get("qos_settings", {})
        if not isinstance(qos_settings, VirtualSwtichQosSettings):
            fields["qos_settings"] = VirtualSwtichQosSettings.from_raw_data(
                raw_data=qos_settings)
        super(VirtualSwitchManager, self).__init__(**fields)

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data["properties"]
        qos_settings = properties.get("qosSettings", {})
        properties["qosSettings"] = VirtualSwtichQosSettings.from_raw_data(
            raw_data=qos_settings)
        return super(VirtualSwitchManager, cls).from_raw_data(raw_data)

    @classmethod
    def remove(cls, resource_id, parent_id=None, grandparent_id=None,
               wait=True, timeout=None):
        """Delete the required resource."""
        raise exception.NotSupported(feature="DELETE",
                                     context="VirtualSwitchManager")


class Routes(_BaseHNVModel):

    """Routes Model.

    A routes resource is used to create routes under a tenant's Route Table.
    The tenant can specify the addressPrefix of the route, the type of next
    hop, and the next hop customer IP address.
    """

    _endpoint = "/networking/v1/routeTables/{parent_id}/routes/{resource_id}"

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    address_prefix = model.Field(name="address_prefix", key="addressPrefix",
                                 is_required=True)
    """The destination CIDR to which the route applies, such as 10.1.0.0/16"""

    next_hop_type = model.Field(name="next_hop_type", key="nextHopType",
                                is_required=True)
    """The type of hop to which the packet is sent.

    Valid values are:
        * `constant.VIRTUAL_APPLIANCE` represents a virtual appliance VM
            within the tenant virtual network.
        * `constant.VNET_LOCAL` represents the local virtual network.
        * `constant.VIRTUAL_NETWORK_GATEWAY` represents a virtual network
            gateway.
        * `constant.INTERNET` represents the default internet gateway.
        * `None` represents a black hole.
    """

    next_hop_ip_address = model.Field(name="next_hop_ip_address",
                                      key="nextHopIpAddress",
                                      is_required=False)
    """Indicates the next hop to which IP address packets are forwarded,
    such as 11.0.0.23."""


class RouteTables(_BaseHNVModel):

    """Route Table Model.

    The RouteTable resource contains a list of routes. RouteTable resources
    can be applied to subnets of a tenant virtual network to control routing
    within virtual network. Once routeTables has been associated to a virtual
    subnet, all tenant VMs created within that subnet will inherit the
    RouteTable and will have their traffic routed per the routes contained
    in the table.
    """

    _endpoint = "/networking/v1/routeTables/{resource_id}"

    routes = model.Field(name="routes", key="routes", is_required=False,
                         default=list)
    """Indicates the routes in a route table, see routes resource for full
    details on this element."""

    subnetworks = model.Field(name="subnetworks", key="subnets",
                              is_read_only=True)
    """Indicates an array of references to subnets resources this route
    table is associated with."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data["properties"]

        routes = []
        raw_routes = properties.get("routes", [])
        for raw_route in raw_routes:
            raw_route["parentResourceID"] = raw_data["resourceId"]
            routes.append(Routes.from_raw_data(raw_route))
        properties["routes"] = routes

        subnets = []
        raw_subnets = properties.get("subnets", [])
        for raw_subnet in raw_subnets:
            subnets.append(Resource.from_raw_data(raw_subnet))
        properties["subnets"] = subnets

        return super(RouteTables, cls).from_raw_data(raw_data)


class MainMode(model.Model):

    """Main mode IPsec configuration details."""

    diffie_hellman_group = model.Field(
        name="diffie_hellman_group", key="diffieHellmanGroup",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates Diffie Hellman group used during main mode IKE negotiation.
    Values: `Group1`, `Group2`, `Group14`, `ECP256`, `ECP384` or `Group24`."""

    integrity_algorithm = model.Field(
        name="integrity_algorithm", key="integrityAlgorithm",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates Integrity algorithm used during main mode IKE negotiation.
    Values: `MD5`, `SHA196`, `SHA256` or `SHA384`."""

    encryption_algorithm = model.Field(
        name="encryption_algorithm", key="encryptionAlgorithm",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates cipher algorithm used during main mode IKE negotiation.
    Values: `DES`, `DES3`, `AES128`, `AES192` or `AES256`."""

    sa_life_time_seconds = model.Field(
        name="sa_life_time_seconds", key="saLifeTimeSeconds",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates life time of SA in seconds."""

    sa_life_time_kb = model.Field(
        name="sa_life_time_kb", key="saLifeTimeKiloBytes",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates life time of SA in Kilobytes. Ignored by IPsec."""


class QuickMode(model.Model):

    """Quick mode IPsec configuration"""

    perfect_forward_secrecy = model.Field(
        name="perfect_forward_secrecy", key="perfectForwardSecrecy",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates whether Perfect Forward Secrecy is enabled or not. If enabled
    specifies the algorithm.
    Values: `None`, `PFS1`, `PFS2`, `PFS2048`, `PFS14`, `ECP256`, `ECP384`,
    `PFSMM` or `PFS24`."""

    cipher_tc = model.Field(
        name="cipher_tc", key="cipherTransformationConstant",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates the encryption algorithm used for data traffic.
    Values:
        None, `constant.AES128`, `constant.AES128CBC`, `constant.AES192`,
        `constant.AES192CBC`, `constant.AES256`, `constant.AES256`,
        `constant.CBCDES`, `constant.CBCDES3`, `constant.DES`, `constant.DES3`,
        `constant.GCMAES128`, `constant.GCMAES192` or `constant.GCMAES256`.
    """

    authentication_tc = model.Field(
        name="authentication_tc", key="authenticationTransformationConstant",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates the authentication transform used for data traffic.
    Values: `constant.MD596`, `constant.SHA196`, `constant.SHA256`,
    `constant.GCMAES128`, `constant.GCMAES192` or `constant.GCMAES256`."""

    sa_life_time_seconds = model.Field(
        name="sa_life_time_seconds", key="saLifeTimeSeconds",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates life time of SA in seconds."""

    sa_life_time_kb = model.Field(
        name="sa_life_time_kb", key="saLifeTimeKiloBytes",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates life time of SA in Kilobytes."""

    idle_disconnect = model.Field(
        name="idle_disconnect", key="idleDisconnectSeconds",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates idle time after which SA is disconnected."""


class _VpnTrafficSelector(model.Model):

    """Model for VPN traffice selector."""

    ts_type = model.Field(
        name="ts_type", key="type",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates whether traffic is `IPv4` or `IPv6`."""

    protocol_id = model.Field(
        name="protocol_id", key="protocolId",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates IP protocol ID (such as UDP, TCP, and ICMP)."""

    port_start = model.Field(
        name="port_start", key="portStart",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates start of port range."""

    port_end = model.Field(
        name="port_end", key="portEnd",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates end of port range."""

    ip_address_start = model.Field(
        name="ip_address_start", key="ipAddressStart",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates start of IP addresses."""

    ip_address_end = model.Field(
        name="ip_address_end", key="ipAddressEnd",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates end of IP addresses."""

    ts_payload_id = model.Field(
        name="ts_payload_id", key="tsPayloadId",
        is_required=False, is_read_only=False, is_property=False)
    """No information available for this field."""


class LocalVpnTrafficSelector(_VpnTrafficSelector):

    """Model for local VPN traffic selector.

    Indicates collection of IPsec TrafficSelectors on the hoster side.
    """

    pass


class RemoteVpnTrafficSelector(_VpnTrafficSelector):

    """Model for remote VPN traffic selector.

    Indicates collection of IPsec TrafficSelectors on the tenant side.
    """

    pass


class IPSecConfiguration(model.Model):

    """Details of IPsec configuration."""

    authentication_method = model.Field(
        name="authentication_method", key="authenticationMethod",
        is_required=False, is_read_only=False, is_property=False,
        default="PSK")
    """Indicates authentication method. PSK is the only valid value."""

    shared_secret = model.Field(
        name="shared_secret", key="sharedsecret",
        is_required=False, is_read_only=False, is_property=False)
    """The shared secret used for this NetworkConnection.
    Note this is write-only property and the value of this field is not
    shown in the GET of Networkconnection."""

    main_mode = model.Field(
        name="main_mode", key="mainMode",
        is_required=False, is_read_only=False, is_property=False)
    """Main mode IPsec configuration details."""

    quick_mode = model.Field(
        name="quick_mode", key="quickMode",
        is_required=False, is_read_only=False, is_property=False)
    """Quick mode IPsec configuration."""

    local_vpn_ts = model.Field(
        name="local_vpn_ts", key="localVpnTrafficSelector",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates collection of IPsec TrafficSelectors on the hoster side."""

    remote_vpn_ts = model.Field(
        name="remote_vpn_ts", key="remoteVpnTrafficSelector",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates collection of IPsec TrafficSelectors on the tenant side."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        raw_main = raw_data.get("mainMode", None)
        if raw_main is not None:
            main_mode = MainMode.from_raw_data(raw_main)
            raw_data["mainMode"] = main_mode

        raw_quick = raw_data.get("quickMode", None)
        if raw_quick is not None:
            quick_mode = QuickMode.from_raw_data(raw_quick)
            raw_data["quickMode"] = quick_mode

        local_vpn_ts = []
        for raw_local_vpn in raw_data.get("localVpnTrafficSelector", []):
            local_vpn_ts.append(LocalVpnTrafficSelector.from_raw_data(
                raw_local_vpn))
        raw_data["localVpnTrafficSelector"] = local_vpn_ts

        remote_vpn_ts = []
        for raw_remote_vpn in raw_data.get("remoteVpnTrafficSelector", []):
            remote_vpn_ts.append(RemoteVpnTrafficSelector.from_raw_data(
                raw_remote_vpn))
        raw_data["remoteVpnTrafficSelector"] = remote_vpn_ts

        return super(IPSecConfiguration, cls).from_raw_data(raw_data)


class IPAddress(model.Model):

    """IP assigned in the tenant compartment for L3 interface."""

    ip_address = model.Field(
        name="ip_address", key="ipAddress",
        is_required=False, is_read_only=False, is_property=False)
    """IP address for L3 interface in tenant compartment."""

    prefix_length = model.Field(
        name="prefix_length", key="prefixLength",
        is_required=False, is_read_only=False, is_property=False)
    """Prefix length of the IP address."""


class NetworkInterfaceRoute(model.Model):

    """Model for network interface route."""

    destination_prefix = model.Field(
        name="destination_prefix", key="destinationPrefix",
        is_required=True, is_read_only=False, is_property=False)
    """Prefix with subnet of the routes."""

    next_hop = model.Field(
        name="next_hop", key="nextHop",
        is_required=False, is_read_only=False, is_property=False)
    """Next Hop of the routes. Is significant only for L3 connections.
    Has no significance for point to point connections such as IPsec & GRE."""

    metric = model.Field(
        name="metric", key="metric",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates Metric of the route."""

    protocol = model.Field(
        name="protocol", key="protocol",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates how the route is learnt/added (`static` or `BGP`)."""


class NetworkInterfaceStatistics(model.Model):

    """Model for network interface statistics."""

    outbound_bytes = model.Field(
        name="outbound_bytes", key="outboundBytes",
        is_required=False, is_read_only=True, is_property=False)
    """Indicates number of bytes transmitted."""

    inbound_bytes = model.Field(
        name="inbound_bytes", key="inboundBytes",
        is_required=False, is_read_only=True, is_property=False)
    """Indicates number of bytes received."""

    rx_total_packets_dropped = model.Field(
        name="rx_total_packets_dropped", key="rxTotalPacketsDropped",
        is_required=False, is_read_only=True, is_property=False)
    """Indicates number of packets dropped in ingress direction."""

    tx_total_packets_dropped = model.Field(
        name="tx_total_packets_dropped", key="txTotalPacketsDropped",
        is_required=False, is_read_only=True, is_property=False)
    """Indicates number of packets dropped in egress direction."""

    tx_rate_kbps = model.Field(
        name="tx_rate_kbps", key="txRateKbps",
        is_required=False, is_read_only=True, is_property=False)
    """Indicates rate at which traffic is going out in Kbps."""

    rx_rate_kbps = model.Field(
        name="rx_rate_kbps", key="rxRateKbps",
        is_required=False, is_read_only=True, is_property=False)
    """Indicates rate at which traffic is coming in in Kbps."""

    tx_rate_limited_packets_dropped = model.Field(
        name="tx_rate_limited_packets_dropped",
        key="txRateLimitedPacketsDropped",
        is_required=False, is_read_only=True, is_property=False)
    """Indicates number of packets dropped in egress direction due to
    rate limiting."""

    rx_rate_limited_packets_dropped = model.Field(
        name="rx_rate_limited_packets_dropped",
        key="rxRateLimitedPacketsDropped",
        is_required=False, is_read_only=True, is_property=False)
    """Indicates number of packets dropped in ingress direction due to
    rate limiting."""

    last_updated = model.Field(
        name="last_updated", key="lastUpdated",
        is_required=False, is_read_only=True, is_property=False)
    """Indicates the time the statistics were last updated."""


class GREConfiguration(model.Model):

    """Model for GRE configuration.

    Indicates details of GRE configuration.
    """

    gre_key = model.Field(
        name="gre_key", key="greKey",
        is_required=False, is_read_only=False, is_property=False)
    """Indicates GRE key."""


class L3Configuration(model.Model):

    """Model for L3 configuration.

    Indicates details of L3 configuration.
    """

    vlan_subnet = model.Field(
        name="vlan_subnet", key="vlanSubnet",
        is_required=False, is_read_only=False, is_property=False)
    """Reference to a logical subnet of L3 connection."""


class NetworkConnections(_BaseHNVModel):

    """Model for network connections.

    The networkConnections resource specifies a connection from virtual
    network to external networks.
    Multiple connections can exist for a given virtual network and there
    are different types of connections.
    """

    _endpoint = ("/networking/v1/virtualGateways/{parent_id}"
                 "/networkConnections/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    connection_type = model.Field(name="connection_type", key="connectionType",
                                  is_required=False, is_read_only=False)
    """Indicates type of connection. Valid keys are `constant.IPSSEC`,
    `constant.GRE`  and `constant.L3`."""
    outbound_kbps = model.Field(name="outbound_kbps",
                                key="outboundKiloBitsPerSecond",
                                is_required=False, is_read_only=False)
    """Indicates maximum allowed outbound bandwidth in Kbps."""

    inbound_bbps = model.Field(name="inbound_bbps",
                               key="inboundKiloBitsPerSecond",
                               is_required=False, is_read_only=False)
    """Indicates maximum allowed outbound bandwidth in Kbps."""

    ipsec_configuration = model.Field(name="ipsec_configuration",
                                      key="ipSecConfiguration",
                                      is_required=False, is_read_only=False)
    """Details of IPsec configuration."""

    ip_address = model.Field(name="ip_address", key="IpAddress",
                             is_required=False, is_read_only=False)
    """Indicates ConnecTo Address to which peers connect to and which is
    the source IP address in egress direction. This would be the VIP."""

    ip_addresses = model.Field(name="ip_addresses", key="ipAddresses",
                               is_required=False, is_read_only=False)
    """IP assigned in the tenant compartment for L3 interface."""

    peer_ip_address = model.Field(name="peer_ip_address",
                                  key="peerIPAddresses",
                                  is_required=False, is_read_only=False)
    """Indicates peer IP address to which connection is made."""

    source_ip_address = model.Field(name="source_ip_address",
                                    key="sourceIPAddress",
                                    is_required=False, is_read_only=False)
    """Indicates sourceIPAddress used by the tunnel. Applicable to
    IKEv2 and GRE."""

    destination_ip_address = model.Field(name="destination_ip_address",
                                         key="destinationIPAddress",
                                         is_required=False, is_read_only=False)
    """Indicates destination ip address of the tunnel. Applicable to
    IKEv2 and GRE."""

    routes = model.Field(name="routes", key="routes",
                         is_required=False, is_read_only=False)
    """List of all the routes (static and those learned via BGP) on the
    network interface. Traffic matching the routes is transmitted on the
    network interface.
    """

    connection_status = model.Field(name="connection_status",
                                    key="connectionStatus",
                                    is_required=False, is_read_only=False)
    """Indicates administrative status of connection.
    Values: `enabled` or `disabled`."""

    connection_state = model.Field(name="connection_state",
                                   key="connectionState",
                                   is_required=False, is_read_only=False)
    """Indicates operational status of connection.
    Values: `Connected` or `Disconnected`.
    """

    statistics = model.Field(name="statistics", key="statistics",
                             is_required=False, is_read_only=False)
    """Statistics of the connection."""

    connection_uptime = model.Field(name="connection_uptime",
                                    key="connectionUpTime",
                                    is_required=False, is_read_only=True)
    """Indicates operations up time of the connection in seconds."""

    connection_error_reason = model.Field(name="connection_error_reason",
                                          key="connectionErrorReason",
                                          is_required=False,
                                          is_read_only=True)
    """Indicates the reason for not being able to connect after dialling
    in the previous attempt."""

    unreachability_reason = model.Field(name="unreachability_reason",
                                        key="unreachabilityReason",
                                        is_required=False, is_read_only=True)
    """Indicates the reason for not being able to connect/dial in the
    previous attempt."""

    gre_configuration = model.Field(name="gre_configuration",
                                    key="greConfiguration",
                                    is_required=False, is_read_only=False)
    """Indicates details of GRE configuration."""

    l3_configuration = model.Field(name="l3_configuration",
                                   key="l3Configuration",
                                   is_required=False, is_read_only=False)
    """Indicates details of L3 configuration."""

    gateway = model.Field(name="gateway", key="gateway",
                          is_required=False, is_read_only=False)

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data.get("properties", {})

        raw_content = properties.get("ipSecConfiguration", None)
        if raw_content is not None:
            ip_sec = IPSecConfiguration.from_raw_data(raw_content)
            properties["ipSecConfiguration"] = ip_sec

        ip_addresses = []
        for raw_content in properties.get("ipAddresses", []):
            ip_addresses.append(IPAddress.from_raw_data(raw_content))
        properties["ipAddresses"] = ip_addresses

        routes = []
        for raw_content in properties.get("routes", []):
            routes.append(NetworkInterfaceRoute.from_raw_data(raw_content))
        properties["routes"] = routes

        raw_content = properties.get("statistics", None)
        if raw_content is not None:
            statistics = NetworkInterfaceStatistics.from_raw_data(
                raw_content)
            properties["statistics"] = statistics

        raw_content = properties.get("greConfiguration", None)
        if raw_content is not None:
            gre_configuration = GREConfiguration.from_raw_data(raw_content)
            properties["greConfiguration"] = gre_configuration

        raw_content = properties.get("l3Configuration", None)
        if raw_content is not None:
            l3_configuration = L3Configuration.from_raw_data(raw_content)
            properties["l3Configuration"] = l3_configuration

        raw_content = properties.get("gateway", None)
        if raw_content is not None:
            gateway = Resource.from_raw_data(raw_content)
            properties["gateway"] = gateway

        return super(NetworkConnections, cls).from_raw_data(raw_data)


class PublicIPAddresses(_BaseHNVModel):

    """Model for public IP addresses.

    The PublicIPAddresses resource specifies an IP address which is publically
    available. This PublicIPAddresses resource is used by the VirtualGateways
    resource and the loadBalancers resource to indicate the IP address that
    can be used to communicate with the virtual network from outside it.
    """

    _endpoint = "/networking/v1/publicIpAddresses/{resource_id}"

    ip_address = model.Field(name="ip_address", key="ipAddress",
                             is_required=False, is_read_only=False)
    """IP address which is allocated.

    The caller can pass in a specific public IP address to be allocated or
    leave it empty.
    """

    allocation_method = model.Field(name="allocation_method",
                                    key="publicIPAllocationMethod",
                                    is_required=False, is_read_only=False)
    """`Dynamic` or `Static`

    In case of static publicIpAllocationMethod, ipAddress property
    needs to be passed indicating the specific public IP address which
    needs to be allocated.
    In case of Dynamic publicIpAllocationMethod, the ipAddress
    property is not meaningful in a PUT (allocation request). In case
    of Dynamic, any free public IP address will be allocated to the
    caller.
    """

    dns_record = model.Field(name="dns_record", key="dnsRecord",
                             is_required=False, is_read_only=False)
    """Properties of a DNS record associated with this public IP address."""

    idle_timeout = model.Field(name="idle_timeout",
                               key="idleTimeoutInMinutes",
                               is_required=False, is_read_only=False)
    """Specifies the timeout for the TCP idle connection.

    The value can be set between 4 and 30 minutes. The default is 4
    minutes. If public IP is used as a frontend IP of a Load Balancer
    this value is ignored.
    """

    ip_configuration = model.Field(name="ip_configuration",
                                   key="ipConfiguration",
                                   is_required=False, is_read_only=True)
    """Reference to an ipConfigurations resource.

    Relative URI of the private IP address with which this public IP is
    associated. Private ip can be defined on NIC, loadBalancers, or
    gateways.
    """

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data.get("properties", {})

        raw_content = properties.get("ipConfiguration", None)
        if raw_content is not None:
            resource = Resource.from_raw_data(raw_content)
            properties["ipConfiguration"] = resource

        return super(PublicIPAddresses, cls).from_raw_data(raw_data)


class BackendAddressPools(_BaseHNVModel):

    """Model for backend address pools.

    This resource represents the list of IPs that can receive network traffic
    that comes via the front-end IPs. The Load Balancing MUX handles incoming
    traffic via the front-end IPs and distributes them to backend IPs based
    on load balancing configuration.
    """

    _endpoint = ("/networking/v1/loadBalancers/{parent_id}"
                 "/backendAddressPools/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    backend_ip_configurations = model.Field(
        name="backend_ip_configurations", key="backendIPConfigurations",
        is_required=False, is_read_only=False)
    """Indicates an array of references to ipConfiguration Resources.

    There is no restriction on having the same IP configurations in multiple
    backendAddressPools. An IpConfiguration can become a part of a
    backendAddressPool by setting a reference to a backendAddressPool resource
    in the loadBalancerBackendAddressPools array field on the IpConfiguration
    resource.
    """

    load_balancing_rules = model.Field(name="load_balancing_rules",
                                       key="loadBalancingRules",
                                       is_required=False, is_read_only=False)
    """Indicates an array of references to the set of loadBalancingRules
    resources that use this backend address pool.
    """

    outbound_nat_rules = model.Field(name="outbound_nat_rules",
                                     key="outboundNatRules",
                                     is_required=False, is_read_only=False)
    """Indicates an array of references to the set of outboundNatRules
    resources that use this backend address pool."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data.get("properties", {})

        backend_ip_configurations = []
        for raw_content in properties.get("backendIPConfigurations", []):
            resource = Resource.from_raw_data(raw_content)
            backend_ip_configurations.append(resource)
        properties["backendIPConfigurations"] = backend_ip_configurations

        load_balancing_rules = []
        for raw_content in properties.get("loadBalancingRules", []):
            resource = Resource.from_raw_data(raw_content)
            load_balancing_rules.append(resource)
        properties["loadBalancingRules"] = load_balancing_rules

        outbound_nat_rules = []
        for raw_content in properties.get("outboundNatRules", []):
            resource = Resource.from_raw_data(raw_content)
            outbound_nat_rules.append(resource)
        properties["outboundNatRules"] = outbound_nat_rules

        return super(BackendAddressPools, cls).from_raw_data(raw_data)


class FrontendIPConfigurations(_BaseHNVModel):

    """Model for frontend ip configurations.

    This resource represents the frontend IP addresses of the load balancer.
    Either a publicIPAddress or a privateIPAddress and subnet must
    be configured.
    """

    _endpoint = ("/networking/v1/loadBalancers/{parent_id}"
                 "/frontendIpConfigurations/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    inbound_nat_rules = model.Field(
        name="inbound_nat_rules", key="inboundNatRules",
        is_required=False, is_read_only=True)
    """Indicates a reference to the inboundNatRules resource used by
    the frontEndIpConfiguration."""

    load_balancing_rules = model.Field(
        name="load_balancing_rules", key="loadBalancingRules",
        is_required=False, is_read_only=False)
    """Indicates a reference to the loadBalancingRules resource used
    by the frontEndIpConfiguration."""

    outbound_nat_rules = model.Field(
        name="outbound_nat_rules", key="outboundNatRules",
        is_required=False, is_read_only=True)
    """Indicates a reference to the outboundNatRules resource used by
    the frontEndIpConfiguration."""

    public_ip_address = model.Field(
        name="public_ip_address", key="publicIPAddress",
        is_required=False, is_read_only=False)
    """Indicates a reference to the publicIPAddresses resource used by
    the frontEndIpConfiguration. If a publicIPAddress is specified,
    then a privateIPaddress is not specified. When a
    publicIPAddress is specified, the privateIpAllocationMethod is
    set to Dynamic.
    """

    private_ip_address = model.Field(name="private_ip_address",
                                     key="privateIPAddress",
                                     is_required=False, is_read_only=False)
    """This is only specified if a specific private IP address identifies an
    IP address which is statically configured for use with this
    frontendIpConfiguration.

    PrivateIPAllocation method MUST be allocated static for this case.
    If a privateIPAddress is specified, a reference to a publicIPaddress
    cannot be specified at the same time. privateIPAddresses can be either
    from the infrastructure address space or from a tenant address space,
    in either case they MUST be accompanied with a valid subnet specified in
    subnet element reference.
    """

    private_ip_allocation_method = model.Field(
        name="private_ip_allocation_method", key="privateIPAllocationMethod",
        is_required=False, is_read_only=False)
    """Static or Dynamic."""

    subnet = model.Field(name="subnet", key="subnet",
                         is_required=False, is_read_only=False)
    """Indicates a references to the subnet resource used by the
    frontendIpConfiguration resource. MUST be specified if a
    privateIPaddress is specified.
    A subnet reference to a logical network subnet is needed if the
    privateIpAddress is from the infrastructure address space. A
    subnet reference to a virtual network subnet is needed if the
    privateIpAddress is from a tenant address space.
    The subnet MUST include the IP address specified in
    privateIpAddress.
    """

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data.get("properties", {})

        load_balancing_rules = []
        for raw_content in properties.get("loadBalancingRules", []):
            resource = Resource.from_raw_data(raw_content)
            load_balancing_rules.append(resource)
        properties["loadBalancingRules"] = load_balancing_rules

        inbound_nat_rules = []
        for raw_content in properties.get("inboundNatRules", []):
            resource = Resource.from_raw_data(raw_content)
            inbound_nat_rules.append(resource)
        properties["inboundNatRules"] = inbound_nat_rules

        outbound_nat_rules = []
        for raw_content in properties.get("outboundNatRules", []):
            resource = Resource.from_raw_data(raw_content)
            outbound_nat_rules.append(resource)
        properties["outboundNatRules"] = outbound_nat_rules

        raw_content = properties.get("subnet", None)
        if raw_content is not None:
            resource = Resource.from_raw_data(raw_content)
            properties["subnet"] = resource

        return super(FrontendIPConfigurations, cls).from_raw_data(raw_data)


class InboundNATRules(_BaseHNVModel):

    """Model for inbound nat rules.

    This resource is used to configure the load balancer to apply
    Network Address Translation of inbound traffic.
    """

    _endpoint = ("/networking/v1/loadBalancers/{parent_id}"
                 "/inboundNatRules/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    backend_ip_configuration = model.Field(
        name="backend_ip_configuration", key="backendIPConfiguration",
        is_required=False, is_read_only=False)
    """Indicates a references to backendAddressPool resource. Traffic
    sent to frontendPort of each of the frontendIPConfigurations is
    forwarded to the backend IP.
    """

    backend_port = model.Field(name="backend_port", key="backendPort",
                               is_required=False, is_read_only=False)
    """Indicates a port used for internal connections on the endpoint.
    The localPort attribute maps the external port on the endpoint
    to an internal port on a role. This is useful in scenarios where a
    role has to communicate to an internal component on a port
    that different from the one that is exposed externally.
    Possible values range between 1 and 65535, inclusive.
    This parameter is required if the protocol is TCP or UDP.
    """

    frontend_ip_configurations = model.Field(
        name="frontend_ip_configurations", key="frontendIPConfigurations",
        is_required=True, is_read_only=False)
    """Indicates an array of references to frontendIPConfigurations
    resources."""

    frontend_port = model.Field(name="frontend_port", key="frontendPort",
                                is_required=False, is_read_only=False)
    """The port for the external endpoint. Any port number can be
    specified, but the port numbers specified for each role in the
    service MUST be unique. Possible values range between 1 and
    65535, inclusive.
    This parameter must be specified if protocol is TCP or UDP.
    """

    protocol = model.Field(name="protocol", key="protocol",
                           is_required=True, is_read_only=False)
    """Indicates the inbound transport protocol for the external
    endpoint. Valid values include `UDP`, `TCP`, `GRE`, `ESP` or `ALL`.
    `ALL` indicates a wildcard.
    """

    idle_timeout = model.Field(name="idle_timeout",
                               key="idleTimeoutInMinutes",
                               is_required=False, is_read_only=False)
    """Specifies the timeout for the TCP idle connection.

    The value can be set between 4 and 30 minutes. The default is 4
    minutes. If public IP is used as a frontend IP of a Load Balancer
    this value is ignored.
    """

    floating_ip = model.Field(name="floating_ip", key="enableFloatingIP",
                              is_required=False, is_read_only=False)
    """
    This specifies that a floating IP will be used on the available servers
    behind a load balancer. Floating IP (VIP) will be forwarded by the load
    balancer to the backend server. The back-end server will be configured
    with that VIP, a datacenter IP and weakhost forwarding.

    Floating IP configuration is required if you are using the SQL AlwaysOn
    Availability Group feature. This setting can't be changed after you create
    the endpoint.
    """

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data.get("properties", {})

        raw_ip_configuration = properties.get("backendIPConfiguration", [])
        if isinstance(raw_ip_configuration, dict):
            raw_ip_configuration = [raw_ip_configuration]

        for raw_content in raw_ip_configuration:
            backend_ip_configuration = Resource.from_raw_data(raw_content)
            properties["backendIPConfiguration"] = backend_ip_configuration

        frontend_ip_configurations = []
        for raw_content in properties.get("frontendIPConfigurations", []):
            resource = Resource.from_raw_data(raw_content)
            frontend_ip_configurations.append(resource)
        properties["frontendIPConfigurations"] = frontend_ip_configurations

        return super(InboundNATRules, cls).from_raw_data(raw_data)


class LoadBalancingRules(_BaseHNVModel):

    """Model for load balancing rules.

    This resource is used to configure load balancing policies. The policies
    dictate the kind of traffic that is load-balanced, and port mapping
    between frontend IPs and backend IPs.
    """

    _endpoint = ("/networking/v1/loadBalancers/{parent_id}"
                 "/loadBalancingRules/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    backend_address_pool = model.Field(
        name="backend_address_pool", key="backendAddressPool",
        is_required=False, is_read_only=False)
    """Indicates an array of references to a BackendAddressPool resource.

    Inbound traffic is randomly load balanced across IPs in the backend pool.
    """

    backend_port = model.Field(name="backend_port", key="backendPort",
                               is_required=False, is_read_only=False)
    """Indicates the port used for internal connections on the endpoint.

    The localPort attribute maps the external port on the endpoint to an
    internal port on a role. This is useful in scenarios where a role has
    to communicate to an internal component on a port that different from
    the one that is exposed externally. If not specified, the value of
    localPort is the same as the port attribute. Set the value of localPort
    to "*" to automatically assign an unallocated port that is discoverable
    using the runtime API.
    Possible values range between 1 and 65535, inclusive.
    This parameter is required if the protocol is TCP or UDP.
    """

    frontend_ip_configurations = model.Field(
        name="frontend_ip_configurations", key="frontendIPConfigurations",
        is_required=True, is_read_only=False)
    """Indicates an array of references to FrontendIPAddress resources."""

    frontend_port = model.Field(name="frontend_port", key="frontendPort",
                                is_required=False, is_read_only=False)
    """Indicates the port for the external endpoint.

    Possible values range between 1 and 65535, inclusive. This value MUST
    be unique for the loadbalancer resource.
    This parameter is required if the protocol is TCP or UDP.
    """

    idle_timeout = model.Field(
        name="idle_timeout", key="idleTimeoutInMinutes",
        is_required=False, is_read_only=False)
    """Indicates the timeout for the Tcp idle connection in the inbound
    direction, i.e. a connection initiated by an internet client to a VIP.
    The value can be set between 4 and 30 minutes. The default value is
    4 minutes.
    """

    protocol = model.Field(name="protocol", key="protocol",
                           is_required=True, is_read_only=False)
    """Indicates the inbound transport protocol for the external endpoint.
    Valid values include `UDP`, `TCP`, `GRE`, `ESP` or `ALL`.
    """

    probe = model.Field(name="probe", key="probe",
                        is_required=False, is_read_only=False)
    """Indicates a reference to the probe resource used by this
    LoadBalancingRule.
    """

    floating_ip = model.Field(name="floating_ip", key="enableFloatingIP",
                              is_required=False, is_read_only=False)
    """
    This specifies that a floating IP will be used on the available servers
    behind a load balancer. Floating IP (VIP) will be forwarded by the load
    balancer to the backend server. The back-end server will be configured
    with that VIP, a datacenter IP and weakhost forwarding.

    Floating IP configuration is required if you are using the SQL AlwaysOn
    Availability Group feature. This setting can't be changed after you create
    the endpoint.
    """

    load_distribution = model.Field(
        name="load_distribution", key="loadDistribution",
        is_required=False, is_read_only=False)
    """This specifies the load balancing distribution type to be used by
    the load balancer. The loadBalancer uses a distribution algorithm which
    is a 5 tuple (source IP, source port, destination IP, destination port,
    protocol type) hash to map traffic to available servers. It provides
    stickiness only within a transport session, which is a feature that routes
    the requests for a particular session to the same physical machine that
    serviced the first request for that session. Packets in the same TCP or
    UDP session will be directed to the same datacenter IP instance behind the
    load balanced endpoint. When the client closes and re-opens the connection
    or starts a new session from the same source IP, the source port changes
    and causes the traffic to go to a different datacenter IP endpoint.

    The loadBalancer can be configured to use a 2 tuple (Source IP,
    Destination IP) or 3 tuple (Source IP, Destination IP, Protocol) to map
    traffic to the available servers. By using SourceIPProtocol, connections
    initiated from the same client computer goes to the same datacenter IP
    endpoint.
        * Default - The load balancer is configured to use a 5 tuple hash
    to map traffic to available servers
        * SourceIP - The load balancer is configured to use a 2 tuple hash
    to map traffic to available servers
        * SourceIPProtocol - The load balancer is configured to use a 3 tuple
    hash to map traffic to available servers
    """

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data.get("properties", {})

        frontend_ip_configurations = []
        for raw_content in properties.get("frontendIPConfigurations", []):
            resource = Resource.from_raw_data(raw_content)
            frontend_ip_configurations.append(resource)
        properties["frontendIPConfigurations"] = frontend_ip_configurations

        raw_content = properties.get("backendAddressPool", None)
        if raw_content is not None:
            resource = Resource.from_raw_data(raw_content)
            properties["backendAddressPool"] = resource

        raw_content = properties.get("probe", None)
        if raw_content is not None:
            resource = Resource.from_raw_data(raw_content)
            properties["probe"] = resource

        return super(LoadBalancingRules, cls).from_raw_data(raw_data)


class OutboundNATRules(_BaseHNVModel):

    """Model for outbound NAT rules.

    This resource is used to configure the load balancer to apply
    Network Address Translation of outbound traffic.
    """

    _endpoint = ("/networking/v1/loadBalancers/{parent_id}"
                 "/outboundNatRules/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    frontend_ip_configurations = model.Field(
        name="frontend_ip_configurations", key="frontendIPConfigurations",
        is_required=True, is_read_only=False)
    """Indicates an array of frontendIpConfigurations resources.

    Indicates an array of references to frontendIpAddress resources.
    """

    backend_address_pool = model.Field(
        name="backend_address_pool", key="backendAddressPool",
        is_required=True, is_read_only=False)
    """Indicates a reference to the backendAddressPool resource.

    This is the pool of IP addresses where outbound traffic originates.
    """

    protocol = model.Field(
        name="protocol", key="protocol",
        is_required=True, is_read_only=False)
    """Protocol for outbound traffic. For transparent outbound NAT
    specify "all".
    Valid values include `TCP`, `UDP`, `GRE`, `ESP` or `All`.
    """

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data.get("properties", {})

        frontend_ip_configurations = []
        for raw_content in properties.get("frontendIPConfigurations", []):
            resource = Resource.from_raw_data(raw_content)
            frontend_ip_configurations.append(resource)
        properties["frontendIPConfigurations"] = frontend_ip_configurations

        raw_content = properties.get("backendAddressPool", None)
        if raw_content is not None:
            resource = Resource.from_raw_data(raw_content)
            properties["backendAddressPool"] = resource

        return super(OutboundNATRules, cls).from_raw_data(raw_data)


class Probes(_BaseHNVModel):

    """Model for probes."""

    _endpoint = ("/networking/v1/loadBalancers/{parent_id}"
                 "/probes/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    interval = model.Field(name="interval", key="intervalInSeconds",
                           is_required=False, is_read_only=False)
    """Indicates the interval, in seconds, for how frequently to probe the
    endpoint for health status. Typically, the interval is slightly less than
    half the allocated timeout period (in seconds) which allows two full
    probes before taking the instance out of rotation. The default value is
    15, the minimum value is 5.
    """

    load_balancing_rules = model.Field(
        name="load_balancing_rules", key="loadBalancingRules",
        is_required=False, is_read_only=True)
    """Indicates an array of references to loadBalancingRule resources that
    use this probe.
    """

    number_of_probes = model.Field(
        name="number_of_probes", key="numberOfProbes",
        is_required=False, is_read_only=False)
    """Indicates the timeout period, in seconds, applied to the probe where
    no response will result in stopping further traffic from being delivered
    to the endpoint. This value allows endpoints to be taken out of rotation
    faster or slower than the typical times (which are the defaults).
    The default value is 31, the minimum value is 11.
    """

    protocol = model.Field(name="protocol", key="protocol",
                           is_required=True, is_read_only=False)
    """Indicates the protocol of the end point.

    Valid values are `HTTP` or `TCP`. If `TCP` is specified, a received ACK
    is required for the probe to be successful. If `HTTP` is specified,
    a 200 OK response from the specified URI is required for the probe to
    be successful.
    """

    port = model.Field(name="port", key="port",
                       is_required=True, is_read_only=False)
    """Indicates the port for communicating the probe. Possible values range
    from 1 to 65535, inclusive.
    """

    request_path = model.Field(name="request_path", key="requestPath",
                               is_required=True, is_read_only=False)
    """Indicates the URI used for requesting health status from the VM.

    The path is required if protocol is set to HTTP. Otherwise, it is not
    allowed. There is no default value.
    """

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data.get("properties", {})

        load_balancing_rules = []
        for raw_content in properties.get("loadBalancingRules", []):
            resource = Resource.from_raw_data(raw_content)
            load_balancing_rules.append(resource)
        properties["loadBalancingRules"] = load_balancing_rules

        return super(Probes, cls).from_raw_data(raw_data)


class LoadBalancers(_BaseHNVModel):

    """Model for load balancers.

    The loadBalancers resource allows fine-grained configuration of the
    distribution of incoming traffic across VM instances that are hosted
    in a Windows Server and System Center cloud. This resource has two
    main parts: a frontend and a backend configuration.

    The frontend configuration exposes the IP address of the load balancer.
    For example, this address can be a reserved public or private IP address
    previously provided to the client, or it can be an IP address that is
    dynamically allocated from a subnet of a virtual network.
    """

    _endpoint = "/networking/v1/loadBalancers/{resource_id}"

    backend_address_pools = model.Field(name="backend_address_pools",
                                        key="backendAddressPools",
                                        is_required=False, is_read_only=False)
    """Indicates the backend Address Pool of the load balancer."""

    frontend_ip_configurations = model.Field(
        name="frontend_ip_configurations", key="frontendIPConfigurations",
        is_required=True, is_read_only=False)
    """Indicates the frontend IP addresses of the load balancer."""

    load_balancing_rules = model.Field(name="load_balancing_rules",
                                       key="loadBalancingRules",
                                       is_required=False, is_read_only=False)
    """A list of load balancing configurations.

    Each configuration describes what traffic and how it gets load balanced
    between backend IPs.
    """

    inbound_nat_rules = model.Field(name="inbound_nat_rules",
                                    key="inboundNatRules",
                                    is_required=False, is_read_only=False)
    """Indicates an array of inbound NAT rules configured for the
    load balancer.
    """

    outbound_nat_rules = model.Field(name="outbound_nat_rules",
                                     key="outboundNatRules",
                                     is_required=False, is_read_only=False)
    """Indicates an array of outbound NAT rules configured for the
    load balancer.
    """

    probes = model.Field(name="probes", key="probes",
                         is_required=False, is_read_only=False)
    """Indicates an array of probes configured for the
    load balancer.
    """

    @classmethod
    def from_raw_data(cls, raw_data):
        properties = raw_data.get("properties", {})

        backend_address_pools = []
        for raw_content in properties.get("backendAddressPools", []):
            raw_content["parentResourceID"] = raw_data["resourceId"]
            address_pool = BackendAddressPools.from_raw_data(raw_content)
            backend_address_pools.append(address_pool)
        properties["backendAddressPools"] = backend_address_pools

        frontend_ip_configurations = []
        for raw_content in properties.get("frontendIPConfigurations", []):
            raw_content["parentResourceID"] = raw_data["resourceId"]
            ip_configurations = FrontendIPConfigurations.from_raw_data(
                raw_content)
            frontend_ip_configurations.append(ip_configurations)
        properties["frontendIPConfigurations"] = frontend_ip_configurations

        inbound_nat_rules = []
        for raw_content in properties.get("inboundNatRules", []):
            raw_content["parentResourceID"] = raw_data["resourceId"]
            inbound_nat_rule = InboundNATRules.from_raw_data(raw_content)
            inbound_nat_rules.append(inbound_nat_rule)
        properties["inboundNatRules"] = inbound_nat_rules

        outbound_nat_rules = []
        for raw_content in properties.get("outboundNatRules", []):
            raw_content["parentResourceID"] = raw_data["resourceId"]
            inbound_nat_rule = OutboundNATRules.from_raw_data(raw_content)
            outbound_nat_rules.append(inbound_nat_rule)
        properties["outboundNatRules"] = outbound_nat_rules

        load_balancing_rules = []
        for raw_content in properties.get("loadBalancingRules", []):
            raw_content["parentResourceID"] = raw_data["resourceId"]
            balancing_rule = LoadBalancingRules.from_raw_data(raw_content)
            load_balancing_rules.append(balancing_rule)
        properties["loadBalancingRules"] = load_balancing_rules

        probes = []
        for raw_content in properties.get("probes", []):
            raw_content["parentResourceID"] = raw_data["resourceId"]
            probe = Probes.from_raw_data(raw_content)
            probes.append(probe)
        properties["probes"] = probes

        return super(LoadBalancers, cls).from_raw_data(raw_data)


class _BGPPeersStatistics(model.Model):

    """Base model for BGP peers statistics submodels."""

    last_sent = model.Field(
        name="last_sent", key="lastsent",
        is_property=False, is_required=False, is_read_only=True)
    """Last sent timestamp."""

    last_received = model.Field(
        name="last_received", key="lastReceived",
        is_property=False, is_required=False, is_read_only=True)
    """Last received timestamp."""

    sent_count = model.Field(
        name="sent_count", key="sentCount",
        is_property=False, is_required=False, is_read_only=True)
    """Sent count."""

    received_count = model.Field(
        name="received_count", key="receivedCount",
        is_property=False, is_required=False, is_read_only=True)
    """Received count."""


class OpenMessageStatistics(_BGPPeersStatistics):

    """Model for open message statistics."""

    pass


class NotificationMessageStatistics(_BGPPeersStatistics):

    """Model for notification message statistics."""

    pass


class KeepAliveMessageStatistics(_BGPPeersStatistics):

    """Model for keep alive message statistics."""

    pass


class RouteRefreshMessageStatistics(_BGPPeersStatistics):

    """Model for route regresh message statistics."""

    pass


class UpdateMessageStatistics(_BGPPeersStatistics):

    """Model for update message statistics."""

    pass


class _StatisticsRoute(model.Model):

    """Base model for IPV4 and IPV6 route statistics."""

    update_sent_count = model.Field(
        name="update_sent_count", key="updateSentCount",
        is_property=False, is_required=False, is_read_only=True)
    """Route update sent count."""

    update_received_count = model.Field(
        name="update_received_count", key="updateReceivedCount",
        is_property=False, is_required=False, is_read_only=True)
    """Route update received count."""

    withdrawl_sent_count = model.Field(
        name="withdraw_sent_count", key="withdrawlSentCount",
        is_property=False, is_required=False, is_read_only=True)
    """Route withdrawal sent count."""

    withdrawl_received_count = model.Field(
        name="withdraw_received_count", key="withdrawlReceivedCount",
        is_property=False, is_required=False, is_read_only=True)
    """Route withdrawal received count."""


class IPV4Route(_StatisticsRoute):

    """Stats for IPv4 routes."""

    pass


class IPV6Route(_StatisticsRoute):

    """Stats for IPv6 routes."""

    pass


class BGPPeersStatistics(model.Model):

    """Provides statistics for this peer."""

    tcp_connection_established = model.Field(
        name="tcp_connection_established", key="tcpConnectionEstablished",
        is_property=False, is_required=False, is_read_only=True)
    """Timestamp of TCP connection establishment for BGP."""

    tcp_connection_closed = model.Field(
        name="tcp_connection_closed", key="tcpConnectionClosed",
        is_property=False, is_required=False, is_read_only=True)
    """Timestamp of TCP connection closed for BGP."""

    open_message_stats = model.Field(
        name="open_message_stats", key="openMessageStats",
        is_property=False, is_required=False, is_read_only=True)
    """Instance of OpenMessageStatistics."""

    notification_message_stats = model.Field(
        name="notification_message_stats", key="notificationMessageStats",
        is_property=False, is_required=False, is_read_only=True)
    """Instance of NotificationMessageStatistics."""

    keep_alive_message_stats = model.Field(
        name="keep_alive_message_stats", key="keepAliveMessageStats",
        is_property=False, is_required=False, is_read_only=True)
    """Instance of KeepAliveMessageStatistics."""

    route_refresh_message_stats = model.Field(
        name="route_refresh_message_stats", key="routeRefreshMessageStats",
        is_property=False, is_required=False, is_read_only=True)
    """Instance of RouteRefreshMessageStatistics."""

    update_message_stats = model.Field(
        name="update_message_stats", key="updateMessageStats",
        is_property=False, is_required=False, is_read_only=True)
    """Instance of UpdateMessageStatistics."""

    ipv4_route_stats = model.Field(
        name="ipv4_route_stats", key="ipv4Route",
        is_property=False, is_required=False, is_read_only=True)
    """Stats for IPv4 routes."""

    ipv6_route_stats = model.Field(
        name="ipv6_route_stats", key="ipv6Route",
        is_property=False, is_required=False, is_read_only=True)
    """Stats for IPv6 routes."""

    last_updated = model.Field(
        name="last_updated", key="lastUpdated",
        is_property=False, is_required=False, is_read_only=True)
    """Time stamp when the stats were last updated."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""

        # pylint: disable=redefined-variable-type

        raw_content = raw_data.get("updateMessageStats", None)
        if raw_content is not None:
            statistics = UpdateMessageStatistics.from_raw_data(raw_content)
            raw_data["updateMessageStats"] = statistics

        raw_content = raw_data.get("routeRefreshMessageStats", None)
        if raw_content is not None:
            statistics = RouteRefreshMessageStatistics.from_raw_data(
                raw_content)
            raw_data["routeRefreshMessageStats"] = statistics

        raw_content = raw_data.get("keepAliveMessageStats", None)
        if raw_content is not None:
            statistics = KeepAliveMessageStatistics.from_raw_data(raw_content)
            raw_data["keepAliveMessageStats"] = statistics

        raw_content = raw_data.get("notificationMessageStats", None)
        if raw_content is not None:
            statistics = NotificationMessageStatistics.from_raw_data(
                raw_content)
            raw_data["notificationMessageStats"] = statistics

        raw_content = raw_data.get("openMessageStats", None)
        if raw_content is not None:
            statistics = OpenMessageStatistics.from_raw_data(raw_content)
            raw_data["openMessageStats"] = statistics

        raw_content = raw_data.get("ipv4Route", None)
        if raw_content is not None:
            statistics = IPV4Route.from_raw_data(raw_content)
            raw_data["ipv4Route"] = statistics

        raw_content = raw_data.get("ipv6Route", None)
        if raw_content is not None:
            statistics = IPV6Route.from_raw_data(raw_content)
            raw_data["ipv6Route"] = statistics

        return super(BGPPeersStatistics, cls).from_raw_data(raw_data)


class BGPPeers(_BaseHNVModel):

    """Model for BGP peers.

    This resource configures BGP peers of the virtualGateways resource.
    The peer is identified by remoteRouterId and asNumber. A VRF context
    can be specified on devices that support VRF. The routeMapIn and
    routeMapOut properties can specify a policy map that controls the
    route updates that are associated with the BGP peer.
    """

    _endpoint = ("/networking/v1/virtualGateways/{grandparent_id}"
                 "/bgpRouters/{parent_id}/bgpPeers/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=False, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    grandparent_id = model.Field(
        name="grandparent_id", key="grandParentResourceID",
        is_property=False, is_required=False, is_read_only=True)
    """The grand parent resource ID field contains the resource ID that
    is associated with network objects that are ancestors of the parent
    of the necessary resource."""

    connection_state = model.Field(
        name="connection_state", key="connectionState",
        is_required=False, is_read_only=True)
    """Status of BGP peering for this peer. Possible values are `Connected` and
    `Disconnected`."""

    asn_number = model.Field(name="asn_number", key="asNumber",
                             is_required=False, is_read_only=True)
    """Indicates the ASN number of the BGP Peer."""

    ext_asn_number = model.Field(name="ext_asn_number", key="extAsNumber",
                                 is_required=False, is_read_only=False)
    """Indicates Extended ASN number of the BGP Peer in XX.YY format."""

    peer_ip_address = model.Field(name="peer_ip_address", key="peerIpAddress",
                                  is_required=False, is_read_only=False)
    """IP address of the peer."""

    statistics = model.Field(name="statistics", key="statistics",
                             is_required=False, is_read_only=True)
    """Provides statistics for this peer."""

    policy_map_out = model.Field(name="policy_map_out", key="policyMapOut",
                                 is_required=False, is_read_only=False)
    """Reference to the policy map object that is used to filter
    the routing updates sent to the peer."""

    policy_map_in = model.Field(name="policy_map_in", key="policyMapIn",
                                is_required=False, is_read_only=False)
    """Reference to the policy map object that is used to filter
    routing updates received from the peer."""

    is_generated = model.Field(name="is_generated", key="isGenerated",
                               is_required=False, is_read_only=True)
    """This flag is set to `True` for iBGP peers."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data.get("properties", {})

        raw_content = properties.get("statistics", None)
        if raw_content is not None:
            statistics = BGPPeersStatistics.from_raw_data(raw_content)
            properties["statistics"] = statistics

        super(BGPPeers, cls).from_raw_data(raw_data)


class BGPRouters(_BaseHNVModel):

    """Model for BGP routers.

    The BGP Router resource contains the configuration needed for the Border
    Gateway Protocol (BGP) router in the virtual gateway to connect to BGP
    routers outside the virtual network in order to exchange routing
    information.
    """

    _endpoint = ("/networking/v1/virtualGateways/{parent_id}"
                 "/bgpRouters/{resource_id}")

    parent_id = model.Field(
        name="parent_id", key="parentResourceID",
        is_property=False, is_required=True, is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    require_igp_sync = model.Field(
        name="require_igp_sync", key="requireIgpSync",
        is_required=True, is_read_only=False)

    is_enabled = model.Field(name="is_enabled", key="isEnabled",
                             is_required=True, is_read_only=False)

    is_generated = model.Field(name="is_generated", key="isGenerated",
                               is_required=False, is_read_only=True)
    """If this BGP router is automatically enabled, without making any REST
    calls then isGenerated is set to `True`."""

    ext_as_number = model.Field(name="ext_as_number", key="extAsNumber",
                                is_required=False, is_read_only=False)
    """Extended (4-byte) ASN of the local BGP Router in XX.YY format."""

    router_id = model.Field(name="router_id", key="routerId",
                            is_required=False, is_read_only=False)
    """Indicates Router ID."""

    router_ip = model.Field(
        name="router_ip", key="routerIP",
        is_required=False, is_read_only=False)
    """Indicates IP addresses to which BGP peering can be established."""

    bgp_peers = model.Field(name="bgp_peers", key="bgpPeers",
                            is_required=False, is_read_only=False)
    """Collection of BGP peers associated with the BGP Routers resource."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data.get("properties", {})

        bgp_peers = []
        for raw_content in properties.get("bgpPeers", []):
            raw_content["parentResourceID"] = raw_data["resourceId"]
            raw_content["grandParentResourceID"] = raw_data["parentResourceID"]
            bgp_peers.append(BGPPeers.from_raw_data(raw_content))
        properties["bgpPeers"] = bgp_peers

        return super(BGPRouters, cls).from_raw_data(raw_data)


class LoadBalancerManager(_BaseHNVModel):

    """Model for load balancer manager.

    The LoadBalancerManager resource is a singleton resource that configures
    the load balancing service of the Network Controller.
    """

    _endpoint = "/networking/v1/loadBalancerManager/config"

    manager_ip_address = model.Field(
        name="manager_ip_address", key="loadBalancerManagerIPAddress",
        is_property=True, is_required=True, is_read_only=False)
    """The IP address of the load balancer service. This is part of one of
    the FrontendIPPools as specified in the FrontendIPPool element in this
    resource."""

    outbound_nat_ip = model.Field(
        name="outbound_nat_ip", key="outboundNatIPExemptions",
        is_property=True, is_required=True, is_read_only=False)
    """An array of v4 or v6 subnets masks with prefixes that will not have
    the source IP and Port changed by being NAT-ed. This is typically used
    for datacenter services that will communicated with other services within
    the same datacenter or cluster. Array of strings in the following format:
    0.0.0.0/0.

    NOTE: There is no validation that these IP addresses are known by the
    Network Controller."""

    vip_ip_pools = model.Field(
        name="vip_ip_pools", key="vipIpPools",
        is_property=True, is_required=True, is_read_only=False)
    """An array of references to ipPool resource that will be used for the
    frontend IP Addresses.
    """

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        properties = raw_data.get("properties", {})

        vip_ip_pools = []
        for raw_content in properties.get("vipIpPools", []):
            resource = Resource.from_raw_data(raw_content)
            vip_ip_pools.append(resource)
        properties["vipIpPools"] = vip_ip_pools

        return super(LoadBalancerManager, cls).from_raw_data(raw_data)
