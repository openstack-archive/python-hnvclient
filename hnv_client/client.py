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

import time
import uuid

from oslo_log import log as logging

from hnv_client.common import constant
from hnv_client.common import exception
from hnv_client.common import model
from hnv_client.common import utils
from hnv_client import config as hnv_config

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

    parent_id = model.Field(name="parent_id",
                            key="parentResourceID",
                            is_property=False, is_required=False,
                            is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    grandparent_id = model.Field(name="grandparent_id",
                                 key="grandParentResourceID",
                                 is_property=False, is_required=False,
                                 is_read_only=True)
    """The grand parent resource ID field contains the resource ID that
    is associated with network objects that are ancestors of the parent
    of the necessary resource."""

    instance_id = model.Field(name="instance_id", key="instanceId",
                              is_property=False)
    """The globally unique Id generated and used internally by the Network
    Controller. The mapping resource that enables the client to map between
    the instanceId and the resourceId."""

    etag = model.Field(name="etag", key="etag", is_property=False)
    """An opaque string representing the state of the resource at the
    time the response was generated."""

    tags = model.Field(name="tags", key="tags", is_property=False,
                       is_required=False)

    provisioning_state = model.Field(name="provisioning_state",
                                     key="provisioningState",
                                     is_read_only=True, is_required=False)
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    @staticmethod
    def _get_client():
        """Create a new client for the HNV REST API."""
        return utils.get_client(url=CONFIG.HNV.url,
                                username=CONFIG.HNV.username,
                                password=CONFIG.HNV.password,
                                allow_insecure=CONFIG.HNV.https_allow_insecure,
                                ca_bundle=CONFIG.HNV.https_ca_bundle)

    @classmethod
    def get(cls, resource_id=None, parent_id=None):
        """Retrieves the required resources.

        :param resource_id:      The identifier for the specific resource
                                 within the resource type.
        :param parent_id:        The identifier for the specific ancestor
                                 resource within the resource type.
        """
        client = cls._get_client()
        endpoint = cls._endpoint.format(resource_id=resource_id or "",
                                        parent_id=parent_id or "")
        raw_data = client.get_resource(endpoint)
        if resource_id is None:
            return [cls.from_raw_data(item) for item in raw_data["value"]]
        else:
            return cls.from_raw_data(raw_data)

    @classmethod
    def remove(cls, resource_id, parent_id=None, wait=True, timeout=None):
        """Delete the required resource.

        :param resource_id:   The identifier for the specific resource
                              within the resource type.
        :param parent_id:     The identifier for the specific ancestor
                              resource within the resource type.
        :param wait:          Whether to wait until the operation is completed
        :param timeout:       The maximum amount of time required for this
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
                                        parent_id=parent_id or "")
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

    def commit(self, wait=True, timeout=None):
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
        super(_BaseHNVModel, self).commit(wait=wait, timeout=timeout)
        client = self._get_client()
        endpoint = self._endpoint.format(resource_id=self.resource_id or "",
                                         parent_id=self.parent_id or "")
        request_body = self.dump(include_read_only=False)
        response = client.update_resource(endpoint, data=request_body)

        elapsed_time = 0
        while wait:
            response = client.get_resource(endpoint)
            properties = response.get("properties", {})
            provisioning_state = properties.get("provisioningState", None)
            if not provisioning_state:
                raise exception.ServiceException("The object doesn't contain "
                                                 "`provisioningState`.")
            if provisioning_state == constant.FAILED:
                raise exception.ServiceException(
                    "Failed to complete the required operation.")
            elif provisioning_state == constant.SUCCEEDED:
                break

            elapsed_time += CONFIG.HNV.retry_interval
            if timeout and elapsed_time > timeout:
                raise exception.TimeOut("The request timed out.")
            time.sleep(CONFIG.HNV.retry_interval)

        # Process the raw data from the update response
        fields = self.process_raw_data(response)
        # Set back the provision flag
        self._provision_done = False
        # Update the current model representation
        self._set_fields(fields)
        # Lock the current model
        self._provision_done = True


class Resource(model.Model):

    """Model for the resource references."""

    resource_ref = model.Field(name="resource_ref", key="resourceRef",
                               is_property=False, is_required=True)
    """A relative URI to an associated resource."""


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
                 "/logicalSubnets/{parent_id}/ipPools/{resource_id}")

    parent_id = model.Field(name="parent_id",
                            key="parentResourceID",
                            is_property=False, is_required=True,
                            is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    grandparent_id = model.Field(name="grandparent_id",
                                 key="grandParentResourceID",
                                 is_property=False, is_required=True,
                                 is_read_only=True)
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

    parent_id = model.Field(name="parent_id",
                            key="parentResourceID",
                            is_property=False, is_required=True,
                            is_read_only=True)
    """The parent resource ID field contains the resource ID that is
    associated with network objects that are ancestors of the necessary
    resource.
    """

    address_prefix = model.Field(name="address_prefix", key="addressPrefix")
    """Identifies the subnet id in form of ipAddresss/prefixlength."""

    vlan_id = model.Field(name="vlan_id", key="vlanId", is_required=True,
                          default=0)
    """Indicates the VLAN ID associated with the logical subnet."""

    routes = model.Field(name="routes", key="routes", is_required=False)
    """Indicates the routes that are contained in the logical subnet."""

    ip_pools = model.Field(name="ip_pools", key="ipPools",
                           is_required=False)
    """Indicates the IP Pools that are contained in the logical subnet."""

    dns_servers = model.Field(name="dns_servers", key="dnsServers",
                              is_required=False)
    """Indicates one or more DNS servers that are used for resolving DNS
    queries by devices or host connected to this logical subnet."""

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

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        ip_pools = []
        properties = raw_data["properties"]
        for raw_ip_pool in properties.get("ipPools", []):
            raw_ip_pool["parentResourceID"] = raw_data["resourceId"]
            raw_ip_pool["grandParentResourceID"] = raw_data["parentResourceID"]
            ip_pools.append(IPPools.from_raw_data(raw_ip_pool))
        properties["ipPools"] = ip_pools

        return super(LogicalSubnetworks, cls).from_raw_data(raw_data)


class LogicalNetworks(_BaseHNVModel):

    """Logical networks model.

    The logicalNetworks resource represents a logical partition of physical
    network that is dedicated for a specific purpose.
    A logical network comprises of a collection of logical subnets.
    """

    _endpoint = "/networking/v1/logicalNetworks/{resource_id}"

    subnetworks = model.Field(name="subnetworks", key="subnets",
                              is_required=False, default=[])
    """Indicates the subnets that are contained in the logical network."""

    network_virtualization_enabled = model.Field(
        name="network_virtualization_enabled",
        key="networkVirtualizationEnabled", default=False, is_required=False)
    """Indicates if the network is enabled to be the Provider Address network
    for one or more virtual networks. Valid values are `True` or `False`.
    The default is `False`."""

    virtual_networks = model.Field(name="virtual_networks",
                                   key="virtualNetworks",
                                   is_read_only=True)
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
