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

"""This module contains fake HVN API response."""

import json
import pkg_resources

from hnv.common import utils


class FakeResponse(object):

    """HNV API fake responses."""

    def __init__(self):
        self._resources = "hnv.tests.fake.response"
        self._cache = {}

    def _load_resource(self, resource):
        """Load the json response for the required resource."""
        if resource not in self._cache:
            resource_stream = pkg_resources.resource_stream(
                self._resources, resource)
            json_response = utils.get_as_string(resource_stream.read())
            self._cache[resource] = json.loads(json_response)
        return self._cache[resource]

    def logical_networks(self):
        """Fake GET(all) response for logical networks."""
        return self._load_resource("logical_networks.json")

    def logical_subnets(self):
        """Fake GET(all) response for logical subnets."""
        return self._load_resource("logical_subnets.json")

    def ip_pools(self):
        """Fake GET(all) response for IP pools."""
        return self._load_resource("ip_pools.json")

    def network_interfaces(self):
        """Fake GET(all) response for network interfaces."""
        return self._load_resource("network_interfaces.json")

    def ip_configurations(self):
        """Fake GET(all) response for ip configurations."""
        return self._load_resource("ip_configurations.json")

    def virtual_networks(self):
        """Fake GET(all) response for virtual networks."""
        return self._load_resource("virtual_networks.json")

    def virtual_subnetworks(self):
        """Fake GET(all) response for virtual subnetworks."""
        return self._load_resource("virtual_subnetworks.json")

    def acl_rules(self):
        """Fake GET(all) response for ACL rules."""
        return self._load_resource("acl_rules.json")

    def acl(self):
        """Fake GET(all) response for ACL."""
        return self._load_resource("acl.json")

    def virtual_switch_manager(self):
        """Fake GET response for virtual switch manager."""
        return self._load_resource("virtual_switch_manager.json")

    def routes(self):
        """Fake GET(all) response for routes."""
        return self._load_resource("routes.json")

    def route_tables(self):
        """Fake GET(all) response for route tables."""
        return self._load_resource("route_tables.json")

    def network_connections(self):
        """Fake GET(all) response for network connections."""
        return self._load_resource("network_connections.json")

    def public_ip_addresses(self):
        """Fake GET(all) response for public IP addresses."""
        return self._load_resource("public_ip_addresses.json")

    def backend_address_pools(self):
        """Fake GET(all) response for backend address pools."""
        return self._load_resource("backend_address_pools.json")

    def frontend_ip_configurations(self):
        """Fake GET(all) response for frontend ip configurations."""
        return self._load_resource("frontend_ip_configurations.json")

    def inbound_nat_rules(self):
        """Fake GET(all) response for inbound nat rules."""
        return self._load_resource("inbound_nat_rules.json")

    def load_balancing_rules(self):
        """Fake GET(all) response for load balacing rules."""
        return self._load_resource("load_balancing_rules.json")

    def outbound_nat_rules(self):
        """Fake GET(all) response for outbound nat rules."""
        return self._load_resource("outbound_nat_rules.json")

    def probes(self):
        """Fake GET(all) response for probes."""
        return self._load_resource("probes.json")

    def load_balancers(self):
        """Fake GET(all) response for load balancers."""
        return self._load_resource("load_balancers.json")

    def bgp_peers(self):
        """Fake GET(all) response for BGP peers."""
        return self._load_resource("bgp_peers.json")

    def bgp_routers(self):
        """Fake GET(all) response for BGP routers."""
        return self._load_resource("bgp_routers.json")

    def load_balancer_manager(self):
        """Fake GET response for load balancer manager."""
        return self._load_resource("load_balancer_manager.json")

    def load_balancer_mux(self):
        """Fake GET(all) response for load balancer mux."""
        return self._load_resource("load_balancer_mux.json")
