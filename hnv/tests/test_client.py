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

# pylint: disable=protected-access

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from hnv import client
from hnv.common import constant
from hnv.common import exception
from hnv import config as hnv_config
from hnv.tests.fake import fake_response
from hnv.tests import utils as test_utils

CONFIG = hnv_config.CONFIG


class TestBaseHNVModel(unittest.TestCase):

    def setUp(self):
        client._BaseHNVModel._endpoint = "{parent_id}/{resource_id}"

    @mock.patch("hnv.client._BaseHNVModel.process_raw_data")
    @mock.patch("hnv.client._BaseHNVModel._set_fields")
    def test_reset_model(self, mock_set_fields, mock_process):
        resource = client._BaseHNVModel()

        mock_process.return_value = mock.sentinel.fields
        mock_set_fields.reset_mock()

        resource._reset_model(mock.sentinel.response)

        mock_process.assert_called_once_with(mock.sentinel.response)
        mock_set_fields.assert_called_once_with(mock.sentinel.fields)

    @mock.patch("hnv.client._BaseHNVModel.from_raw_data")
    @mock.patch("hnv.client._BaseHNVModel._get_client")
    def test_get(self, mock_get_client, mock_from_raw_data):
        mock_from_raw_data.return_value = mock.sentinel.resource
        http_client = mock_get_client.return_value = mock.Mock()
        get_resource = http_client.get_resource = mock.Mock()
        get_resource.return_value = {}

        resource = client._BaseHNVModel.get(resource_id="hnv-client-test")

        get_resource.assert_called_once_with("/hnv-client-test")
        self.assertIs(resource, mock.sentinel.resource)

    @mock.patch("hnv.client._BaseHNVModel.from_raw_data")
    @mock.patch("hnv.client._BaseHNVModel._get_client")
    def test_get_all(self, mock_get_client, mock_from_raw_data):
        mock_from_raw_data.side_effect = [{} for index in range(10)]

        http_client = mock_get_client.return_value = mock.Mock()
        get_resource = http_client.get_resource = mock.Mock()
        get_resource.return_value = {"value": [{} for _ in range(10)]}

        resources = client._BaseHNVModel.get()

        get_resource.assert_called_once_with("/")
        self.assertEqual(resources, [{} for _ in range(10)])

    @mock.patch("time.sleep")
    @mock.patch("hnv.client._BaseHNVModel._get_client")
    def _test_remove(self, mock_get_client, mock_sleep,
                     loop_count, timeout):
        http_client = mock_get_client.return_value = mock.Mock()
        remove_resource = http_client.remove_resource = mock.Mock()
        get_resource = http_client.get_resource = mock.Mock()
        side_effect = [None for _ in range(loop_count)]
        side_effect.append(exception.NotFound if not timeout else None)
        get_resource.side_effect = side_effect

        request_timeout = CONFIG.HNV.retry_interval * loop_count
        request_wait = True if loop_count > 0 else False

        if timeout:
            self.assertRaises(exception.TimeOut, client._BaseHNVModel.remove,
                              "hnv-client-test", wait=request_wait,
                              timeout=request_timeout)
        else:
            client._BaseHNVModel.remove("hnv-client-test",
                                        wait=request_wait,
                                        timeout=request_timeout)

        remove_resource.assert_called_once_with("/hnv-client-test")

    def test_remove(self):
        self._test_remove(loop_count=0, timeout=False)

    def test_remove_with_wait(self):
        self._test_remove(loop_count=3, timeout=False)

    def test_remove_timeout(self):
        self._test_remove(loop_count=1, timeout=True)

    @staticmethod
    def _get_provisioning(provisioning_state):
        return {"properties": {"provisioningState": provisioning_state}}

    @mock.patch("time.sleep")
    @mock.patch("hnv.client._BaseHNVModel.dump")
    @mock.patch("hnv.client._BaseHNVModel._get_client")
    def _test_commit(self, mock_get_client, mock_dump,
                     mock_sleep,
                     loop_count, timeout, failed, invalid_response):
        http_client = mock_get_client.return_value = mock.Mock()
        update_resource = http_client.update_resource = mock.Mock()
        mock_dump.return_value = mock.sentinel.request_body

        get_resource = http_client.get_resource = mock.Mock()
        side_effect = [self._get_provisioning(constant.UPDATING)
                       for _ in range(loop_count)]
        if timeout:
            side_effect.append(self._get_provisioning(constant.UPDATING))
        elif failed:
            side_effect.append(self._get_provisioning(constant.FAILED))
        elif invalid_response:
            side_effect.append(self._get_provisioning(None))
        else:
            side_effect.append(self._get_provisioning(constant.SUCCEEDED))
        get_resource.side_effect = side_effect

        request_timeout = CONFIG.HNV.retry_interval * loop_count
        request_wait = True if loop_count > 0 else False

        model = client._BaseHNVModel(resource_id="hnv-client",
                                     parent_id="test")

        if invalid_response or failed:
            self.assertRaises(exception.ServiceException, model.commit,
                              wait=request_wait, timeout=request_timeout)
        elif timeout:
            self.assertRaises(exception.TimeOut, model.commit,
                              wait=request_wait, timeout=request_timeout)
        else:
            model.commit(wait=request_wait, timeout=request_timeout)

        mock_dump.assert_called_once_with(include_read_only=False)
        update_resource.assert_called_once_with(
            "test/hnv-client", data=mock.sentinel.request_body,
            if_match=None)

        if request_wait:
            self.assertEqual(get_resource.call_count, loop_count + 1)

    def test_commit(self):
        self._test_commit(loop_count=0, timeout=False,
                          failed=False, invalid_response=False)

    def test_commit_with_wait(self):
        self._test_commit(loop_count=3, timeout=False,
                          failed=False, invalid_response=False)

    def test_commit_timeout(self):
        self._test_commit(loop_count=1, timeout=True,
                          failed=False, invalid_response=False)

    def test_commit_failed(self):
        self._test_commit(loop_count=1, timeout=False,
                          failed=True, invalid_response=False)

    def test_commit_invalid_response(self):
        self._test_commit(loop_count=1, timeout=False,
                          failed=False, invalid_response=True)

    @mock.patch("hnv.client._BaseHNVModel._reset_model")
    @mock.patch("hnv.client._BaseHNVModel._get_client")
    def test_refresh(self, mock_get_client, mock_reset_model):
        http_client = mock_get_client.return_value = mock.Mock()
        get_resource = http_client.get_resource = mock.Mock()
        get_resource.return_value = mock.sentinel.response

        model = client._BaseHNVModel(resource_id="hnv-client",
                                     parent_id="test")
        model.refresh()

        get_resource.assert_called_once_with("test/hnv-client")
        mock_reset_model.assert_called_once_with(mock.sentinel.response)


class TestClient(unittest.TestCase):

    def setUp(self):
        self._response = fake_response.FakeResponse()
        self.maxDiff = None

    def _test_get_resource(self, model, raw_data):
        with test_utils.LogSnatcher("hnv.common.model") as logging:
            model.from_raw_data(raw_data)
        self.assertEqual(logging.output, [])

    def test_logical_networks(self):
        resources = self._response.logical_networks()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.LogicalNetworks,
                                    raw_data=raw_data)

    def test_logical_network_structure(self):
        raw_data = self._response.logical_networks()["value"][0]
        logical_network = client.LogicalNetworks.from_raw_data(raw_data)

        for logical_subnetwork in logical_network.subnetworks:
            self.assertIsInstance(logical_subnetwork,
                                  client.LogicalSubnetworks)

        for virtual_network in logical_network.virtual_networks:
            self.assertIsInstance(virtual_network, client.Resource)

    def test_logical_subnets(self):
        resources = self._response.logical_subnets()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.LogicalSubnetworks,
                                    raw_data=raw_data)

    def test_logical_subnets_structure(self):
        raw_data = self._response.logical_subnets()["value"][0]
        logical_subnetwork = client.LogicalSubnetworks.from_raw_data(raw_data)

        for ip_pool in logical_subnetwork.ip_pools:
            self.assertIsInstance(ip_pool, client.IPPools)

    def test_ip_pools(self):
        resources = self._response.ip_pools()
        for raw_data in resources.get("value", []):
            raw_data["parentResourceID"] = "{uniqueString}"
            raw_data["grandParentResourceID"] = "{uniqueString}"
            self._test_get_resource(model=client.IPPools,
                                    raw_data=raw_data)

    def test_network_interfaces(self):
        resources = self._response.network_interfaces()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.NetworkInterfaces,
                                    raw_data=raw_data)

    def test_network_interfaces_structure(self):
        raw_data = self._response.network_interfaces()["value"][0]
        network_interface = client.NetworkInterfaces.from_raw_data(raw_data)

        for configuration in network_interface.ip_configurations:
            self.assertIsInstance(configuration, client.IPConfiguration)

        self.assertIsInstance(network_interface.dns_settings,
                              client.DNSSettings)
        self.assertIsInstance(network_interface.port_settings,
                              client.PortSettings)

    def test_ip_configurations(self):
        resources = self._response.ip_configurations()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.IPConfiguration,
                                    raw_data=raw_data)

    def test_virtual_networks(self):
        resources = self._response.virtual_networks()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.VirtualNetworks,
                                    raw_data=raw_data)

    def test_virtual_subnetworks(self):
        resources = self._response.virtual_subnetworks()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.SubNetworks,
                                    raw_data=raw_data)

    def test_acl_rules(self):
        resources = self._response.acl_rules()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.ACLRules,
                                    raw_data=raw_data)

    def test_acl(self):
        resources = self._response.acl()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.AccessControlLists,
                                    raw_data=raw_data)

    def test_acl_structure(self):
        raw_data = self._response.acl()["value"][0]
        acl = client.AccessControlLists.from_raw_data(raw_data)

        for acl_rule in acl.acl_rules:
            self.assertIsInstance(acl_rule, client.ACLRules)

    def test_virtual_switch_manager(self):
        raw_data = self._response.virtual_switch_manager()
        self._test_get_resource(model=client.VirtualSwitchManager,
                                raw_data=raw_data)

    def test_routes(self):
        resources = self._response.routes()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.Routes,
                                    raw_data=raw_data)

    def test_route_tables(self):
        resources = self._response.route_tables()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.RouteTables,
                                    raw_data=raw_data)

    def test_network_connections(self):
        resources = self._response.network_connections()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.NetworkConnections,
                                    raw_data=raw_data)

    def test_public_ip_addresses(self):
        resources = self._response.public_ip_addresses()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.PublicIPAddresses,
                                    raw_data=raw_data)

    def test_backend_address_pools(self):
        resources = self._response.backend_address_pools()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.BackendAddressPools,
                                    raw_data=raw_data)

    def test_frontend_ip_configurations(self):
        resources = self._response.frontend_ip_configurations()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.FrontendIPConfigurations,
                                    raw_data=raw_data)

    def test_inbound_nat_rules(self):
        resources = self._response.inbound_nat_rules()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.InboundNATRules,
                                    raw_data=raw_data)

    def test_load_balancing_rules(self):
        resources = self._response.load_balancing_rules()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.LoadBalancingRules,
                                    raw_data=raw_data)

    def test_outbound_nat_rules(self):
        resources = self._response.outbound_nat_rules()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.OutboundNATRules,
                                    raw_data=raw_data)

    def test_probes(self):
        resources = self._response.probes()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.Probes,
                                    raw_data=raw_data)

    def test_load_balancers(self):
        resources = self._response.load_balancers()
        for raw_data in resources.get("value", []):
            self._test_get_resource(model=client.LoadBalancers,
                                    raw_data=raw_data)

    def test_bgp_peers(self):
        resources = self._response.bgp_peers()
        for raw_data in resources.get("value", []):
            raw_data["parentResourceID"] = "fake-parent-id"
            raw_data["grandParentResourceID"] = "fake-grandparent-id"
            self._test_get_resource(model=client.BGPPeers,
                                    raw_data=raw_data)

    def test_bgp_routers(self):
        resources = self._response.bgp_routers()
        for raw_data in resources.get("value", []):
            raw_data["parentResourceID"] = "fake-parent-id"
            self._test_get_resource(model=client.BGPRouters,
                                    raw_data=raw_data)
