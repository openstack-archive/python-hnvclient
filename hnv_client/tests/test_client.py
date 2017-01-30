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

from hnv_client import client
from hnv_client.common import constant
from hnv_client.common import exception
from hnv_client import config as hnv_config

CONFIG = hnv_config.CONFIG


class TestBaseHNVModel(unittest.TestCase):

    def setUp(self):
        client._BaseHNVModel._endpoint = "{parent_id}/{resource_id}"

    @mock.patch("hnv_client.client._BaseHNVModel.from_raw_data")
    @mock.patch("hnv_client.client._BaseHNVModel._get_client")
    def test_get(self, mock_get_client, mock_from_raw_data):
        mock_from_raw_data.return_value = mock.sentinel.resource
        http_client = mock_get_client.return_value = mock.Mock()
        get_resource = http_client.get_resource = mock.Mock()

        resource = client._BaseHNVModel.get(resource_id="hnv-client-test")

        get_resource.assert_called_once_with("/hnv-client-test")
        self.assertIs(resource, mock.sentinel.resource)

    @mock.patch("hnv_client.client._BaseHNVModel.from_raw_data")
    @mock.patch("hnv_client.client._BaseHNVModel._get_client")
    def test_get_all(self, mock_get_client, mock_from_raw_data):
        mock_from_raw_data.side_effect = range(10)

        http_client = mock_get_client.return_value = mock.Mock()
        get_resource = http_client.get_resource = mock.Mock()
        get_resource.return_value = {"value": range(10)}

        resources = client._BaseHNVModel.get()

        get_resource.assert_called_once_with("/")
        self.assertEqual(resources, range(10))

    @mock.patch("time.sleep")
    @mock.patch("hnv_client.client._BaseHNVModel._get_client")
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
    @mock.patch("hnv_client.client._BaseHNVModel.process_raw_data")
    @mock.patch("hnv_client.client._BaseHNVModel.dump")
    @mock.patch("hnv_client.client._BaseHNVModel._get_client")
    def _test_commit(self, mock_get_client, mock_dump, mock_process,
                     mock_sleep,
                     loop_count, timeout, failed, invalid_response):
        http_client = mock_get_client.return_value = mock.Mock()
        update_resource = http_client.update_resource = mock.Mock()
        mock_dump.return_value = mock.sentinel.request_body
        mock_process.return_value = {}

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
            "test/hnv-client", data=mock.sentinel.request_body)

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
