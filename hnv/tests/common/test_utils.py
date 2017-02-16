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

# pylint: disable=protected-access, missing-docstring

import unittest
try:
    import unittest.mock as mock
except ImportError:
    import mock

import requests

from hnv.common import constant
from hnv.common import exception
from hnv.common import utils as hnv_utils
from hnv import config as hnv_config
from hnv.tests import utils as test_utils

CONFIG = hnv_config.CONFIG


class TestHNVClient(unittest.TestCase):

    @staticmethod
    def _get_client(url=mock.sentinel.url, username=mock.sentinel.username,
                    password=mock.sentinel.password,
                    allow_insecure=mock.sentinel.insecure,
                    ca_bundle=mock.sentinel.ca_bundle):
        return hnv_utils._HNVClient(url, username, password, allow_insecure,
                                    ca_bundle)

    @mock.patch("hnv.common.utils._HNVClient._get_headers")
    @mock.patch("hnv.common.utils._HNVClient._verify_https_request")
    @mock.patch("requests_ntlm.HttpNtlmAuth")
    @mock.patch("requests.Session")
    def test_session(self, mock_get_session, mock_auth, mock_verify,
                     mock_headers):
        mock_session = mock.Mock()
        mock_session.headers = {}
        mock_get_session.return_value = mock_session
        mock_verify.return_value = mock.sentinel.verify
        mock_auth.return_value = mock.sentinel.auth
        mock_headers.return_value = {"X-HNV-Test": 1}

        client = self._get_client()
        session = client._session

        self.assertIs(session, mock_session)
        self.assertIs(mock_session.verify, mock.sentinel.verify)
        self.assertIs(mock_session.auth, mock.sentinel.auth)
        self.assertEqual(mock_session.headers.get("X-HNV-Test"), 1)
        mock_auth.assert_called_once_with(username=mock.sentinel.username,
                                          password=mock.sentinel.password)

    def test_verify_https_request(self):
        ca_bundle_client = self._get_client(allow_insecure=None)
        insecure_client = self._get_client(ca_bundle=None)

        self.assertIs(ca_bundle_client._verify_https_request(),
                      mock.sentinel.ca_bundle)
        self.assertFalse(insecure_client._verify_https_request())

    @mock.patch("time.sleep")
    @mock.patch("json.dumps")
    @mock.patch("requests.compat.urljoin")
    @mock.patch("hnv.common.utils._HNVClient._session")
    @mock.patch("hnv.common.utils._HNVClient._get_headers")
    def _test_http_request(self, mock_headers, mock_session, mock_join,
                           mock_dump, mock_sleep,
                           method, body, response, status_code, if_match):
        output = []
        headers = mock_headers.return_value = {}
        mock_join.return_value = mock.sentinel.url
        mock_dump.return_value = mock.sentinel.content

        session_request = mock_session.request = mock.MagicMock()
        session_request.side_effect = response

        expected_response = response[-1]

        status_check = expected_response.raise_for_status = mock.MagicMock()
        if status_code != 200:
            exc_response = mock.MagicMock()
            exc_response.status_code = status_code
            exc_response.text = "Expected Error"
            status_check.side_effect = requests.HTTPError(
                response=exc_response)
            output.append("HTTP Error %(status_code)r: 'Expected Error'" %
                          {"status_code": status_code})

        client = self._get_client()
        with test_utils.LogSnatcher("hnv.common.utils") as logging:
            if isinstance(expected_response, requests.exceptions.SSLError):
                self.assertRaises(exception.CertificateVerifyFailed,
                                  client._http_request,
                                  "/fake/resource", method, body, if_match)
                return
            elif isinstance(expected_response, requests.ConnectionError):
                self.assertRaises(requests.ConnectionError,
                                  client._http_request,
                                  "/fake/resource", method, body, if_match)
                return
            elif status_code == 400:
                self.assertRaises(exception.ServiceException,
                                  client._http_request,
                                  "/fake/resource", method, body, if_match)
            elif status_code == 404:
                self.assertRaises(exception.NotFound,
                                  client._http_request,
                                  "/fake/resource", method, body, if_match)
            elif status_code != 200:
                self.assertRaises(requests.HTTPError,
                                  client._http_request,
                                  "/fake/resource", method, body, if_match)
            else:
                client_response = client._http_request("/fake/resource",
                                                       method, body, if_match)

        mock_join.assert_called_once_with(mock.sentinel.url,
                                          "/fake/resource")
        mock_headers.assert_called_once_with()
        if not method == constant.GET and if_match:
            etag = (body or {}).get("etag", None)
            if etag is None:
                self.assertNotIn("If-Match", headers)
            else:
                self.assertEqual(headers["If-Match"], etag)

        if len(response) == 1:
            session_request.assert_called_once_with(
                method=method, url=mock.sentinel.url, headers=headers,
                data=mock.sentinel.content if body else None,
                timeout=CONFIG.HNV.http_request_timeout
            )
        elif len(response) > 1:
            # Note(alexcoman): The first response is an exception
            output.append("Request failed: ")

        self.assertEqual(logging.output, output)
        if status_code == 200:
            self.assertIs(client_response, expected_response)

    def test_http_request_get(self):
        response = [mock.MagicMock()]
        self._test_http_request(method=constant.GET,
                                body=mock.sentinel.body,
                                response=response,
                                status_code=200,
                                if_match=False)

    def test_http_request_put(self):
        response = [mock.MagicMock()]
        self._test_http_request(method=constant.PUT,
                                body={"etag": mock.sentinel.etag},
                                response=response,
                                status_code=200,
                                if_match=True)

    def test_http_request_with_connection_error(self):
        response = [requests.ConnectionError(), mock.MagicMock()]
        with test_utils.ConfigPatcher('retry_count', 1, "HNV"):
            self._test_http_request(method=constant.GET,
                                    body=mock.sentinel.body,
                                    response=response,
                                    status_code=200,
                                    if_match=False)

    def test_http_request_connection_error(self):
        response = [requests.ConnectionError(), requests.ConnectionError()]
        with test_utils.ConfigPatcher('retry_count', 1, "HNV"):
            self._test_http_request(method=constant.GET,
                                    body=mock.sentinel.body,
                                    response=response,
                                    status_code=200,
                                    if_match=False)

    def test_http_request_ssl_error(self):
        response = [requests.exceptions.SSLError(),
                    requests.exceptions.SSLError()]
        with test_utils.ConfigPatcher('retry_count', 1, "HNV"):
            self._test_http_request(method=constant.GET,
                                    body=mock.sentinel.body,
                                    response=response,
                                    status_code=200,
                                    if_match=False)

    def test_http_request_not_found(self):
        response = [mock.MagicMock()]
        self._test_http_request(method=constant.GET,
                                body=mock.sentinel.body,
                                response=response,
                                status_code=404,
                                if_match=False)

    def test_http_request_bad_request(self):
        response = [mock.MagicMock()]
        self._test_http_request(method=constant.GET,
                                body=mock.sentinel.body,
                                response=response,
                                status_code=400,
                                if_match=False)

    def test_http_request_server_error(self):
        response = [mock.MagicMock()]
        self._test_http_request(method=constant.GET,
                                body=mock.sentinel.body,
                                response=response,
                                status_code=500,
                                if_match=False)

    @mock.patch("hnv.common.utils._HNVClient._http_request")
    def test_get_resource(self, mock_http_request):
        response = mock.Mock()
        response.json = mock.Mock()
        response.json.side_effect = [mock.sentinel.response, ValueError]
        mock_http_request.return_value = response

        client = self._get_client()

        self.assertIs(client.get_resource(mock.sentinel.path),
                      mock.sentinel.response)
        mock_http_request.assert_called_once_with(mock.sentinel.path)
        self.assertRaises(exception.ServiceException,
                          client.get_resource, mock.sentinel.path)

    @mock.patch("hnv.common.utils._HNVClient._http_request")
    def test_update_resource(self, mock_http_request):
        response = mock.Mock()
        response.json = mock.Mock()
        response.json.side_effect = [mock.sentinel.response, ValueError]
        mock_http_request.return_value = response

        client = self._get_client()
        response = client.update_resource(mock.sentinel.path,
                                          mock.sentinel.data)

        self.assertIs(response, mock.sentinel.response)
        mock_http_request.assert_called_once_with(
            resource=mock.sentinel.path, method="PUT", body=mock.sentinel.data,
            if_match=None)
        self.assertRaises(exception.ServiceException,
                          client.update_resource,
                          mock.sentinel.path, mock.sentinel.data)

    @mock.patch("hnv.common.utils._HNVClient._http_request")
    def test_remove_resource(self, mock_http_request):
        mock_http_request.return_value = mock.sentinel.response

        client = self._get_client()
        response = client.remove_resource(mock.sentinel.path)

        self.assertIs(response, mock.sentinel.response)
