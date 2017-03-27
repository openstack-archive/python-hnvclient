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

"""Utilities used across the project."""

import json
import sys
import time

from oslo_log import log as logging
import requests
import requests_ntlm
import six

from hnv.common import constant
from hnv.common import exception
from hnv import CONFIG

LOG = logging.getLogger(__name__)


class _HNVClient(object):

    """Minimalistic client for the Network Controller REST API.

    :param url:             The base URL where the agent looks for
                                Network Controller API.
    :param username:        The username required for connecting to the
                            Network Controller API.
    :param password:        The password required for connecting to the
                            Network Controller API.
    :param allow_insecure:  Whether to disable the validation of
                            HTTPS certificates.
    :param ca_bundle:       The path to a CA_BUNDLE file or directory
                            with certificates of trusted CAs.
    """

    def __init__(self, url, username=None, password=None, allow_insecure=False,
                 ca_bundle=None):
        self._base_url = url
        self._credentials = (username, password)
        self._https_allow_insecure = allow_insecure
        self._https_ca_bundle = ca_bundle
        self._http_session = None

    @property
    def _session(self):
        """The current session used by the client.

        The Session object allows you to persist certain parameters across
        requests. It also persists cookies across all requests made from
        the Session instance, and will use urllib3's connection pooling.
        So if you're making several requests to the same host, the underlying
        TCP connection will be reused, which can result in a significant
        performance increase.
        """
        if self._http_session is None:
            self._http_session = requests.Session()
            self._http_session.headers.update(self._get_headers())
            self._http_session.verify = self._verify_https_request()

            if all(self._credentials):
                username, password = self._credentials
                self._http_session.auth = requests_ntlm.HttpNtlmAuth(
                    username=username, password=password)

        return self._http_session

    @staticmethod
    def _get_headers():
        """Prepare the HTTP headers for the current request."""

        # TODO(alexcoman): Add the x-ms-client-ip-address header in order
        # to improve the Network Controller requests logging.
        return {
            "Accept": "application/json",
            "Connection": "keep-alive",
            "Content-Type": "application/json; charset=UTF-8",
        }

    def _verify_https_request(self):
        """Whether to disable the validation of HTTPS certificates.

        .. notes::
            When `https_allow_insecure` option is `True` the SSL certificate
            validation for the connection with the Network Controller API will
            be disabled (please don't use it if you don't know the
            implications of this behaviour).
        """
        if self._https_ca_bundle:
            return self._https_ca_bundle
        else:
            return not self._https_allow_insecure

    def _http_request(self, resource, method=constant.GET, body=None,
                      if_match=False):
        if not resource.startswith("http"):
            url = requests.compat.urljoin(self._base_url, resource)
        else:
            url = resource

        headers = self._get_headers()
        if method in (constant.PUT, constant.PATCH):
            if if_match:
                etag = (body or {}).get("etag", None)
                if etag is not None:
                    headers["If-Match"] = etag

        attemts = 0
        while True:
            try:
                response = self._session.request(
                    method=method, url=url, headers=headers,
                    data=json.dumps(body) if body else None,
                    timeout=CONFIG["http_request_timeout"]
                )
                break
            except (requests.ConnectionError,
                    requests.RequestException) as exc:
                attemts += 1
                self._http_session = None
                LOG.debug("Request failed: %s", exc)
                if attemts > CONFIG["retry_count"]:
                    if isinstance(exc, requests.exceptions.SSLError):
                        raise exception.CertificateVerifyFailed(
                            "HTTPS certificate validation failed.")
                    raise
                time.sleep(CONFIG["retry_interval"])

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            status_code = exc.response.status_code
            content = exc.response.text
            LOG.debug("HTTP Error %(status_code)r: %(details)r",
                      {"status_code": status_code, "details": content})

            if status_code == 400:
                raise exception.ServiceException(
                    ("HNV Client failed to communicate with the API. "
                     "Please open an issue with the following information: "
                     "%(resource)r: %(details)r"),
                    resource=resource, details=content
                )
            if status_code == 404:
                raise exception.NotFound(
                    "Resource %(resource)r was not found.", resource=resource)
            raise

        return response

    def get_resource(self, path):
        """Getting the required information from the API."""
        response = self._http_request(path)
        try:
            return response.json()
        except ValueError:
            raise exception.ServiceException("Invalid service response.")

    def update_resource(self, path, data, if_match=None):
        """Update the required resource."""
        response = self._http_request(resource=path, method="PUT", body=data,
                                      if_match=if_match)
        try:
            return response.json()
        except ValueError:
            raise exception.ServiceException("Invalid service response.")

    def remove_resource(self, path):
        """Delete the received resource."""
        return self._http_request(path, method="DELETE")


# pylint: disable=dangerous-default-value
def run_once(function, state={}, errors={}):
    """A memoization decorator, whose purpose is to cache calls."""
    @six.wraps(function)
    def _wrapper(*args, **kwargs):
        if function in errors:
            # Deliberate use of LBYL.
            six.reraise(*errors[function])

        try:
            return state[function]
        except KeyError:
            try:
                state[function] = result = function(*args, **kwargs)
                return result
            except Exception:
                errors[function] = sys.exc_info()
                raise
    return _wrapper


@run_once
def get_client(url, username, password, allow_insecure, ca_bundle):
    """Create a new client for the HNV REST API."""
    return _HNVClient(url, username, password, allow_insecure, ca_bundle)


def get_as_string(value):
    if value is None or isinstance(value, six.text_type):
        return value
    else:
        try:
            return value.decode()
        except Exception:
            # This is important, because None will be returned,
            # but not that serious to raise an exception.
            LOG.error("Couldn't decode: %r", value)
