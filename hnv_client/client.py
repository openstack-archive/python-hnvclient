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

    def __init__(self, **fields):
        self._parent_id = fields.pop("parent_id", None)
        super(_BaseHNVModel, self).__init__(**fields)

    @staticmethod
    def _get_client():
        """Create a new client for the HNV REST API."""
        return utils.get_client(url=CONFIG.HNV.url,
                                username=CONFIG.HNV.username,
                                password=CONFIG.HNV.password,
                                allow_insecure=CONFIG.HNV.https_allow_insecure,
                                ca_bundle=CONFIG.HNV.https_ca_bundle)

    @property
    def parent_id(self):
        """The identifier for the specific ancestor resource."""
        return self._parent_id

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
