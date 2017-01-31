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

"""HNV client exception handling."""


class HNVException(Exception):

    """Base hnv_client exception.

    To correctly use this class, inherit from it and define
    a `template` property.

    That `template` will be formated using the keyword arguments
    provided to the constructor.

    Example:
    ::
        class NotFound(HNVException):

            template = "The %(object)r was not found in %(container)s."

        raise NotFound(object="subnet_id", container="network_id")
    """

    template = "An unknown exception occurred."

    def __init__(self, message=None, **kwargs):
        message = message or self.template

        try:
            message = message % kwargs
        except (TypeError, KeyError):
            # Something went wrong during message formatting.
            # Probably kwargs doesn't match a variable in the message.
            message = ("Message: %(template)s. Extra or "
                       "missing info: %(kwargs)s" %
                       {"template": message, "kwargs": kwargs})

        super(HNVException, self).__init__(message)


class DataProcessingError(HNVException):

    """Base exception class for data processing related errors."""

    template = "The provided information is incomplete or invalid."


class ServiceException(HNVException):

    """Base exception for all the API interaction related errors."""

    template = "Something went wrong."


class TimeOut(ServiceException):

    """The request timed out."""

    template = "The request timed out."


class NotFound(ServiceException):

    """The required object is not available in container."""

    template = "The %(object)r was not found in %(container)s."


class CertificateVerifyFailed(ServiceException):

    """The received certificate is not valid.

    In order to avoid the current exception the validation of the SSL
    certificate should be disabled for the metadata provider. In order
    to do that the `https_allow_insecure` config option should be set.
    """

    template = "The received certificate is not valid."


class NotSupported(ServiceException):

    """The functionality required is not available in the current context."""

    template = "%(feature)s is not available for %(context)s."
