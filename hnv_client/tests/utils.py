# Copyright 2016 Cloudbase Solutions Srl
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

"""Utilities used in order to ease the project testing."""

# pylint: disable=too-few-public-methods

import functools
import logging as base_logging

from oslo_log import log as oslo_logging

from hnv_client import config as hnv_conf


CONFIG = hnv_conf.CONFIG


class SnatchHandler(base_logging.Handler):

    """This is similar with unittest.TestCase.assertLogs from Python 3.4."""

    def __init__(self, *args, **kwargs):
        super(SnatchHandler, self).__init__(*args, **kwargs)
        self.output = []

    def emit(self, record):
        message = self.format(record)
        self.output.append(message)


class LogSnatcher(object):
    """A context manager to capture emitted logged messages.

    The class can be used as following::

        with LogSnatcher('hnv_client.client') as snatcher:
            LOG.info("doing stuff")
            LOG.info("doing stuff %s", 1)
            LOG.warn("doing other stuff")
            ...
        self.assertEqual(snatcher.output,
                         ['INFO:unknown:doing stuff',
                          'INFO:unknown:doing stuff 1',
                          'WARN:unknown:doing other stuff'])
    """

    @property
    def output(self):
        """The snatch handler output."""
        return self._snatch_handler.output

    def __init__(self, logger_name):
        self._logger_name = logger_name
        self._snatch_handler = SnatchHandler()
        self._logger = oslo_logging.getLogger(self._logger_name)
        self._previous_level = self._logger.logger.getEffectiveLevel()

    def __enter__(self):
        self._logger.logger.setLevel(base_logging.DEBUG)
        self._logger.handlers.append(self._snatch_handler)
        return self

    def __exit__(self, *args):
        self._logger.handlers.remove(self._snatch_handler)
        self._logger.logger.setLevel(self._previous_level)


class ConfigPatcher(object):
    """Override the configuration for the given key, with the given value.

    This class can be used both as a context manager and as a decorator.
    """

    def __init__(self, key, value, group=None, conf=CONFIG):
        if group:
            self._original_value = conf.get(group).get(key)
        else:
            self._original_value = conf.get(key)
        self._key = key
        self._value = value
        self._group = group
        self._config = conf

    def __call__(self, func, *args, **kwargs):
        def _wrapped_f(*args, **kwargs):
            with self:
                return func(*args, **kwargs)

        functools.update_wrapper(_wrapped_f, func)
        return _wrapped_f

    def __enter__(self):
        self._config.set_override(self._key, self._value,
                                  group=self._group)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._config.set_override(self._key, self._original_value,
                                  group=self._group)
