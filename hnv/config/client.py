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

"""Config options available for HVN."""

from oslo_config import cfg

from hnv.config import base as config_base


class HVNOptions(config_base.Options):

    """Config options available for HVN."""

    def __init__(self, config):
        super(HVNOptions, self).__init__(config, group="HNV")
        self._options = [
            cfg.StrOpt(
                "url", default="http://127.0.0.1/",
                help=("The base URL where the agent looks for "
                      "Network Controller API.")),
            cfg.StrOpt(
                "username",
                help=("The username required for connecting to the Netowork "
                      "Controller API.")),
            cfg.StrOpt(
                "password",
                help=("The password required for connecting to the Netowork "
                      "Controller API."),
                secret=True),
            cfg.BoolOpt(
                "https_allow_insecure", default=False,
                help=("Whether to disable the validation of "
                      "HTTPS certificates.")),
            cfg.StrOpt(
                "https_ca_bundle", default=None,
                help=("The path to a CA_BUNDLE file or directory with "
                      "certificates of trusted CAs.")),
            cfg.IntOpt(
                "retry_count", default=5,
                help="Max. number of attempts for fetching metadata in "
                     "case of transient errors"),
            cfg.FloatOpt(
                "retry_interval", default=1,
                help=("Interval between attempts in case of transient errors, "
                      "expressed in seconds")),
            cfg.IntOpt(
                "http_request_timeout", default=None,
                help=("Number of seconds until network requests stop waiting "
                      "for a response")),
            cfg.StrOpt(
                "logical_network", default=None,
                help=("Logical network to use as a medium for tenant network "
                      "traffic.")),
        ]

    def register(self):
        """Register the current options to the global ConfigOpts object."""
        group = cfg.OptGroup(
            self.group_name,
            title="HNV (Hyper-V Network Virtualization) Options")
        self._config.register_group(group)
        self._config.register_opts(self._options, group=group)

    def list(self):
        """Return a list which contains all the available options."""
        return self._options
