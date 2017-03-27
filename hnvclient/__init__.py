# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import pbr.version


__version__ = pbr.version.VersionInfo(
    'hnvclient').version_string()

CONFIG = {
    "url": None,
    "username": None,
    "password": None,
    "https_allow_insecure": False,
    "https_ca_bundle": None,
    "retry_count": 5,
    "retry_interval": 1,
    "http_request_timeout": None,
}
