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

"""Shared constants across the bcbio-nextgen-vm project."""

GET = "GET"
POST = "POST"
PUT = "PUT"
PATCH = "PATCH"
DELETE = "DELETE"

DELETING = "Deleting"
FAILED = "Failed"
SUCCEEDED = "Succeeded"
UPDATING = "Updating"

ABSOLUTE = "absolute"
WEIGHT = "weight"

VIRTUAL_APPLIANCE = "VirtualAppliance"
VNET_LOCAL = "VnetLocal"
VIRTUAL_NETWORK_GATEWAY = "VirtualNetworkGateway"
INTERNET = "Internet"

# Network connections: Connection type
IPSEC = "IPSec"
GRE = "GRE"
L3 = "L3"

# Cipher transformation constant
NONE = "None"
AES128 = "AES128"
AES128CBC = "AES128CBC"
AES192 = "AES192"
AES192CBC = "AES192CBC"
AES256 = "AES256"
AES256 = "AES256"
CBCDES = "CBCDES"
CBCDES3 = "CBCDES3"
DES = "DES"
DES3 = "DES3"
GCMAES128 = "GCMAES128"
GCMAES192 = "GCMAES192"
GCMAES256 = "GCMAES256"

# Authentication tranformation constant
MD596 = "MD596"
SHA196 = "SHA196"
SHA256 = "SHA256"
GCMAES128 = "GCMAES128"
GCMAES192 = "GCMAES192"
GCMAES256 = "GCMAES256"
