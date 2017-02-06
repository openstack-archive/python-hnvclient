# python-hnv

[![Build Status](https://travis-ci.org/cloudbase/python-hnvclient.svg?branch=master)](https://travis-ci.org/cloudbase/python-hnvclient)

Python client for the HNV (Hyper-V Network Virtualization) REST API.

 - License: Apache License, Version 2.0

## Python API

The Python interface matches the underlying REST API and can be employed in 3rd party projects.

```python
>>> from hnv import client
>>> logical_networks = client.LogicalNetworks.get()
>>> for logical_network in logical_networks:
...     print(logical_network.resource_id)
...
"63606911-e053-42cf-842e-29f67c90d5c6"
"c4cd42ff-5efb-4006-ac56-479730557926"
"cd804db3-df59-4f57-8a7d-11cc3f3c4d98"

>>> logical_network = client.LogicalNetworks.get(resource_id="cd804db3-df59-4f57-8a7d-11cc3f3c4d98")
>>> logical_network
<hnv.client.LogicalNetworks object at 0x7fcd79419910>
>>> logical_network.provisioning_state
u'Succeeded'
>>> logical_network.subnetworks
[<hnv.client.LogicalSubnetworks object at 0x7fcd79419150>]
>>> logical_network.subnetworks[0].resource_id
u'4390e3d8-c527-4534-882f-906c47ffd0bb'
```

or

```python
from __future__ import print_function

import json
import sys

from hnv import config
from hnv import client


def view_logical_networks():
    """List all the available logical networks."""
    logical_networks = client.LogicalNetworks.get()
    print("Logical networks:")
    for logical_network in logical_networks:
        print("\t - ", logical_network.resource_ref)
        print("\t\t", "Logical subnetworks:")
        for logical_subnetwork in logical_network.subnetworks:
            print("\t\t - %s (%s)" % (logical_subnetwork.resource_id,
                                      logical_subnetwork.address_prefix))

        print("\t\t", "Virtual networks:")
        for virtual_network in logical_network.virtual_networks:
            print("\t\t - %s" % virtual_network.resource_ref)


def create_virtual_network():
    """Create a new virtual network on the first logical network."""
    print("Creating a new virtual network.")
    address_space = client.AddressSpace(
        address_prefixes=["192.168.133.0/24"])

    logical_network = client.Resource(
        resource_ref=client.LogicalNetworks.get()[0].resource_ref)

    virtual_network = client.VirtualNetworks(
        resource_id="hvn-test",
        address_space=address_space,
        logical_network=logical_network,
    )
    virtual_network.commit()

    print("The raw content of the new Virtual Network")
    print(json.dumps(virtual_network.dump(), indent=4))


def remove_virtual_network():
    """Remove the new virtual network."""
    print("Remove the new virtual network")
    client.VirtualNetworks.remove(resource_id="hvn-test")


def main():
    """Logical networks sample entry point."""
    config.CONFIG(sys.argv[1:])
    view_logical_networks()
    create_virtual_network()
    view_logical_networks()
    remove_virtual_network()
    view_logical_networks()
```
