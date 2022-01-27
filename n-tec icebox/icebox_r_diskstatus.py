#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H. Eudenbach in the year 2021 in progress

from .agent_based_api.v1 import *
import pprint

def discover_physical_disk_status(section):
    yield Service()

def check_physical_disk_status(section):

    for hddItem in section:
        [physical_ds, hddLocation] = hddItem

        state = State.UNKNOWN

        if physical_ds == 'Online':
            state = State.OK

        if physical_ds == 'Offline':
            state = State.CRIT

        yield Result(
            state=state,
            summary="Physical Disk Status (%s): %s" % (physical_ds, hddLocation)
        )

    return

register.check_plugin(
    name = "physical_disk_status_ntec_iceboxr",
    service_name = "Physical Disk Status  ",
    discovery_function = discover_physical_disk_status,
    check_function = check_physical_disk_status,
)

register.snmp_section(
    name = "physical_disk_status_ntec_iceboxr",
    detect = contains(".1.3.6.1.2.1.1.1.0", "2.6.32-Lacerta"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.22274.1.2.1.1',
        oids = [
            '4',    # Physical Disk Status
            '1',    # Physical Disk Location

        ],
    ),
)
