#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H.Eudenbach in 2021 - holger@eude.rocks

from .agent_based_api.v1 import *
import re
import pprint

def discover_smart_error(section):
    yield Service()

def check_smart_error(section):

    for hddItem in section:
        [smart_errorrate, hddLocation] = hddItem
        smart_errorrate = int(re.sub("\(.*\)","", smart_errorrate))

        state = State.UNKNOWN
        if smart_errorrate >= 90 and smart_errorrate <=100:
            state = State.OK

        if smart_errorrate >= 85 and smart_errorrate <=89:
            state = State.WARN

        if smart_errorrate >= 0 and smart_errorrate <=84:
            state = State.CRIT

        yield Result(
            state=state,
            summary="Smart Error Rate(%s): %d" % (hddLocation, smart_errorrate)
        )

    return

register.check_plugin(
    name = "smart_error_ntec_iceboxr",
    service_name = "Smart Error Rate ",
    discovery_function = discover_smart_error,
    check_function = check_smart_error,
)

register.snmp_section(
    name = "smart_error_ntec_iceboxr",
    detect = contains(".1.3.6.1.2.1.1.1.0", "2.6.32-Lacerta"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.22274.1.3.4.1',
        oids = [
            '3',    # Smart Error State of HDD 1
            '1',    # Location of HDD 1
        ],
    ),
)