#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H. Eudenbach in the year 2021

def inventory_apc_ups_type(info):
    yield None, None

def check_apc_ups_type(item, params, info):
    return 0, "Type: %s" % info[0][0]

check_info["apc_ups_type"] = {
    'check_function':           check_apc_ups_type,
    'inventory_function':       inventory_apc_ups_type,
    'service_description':      'APC UPS Type',
    'has_perfdata':             False,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.1.1', [
        1, # APC UPS Type
    ]),
    'snmp_scan_function':       lambda oid: oid('.1.3.6.1.4.1.318.1.1.1.1.1.1.0') != None 
}
