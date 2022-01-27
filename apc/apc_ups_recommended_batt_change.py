#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H. Eudenbach in the year 2021

def inventory_apc_ups_recommended_batt_change(info):
    yield None, None

def check_apc_ups_recommended_batt_change(item, params, info):
    return 0, "Recommended Battery change date: %s" % info[0][0] 

check_info["apc_ups_recommended_batt_change"] = {
    'check_function':           check_apc_ups_recommended_batt_change,
    'inventory_function':       inventory_apc_ups_recommended_batt_change,
    'service_description':      'APC UPS recommended battery change date',
    'has_perfdata':             False,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.2.2', [
        21, # APC UPS recommended battery change date
    ]),
    'snmp_scan_function':       lambda oid: oid('1.3.6.1.4.1.318.1.1.1.2.2.21.0') != None 
}
