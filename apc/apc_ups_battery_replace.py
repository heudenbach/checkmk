#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H.Eudenbach in 2021 - holger@eude.rocks

def inventory_apc_ups_battery_replace(info):
    yield None, None

def check_apc_ups_battery_replace(item, params, info):
    # (1 = OK, 2 = Replace)
    battery_status = saveint(info[0][0])
    battery_status = 2
    if battery_status == 1:
        return 0, "Battery status: OK"
    if battery_status == 2:
        return 2, "Battery status: Replace"
    return 1, "Battery status: Unknown" 

check_info["apc_ups_battery_replace"] = {
    'check_function':           check_apc_ups_battery_replace,
    'inventory_function':       inventory_apc_ups_battery_replace,
    'service_description':      'APC UPS battery status',
    'has_perfdata':             False,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.2.2', [
        4, # APC UPS battery replace
    ]),
    'snmp_scan_function':       lambda oid: oid('1.3.6.1.4.1.318.1.1.1.2.2.4.0') != None 
}
