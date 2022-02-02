#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H.Eudenbach in 2021 - holger@eude.rocks

def inventory_apc_battery_capacity(info):
    yield None, None

def check_apc_battery_capacity(item, params, info):
    # Define here: critical = 0-20 # warning = 21-79 # ok = 80-100
    battery_capacity = saveint(info[0][0])
    if battery_capacity in range(80,101):
        return (0, "Battery remaining capacity: %d %%" % (battery_capacity), 
        [('battery_capacity', battery_capacity)]
    )
    if battery_capacity in range(21,80):
        return (1, "Battery remaining capacity: %d %%" % (battery_capacity), 
        [('battery_capacity', battery_capacity)]
    )
    if battery_capacity in range(0,21): 
        return (2, "Battery remaining capacity: %d %%" % (battery_capacity), 
        [('battery_capacity', battery_capacity)]
    )
    return 2, "Battery remaining capacity: Unknown"


check_info["apc_ups_battery_capacity"] = {
    'check_function':           check_apc_battery_capacity,
    'inventory_function':       inventory_apc_battery_capacity,
    'service_description':      'APC UPS battery remaining capacity',
    'has_perfdata':             True,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.2.2', [
        1, # APC UPS Battery Capacity
    ]),
    'snmp_scan_function':       lambda oid: oid('.1.3.6.1.4.1.318.1.1.1.2.2.1.0') != None 
}
