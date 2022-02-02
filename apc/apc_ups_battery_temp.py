#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H.Eudenbach in 2021 - holger@eude.rocks

def inventory_apc_ups_battery_temp(info):
    yield None, None

def check_apc_ups_battery_temp(item, params, info):
    battery_temp = saveint (info[0][0])
    if battery_temp <= (6):
        return (2, "Battery Temperature: %d° Celcius" % (battery_temp),
        [('battery_temp', battery_temp)]
        )
    if battery_temp in range(6,36):
        return (0, "Battery Temperature: %d° Celcius" % (battery_temp),
        [('battery_temp', battery_temp)]
        )
    if battery_temp in range (36,41):
        return (1, "Battery Temperature: %d° Celcius" % (battery_temp),
        [('battery_temp', battery_temp)]
        )
    if battery_temp >= (41):
        return (2, "Battery Temperature: %d° Celcius" % (battery_temp),
        [('battery_temp', battery_temp)]
        )
    return 2, "Battery Temperature: Unknown"

    return (0, "Battery Temperature: %d° Celcius" % (battery_temp),
        [('battery_temp', battery_temp)]
        )

check_info["apc_ups_battery_temp"] = {
    'check_function':           check_apc_ups_battery_temp,
    'inventory_function':       inventory_apc_ups_battery_temp,
    'service_description':      'APC UPS Battery Temperature',
    'has_perfdata':             True,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.2.2', [
        2, # APC UPS Battery Temperature
    ]),
    'snmp_scan_function':       lambda oid: oid('.1.3.6.1.4.1.318.1.1.1.2.2.2.0') != None 
}
