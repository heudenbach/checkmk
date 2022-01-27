#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
#   APC Runtime comes in "timeticks" - divide by 100 to get seconds, divide by 6000 to get minutes
#
#   RFC-2758 definition of timeticks:
#   The TimeTicks type represents a non-negative integer which represents
#   the time, modulo 2^32 (4294967296 decimal), in hundredths of a second
#   between two epochs.  When objects are defined which use this ASN.1
#   type, the description of the object identifies both of the reference
#   epochs.
#
# H. Eudenbach in the year 2021


def inventory_apc_ups_battery_runtime(info):
    yield None, None

def check_apc_ups_battery_runtime(item, params, info):
    battery_runtime = round(saveint(info[0][0]) / 6000)
    if battery_runtime in range(0,20):
        return (2, "Battery run time remaining: %d minutes" % (battery_runtime),
        [('battery_runtime', battery_runtime)]
    )
    if battery_runtime in range(20,41):
        return (1, "Battery run time remaining: %d minutes" % (battery_runtime),
        [('battery_runtime', battery_runtime)]
    )
    if battery_runtime >= 41:
        return (0, "Battery run time remaining: %d minutes" % (battery_runtime),
        [('battery_runtime', battery_runtime)]
    )
    return 2, "Battery run time remaining: Unknown"

check_info["apc_ups_battery_runtime"] = {
    'check_function':           check_apc_ups_battery_runtime,
    'inventory_function':       inventory_apc_ups_battery_runtime,
    'service_description':      'APC UPS battery runtime remaining',
    'has_perfdata':             True,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.2.2', [
        3, # APC UPS Battery runtime remaining
    ]),
    'snmp_scan_function':       lambda oid: oid('.1.3.6.1.4.1.318.1.1.1.2.2.2.3') != None 
}
