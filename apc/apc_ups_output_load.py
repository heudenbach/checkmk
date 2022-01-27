#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H. Eudenbach in the year 2021

def inventory_apc_ups_output_load(info):
    yield None, None

def check_apc_ups_output_load(item, params, info):
    output_load = saveint(info[0][0])
    if output_load in range (60,81):
        return (1, "Output load: %d %%" % (output_load),
        [('output_load', output_load)]
        )
    if output_load >= (81):
        return (2, "Output load: %d %%" % (output_load),
        [('output_load', output_load)]
        )
    return (0, "Output load: %d %%" % (output_load),
        [('output_load', output_load)]
        )
check_info["apc_ups_output_load"] = {
    'check_function':           check_apc_ups_output_load,
    'inventory_function':       inventory_apc_ups_output_load,
    'service_description':      'APC UPS output load',
    'has_perfdata':             True,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.4.2', [
        3, # APC UPS output load
    ]),
    'snmp_scan_function':       lambda oid: oid('.1.3.6.1.4.1.318.1.1.1.4.2.3.0') != None 
}
