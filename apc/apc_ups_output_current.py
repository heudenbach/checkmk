#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H.Eudenbach in 2021 - holger@eude.rocks

def inventory_apc_ups_output_current(info):
    yield None, None

def check_apc_ups_output_current(item, params, info):
    output_current = saveint(info[0][0])
    return (
        0, 
        "Output current: %d ampere" % (output_current),
        [('output_current', output_current)]
    )

check_info["apc_ups_output_current"] = {
    'check_function':           check_apc_ups_output_current,
    'inventory_function':       inventory_apc_ups_output_current,
    'service_description':      'APC UPS output current',
    'has_perfdata':             True,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.4.2', [
        4, # APC UPS output load
    ]),
    'snmp_scan_function':       lambda oid: oid('.1.3.6.1.4.1.318.1.1.1.4.2.4.0') != None 
}
