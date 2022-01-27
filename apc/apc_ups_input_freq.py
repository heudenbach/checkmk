#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H. Eudenbach in the year 2021

def inventory_apc_ups_input_freq(info):
    yield None, None

def check_apc_ups_input_freq(item, params, info):
    input_freq = saveint (info[0][0])
    if input_freq <= (49):
        return (2, "Input frequency: %d Hz" % (input_freq),
        [('input_freq', input_freq)]
        )
    if input_freq >= (51):
        return (2, "Input frequency: %d Hz" % (input_freq),
        [('input_freq', input_freq)]
        )
    return (0, "Input frequency: %d Hz" % (input_freq),
        [('input_freq', input_freq)]
        )

check_info["apc_ups_input_freq"] = {
    'check_function':           check_apc_ups_input_freq,
    'inventory_function':       inventory_apc_ups_input_freq,
    'service_description':      'APC UPS input frequency',
    'has_perfdata':             True,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.3.2', [
        4, # APC UPS input frequency
    ]),
    'snmp_scan_function':       lambda oid: oid('.1.3.6.1.4.1.318.1.1.1.3.2.4.0') != None 
}
