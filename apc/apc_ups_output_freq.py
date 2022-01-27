#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H. Eudenbach in the year 2021

def inventory_apc_ups_output_freq(info):
    yield None, None

def check_apc_ups_output_freq(item, params, info):
    output_freq = saveint (info[0][0])
    if output_freq <= (49):
        return (2, "Output frequency: %d Hz" % (output_freq),
        [('output_freq', output_freq)]
    )
    if output_freq >= (51):
        return (2, "Output frequency: %d Hz" % (output_freq),
        [('output_freq', output_freq)]
    )
    return (0, "Output frequency: %d Hz" % (output_freq),
        [('output_freq', output_freq)]
    )

check_info["apc_ups_output_freq"] = {
    'check_function':           check_apc_ups_output_freq,
    'inventory_function':       inventory_apc_ups_output_freq,
    'service_description':      'APC UPS output frequency',
    'has_perfdata':             True,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.4.2', [
        2, # APC UPS Battery remaining timeticks
    ]),
    'snmp_scan_function':       lambda oid: oid('.1.3.6.1.4.1.318.1.1.1.4.2.2.0') != None 
}
