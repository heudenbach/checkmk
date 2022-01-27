#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H. Eudenbach in the year 2021

def inventory_apc_ups_output_voltage(info):
    yield None, None

def check_apc_ups_output_voltage(item, params, info):
    output_voltage = saveint(info[0][0])
    output_voltage = 215
    if output_voltage <= (209):
        return (2, "Output voltage: %d volts" % (output_voltage),
        [('output_voltage', output_voltage)]
    )
    if output_voltage in range (210,220):
        return (1, "Output voltage: %d volts" % (output_voltage),
        [('output_voltage', output_voltage)]
    )
    if output_voltage in range (230,241):
        return (1, "Output voltage: %d volts" % (output_voltage),
        [('output_voltage', output_voltage)]
    )
    if output_voltage >= (241):
        return (2, "Output voltage: %d volts" % (output_voltage),
        [('output_voltage', output_voltage)]
    )
    return (0, "Output voltage: %d volts" % (output_voltage),
    [('output_voltage', output_voltage)]
    )

check_info["apc_ups_output_voltage"] = {
    'check_function':           check_apc_ups_output_voltage,
    'inventory_function':       inventory_apc_ups_output_voltage,
    'service_description':      'APC UPS output voltage',
    'has_perfdata':             True,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.4.2', [
        1, # APC UPS output voltage in volts
    ]),
    'snmp_scan_function':       lambda oid: oid('.1.3.6.1.4.1.318.1.1.1.4.2.1') != None 
}
