#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H.Eudenbach in 2021 - holger@eude.rocks

def inventory_apc_ups_input_voltage(info):
    yield None, None

def check_apc_ups_input_voltage(item, params, info):
    input_voltage = saveint (info[0][0])
    if input_voltage <= (209):
        return (2, "Input voltage: %d volts" % (input_voltage),
        [('input_voltage', input_voltage)]
    )
    if input_voltage in range (210,220):
        return (1, "Input voltage: %d volts" % (input_voltage),
        [('input_voltage', input_voltage)]
    )
    if input_voltage in range (230,241):
        return (1, "Input voltage: %d volts" % (input_voltage),
        [('input_voltage', input_voltage)]
    )
    if input_voltage >= (241):
        return (2, "Input voltage: %d volts" % (input_voltage),
        [('input_voltage', input_voltage)]
    )
    return (0, "Input voltage: %d volts" % (input_voltage),
    [('input_voltage', input_voltage)]
    )

check_info["apc_ups_input_voltage"] = {
    'check_function':           check_apc_ups_input_voltage,
    'inventory_function':       inventory_apc_ups_input_voltage,
    'service_description':      'APC UPS input voltage',
    'has_perfdata':             True,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.3.2', [
        1, # APC UPS input voltage
    ]),
    'snmp_scan_function':       lambda oid: oid('.1.3.6.1.4.1.318.1.1.1.3.2.1.0') != None 
}
