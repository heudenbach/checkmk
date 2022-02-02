#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H.Eudenbach in 2021 - holger@eude.rocks

reasons = [
    'No events',
    'High line voltage',
    'Brownout',
    'Loss of mains power',
    'Small temporary power drop',
    'Large temporary power drop',
    'Small spike',
    'Large spike',
    'UPS self test',
    'Excessive input voltage fluctuation'
]

def inventory_apc_ups_reason_last_transfer(info):
    yield None, None

def check_apc_ups_reason_last_transfer(item, params, info):
    reason = saveint(info[0][0])
    reason = 2
    if reasons[reason-1]:
        message = reasons[reason-1]
        status = 2
        if (reason == 1 or reason == 9):
            status = 0
        if (reason == 4 or reason ==6):
            status = 1
        return status, "Reason of last transfer: %s" % message

    return 1, "Reason of last transfer: Unknown"

check_info["apc_ups_reason_last_transfer"] = {
    'check_function':           check_apc_ups_reason_last_transfer,
    'inventory_function':       inventory_apc_ups_reason_last_transfer,
    'service_description':      'APC UPS reason of last transfer',
    'has_perfdata':             False,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.3.2', [
        5, # APC UPS reason of last transfer
    ]),
    'snmp_scan_function':       lambda oid: oid('1.3.6.1.4.1.318.1.1.1.3.2.5.0') != None 
}
