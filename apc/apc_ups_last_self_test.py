#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H. Eudenbach in the year 2021

def inventory_apc_ups_last_self_test(info):
    yield None, None

def check_apc_ups_last_self_test(item, params, info):
    # (pass = 1 or fail = 2)
    last_self_test = saveint(info[0][0])
    if last_self_test == 1:
        return 0, "Status of last self test: OK"
    if last_self_test == 2:
        return 2, "Status of last self test: FAIL"
    return 1, "Status of last self test: Unknown"    

check_info["apc_ups_last_self_test"] = {
    'check_function':           check_apc_ups_last_self_test,
    'inventory_function':       inventory_apc_ups_last_self_test,
    'service_description':      'APC UPS last self test status',
    'has_perfdata':             False,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.7.2', [
        3, # APC UPS Battery Capacity
    ]),
    'snmp_scan_function':       lambda oid: oid('1.3.6.1.4.1.318.1.1.1.7.2.3.0') != None 
}
