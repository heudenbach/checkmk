#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# H.Eudenbach in 2021 - holger@eude.rocks

def inventory_apc_ups_manufacturer_date(info):
    yield None, None

def check_apc_ups_manufacturer_date(item, params, info):
    return 0, "Manufacturer date: %s" % info[0][0]

check_info["apc_ups_manufacturer_date"] = {
    'check_function':           check_apc_ups_manufacturer_date,
    'inventory_function':       inventory_apc_ups_manufacturer_date,
    'service_description':      'APC UPS Manufacturer Date',
    'has_perfdata':             False,
    'snmp_info':                ('.1.3.6.1.4.1.318.1.1.1.1.2', [
        2, # APC UPS Manufacturer Date
    ]),
    'snmp_scan_function':       lambda oid: oid('.1.3.6.1.4.1.318.1.1.1.1.2.2.0') != None 
}
