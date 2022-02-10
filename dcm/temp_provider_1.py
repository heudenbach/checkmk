from .agent_based_api.v1 import *
import pprint

def discover_temp_provider_1(section):
    yield Service()

def check_temp_provider_1(section):
    aussen_temp = float(section[0][0])
    state = State.UNKNOWN

    if aussen_temp <= 19:
        state = State.CRIT

    if aussen_temp > 19 and aussen_temp < 21:
        state = State.WARN

    if aussen_temp >= 21 and aussen_temp < 31:
        state = State.OK

    if aussen_temp >= 31 and aussen_temp < 33:
        state = State.WARN

    if aussen_temp >= 33:
        state = State.CRIT

    yield Metric("Temperatur", aussen_temp, boundaries=(-40,100))

    yield Result(
        state=state,
        summary="Temperatur Provider 1: % 6.1f° Celcius" % (aussen_temp)
    )
    return

register.check_plugin(
    name = "temp_provider_1",
    service_name = "Provider 1 Temperatur",
    discovery_function = discover_temp_provider_1,
    check_function = check_temp_provider_1,
)

register.snmp_section(
    name = "temp_provider_1",
    detect = all_of(
    exists(".1.3.6.1.3.1.0.10"),
    exists(".1.3.6.1.3.1.0.11"),
    exists(".1.3.6.1.3.1.0.12"),
    exists(".1.3.6.1.3.1.0.13"),
    exists(".1.3.6.1.3.1.0.14"),
    exists(".1.3.6.1.3.1.0.15"),
    exists(".1.3.6.1.3.1.0.16"),
    exists(".1.3.6.1.3.1.0.17"),
    exists(".1.3.6.1.3.1.0.18"),
    exists(".1.3.6.1.3.1.0.19"),
    exists(".1.3.6.1.3.1.0.20"),
    exists(".1.3.6.1.3.1.0.21"),
    exists(".1.3.6.1.3.1.0.22"),
    exists(".1.3.6.1.3.1.0.23"),
    exists(".1.3.6.1.3.1.0.24"),
    exists(".1.3.6.1.3.1.0.25")
    ),
        fetch = SNMPTree(
        base = '.1.3.6.1.3.1.10',
        oids = [
            '2.0',    # Temperatur Provider 1
        ],
    ),
)