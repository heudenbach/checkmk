from .agent_based_api.v1 import *
import pprint

def discover_temp_nshv_a(section):
    yield Service()

def check_temp_nshv_a(section):
    aussen_temp = float(section[0][0])
    state = State.UNKNOWN

    if aussen_temp <= 15:
        state = State.CRIT

    if aussen_temp > 15 and aussen_temp < 16:
        state = State.WARN

    if aussen_temp >= 16 and aussen_temp < 28:
        state = State.OK

    if aussen_temp >= 28 and aussen_temp < 29:
        state = State.WARN

    if aussen_temp >= 29:
        state = State.CRIT

    yield Metric("Temperatur", aussen_temp, boundaries=(-40,100))

    yield Result(
        state=state,
        summary="Temperatur NSHV A: % 6.1f° Celcius" % (aussen_temp)
    )
    return

register.check_plugin(
    name = "temp_nshv_a",
    service_name = "NSHV A Temperatur",
    discovery_function = discover_temp_nshv_a,
    check_function = check_temp_nshv_a,
)

register.snmp_section(
    name = "temp_nshv_a",
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
        base = '.1.3.6.1.3.1',
        oids = [
            '10.0',    # Temperatur NSHV A
        ],
    ),
)