from .agent_based_api.v1 import *
import pprint

def discover_temp_msr_kaelte(section):
    yield Service()

def check_temp_msr_kaelte(section):
    aussen_temp = float(section[0][0])
    state = State.UNKNOWN

    if aussen_temp <= 16:
        state = State.CRIT

    if aussen_temp > 16 and aussen_temp < 17:
        state = State.WARN

    if aussen_temp >= 17 and aussen_temp < 27:
        state = State.OK

    if aussen_temp >= 27 and aussen_temp < 28:
        state = State.WARN

    if aussen_temp >= 28:
        state = State.CRIT

    yield Metric("Temperatur", aussen_temp, boundaries=(-40,100))

    yield Result(
        state=state,
        summary="Temperatur MSR/Kälte: % 6.1f° Celcius" % (aussen_temp)
    )
    return

register.check_plugin(
    name = "temp_msr_kaelte",
    service_name = "MSR/Kälte Temperatur",
    discovery_function = discover_temp_msr_kaelte,
    check_function = check_temp_msr_kaelte,
)

register.snmp_section(
    name = "temp_msr_kaelte",
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
        base = '.1.3.6.1.3.1.2',
        oids = [
            '4.0',    # Temperatur MSR/Kälte
        ],
    ),
)