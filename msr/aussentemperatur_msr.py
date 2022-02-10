from .agent_based_api.v1 import *
import pprint

def discover_aussentemperatur_msr(section):
    yield Service()

def check_aussentemperatur_msr(section):
    aussen_temp = int(section[0][0]) / 10
    state = State.UNKNOWN

    if aussen_temp <= -20:
        state = State.CRIT

    if aussen_temp > -20 and aussen_temp < -14:
        state = State.WARN

    if aussen_temp >= -14 and aussen_temp < 45:
        state = State.OK

    if aussen_temp >= 45 and aussen_temp < 50:
        state = State.WARN

    if aussen_temp >= 50:
        state = State.CRIT

    yield Metric("Aussentemperatur", aussen_temp, boundaries=(-40,100))

    yield Result(
        state=state,
        summary="MSR Aussentemperatur: % 6.1f° Celcius" % (aussen_temp)
    )
    return

register.check_plugin(
    name = "aussentemperatur_msr",
    service_name = "MSR Aussentemperatur",
    discovery_function = discover_aussentemperatur_msr,
    check_function = check_aussentemperatur_msr,
)

register.snmp_section(
    name = "aussentemperatur_msr",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '500.0',    # Aussentemperatur MSR
        ],
    ),
)
