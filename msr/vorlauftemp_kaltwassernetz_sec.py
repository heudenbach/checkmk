from .agent_based_api.v1 import *
import pprint

def discover_vorlauftemp_kaltwassernetz_sec(section):
    yield Service()

def check_vorlauftemp_kaltwassernetz_sec(section):
    aussen_temp = int(section[0][0]) / 10
    state = State.UNKNOWN

    if aussen_temp <= 13:
        state = State.CRIT

    if aussen_temp > 13 and aussen_temp < 15:
        state = State.WARN

    if aussen_temp >= 15 and aussen_temp < 22:
        state = State.OK

    if aussen_temp >= 22 and aussen_temp < 24:
        state = State.WARN

    if aussen_temp >= 24:
        state = State.CRIT

    yield Metric("Kaltwassernetz_Sekundär_Vorlauftemperatur", aussen_temp, boundaries=(-40,100))

    yield Result(
        state=state,
        summary="Kaltwassernetz Sekundär Vorlauftemperatur: % 6.1f° Celcius" % (aussen_temp)
    )
    return

register.check_plugin(
    name = "vorlauftemp_kaltwassernetz_sec",
    service_name = "Kaltwassernetz Sekundär Vorlauftemperatur",
    discovery_function = discover_vorlauftemp_kaltwassernetz_sec,
    check_function = check_vorlauftemp_kaltwassernetz_sec,
)

register.snmp_section(
    name = "vorlauftemp_kaltwassernetz_sec",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '505.0',    # Kaltwassernetz Sekundär Vorlauftemperatur
        ],
    ),
)