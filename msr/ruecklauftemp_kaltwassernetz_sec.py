from .agent_based_api.v1 import *
import pprint

def discover_ruecklauftemp_kaltwassernetz_sec(section):
    yield Service()

def check_ruecklauftemp_kaltwassernetz_sec(section):
    aussen_temp = int(section[0][0]) / 10
    state = State.UNKNOWN

    if aussen_temp <= 13:
        state = State.CRIT

    if aussen_temp > 13 and aussen_temp < 15:
        state = State.WARN

    if aussen_temp >= 15 and aussen_temp < 22:
        state = State.OK

    if aussen_temp >= 22 and aussen_temp < 26:
        state = State.WARN

    if aussen_temp >= 26:
        state = State.CRIT

    yield Metric("Kaltwassernetz_Sekundär_Rücklauftemperatur", aussen_temp, boundaries=(-40,100))

    yield Result(
        state=state,
        summary="Kaltwassernetz Sekundär Rücklauftemperatur: % 6.1f° Celcius" % (aussen_temp)
    )
    return

register.check_plugin(
    name = "ruecklauftemp_kaltwassernetz_sec",
    service_name = "Kaltwassernetz Sekundär Rücklauftemperatur",
    discovery_function = discover_ruecklauftemp_kaltwassernetz_sec,
    check_function = check_ruecklauftemp_kaltwassernetz_sec,
)

register.snmp_section(
    name = "ruecklauftemp_kaltwassernetz_sec",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '506.0',    # Kaltwassernetz Sekundär Rücklauftemperatur
        ],
    ),
)