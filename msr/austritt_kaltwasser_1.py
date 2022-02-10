from .agent_based_api.v1 import *
import pprint

def discover_austritt_kaltwasser_1(section):
    yield Service()

def check_austritt_kaltwasser_1(section):
    aussen_temp = int(section[0][0]) / 10
    state = State.UNKNOWN

    if aussen_temp <= 7:
        state = State.CRIT

    if aussen_temp > 7 and aussen_temp < 10:
        state = State.WARN

    if aussen_temp >= 10 and aussen_temp < 22:
        state = State.OK

    if aussen_temp >= 22 and aussen_temp < 26:
        state = State.WARN

    if aussen_temp >= 26:
        state = State.CRIT

    yield Metric("Temperatur_Kaltwasser_Kaeltemaschine_1", aussen_temp, boundaries=(-40,100))

    yield Result(
        state=state,
        summary="Temperatur Kaltwasser Kältemaschine 1: % 6.1f° Celcius" % (aussen_temp)
    )
    return

register.check_plugin(
    name = "austritt_kaltwasser_1",
    service_name = "Kaltwasser Kältemaschine 1 Austritt Temperatur",
    discovery_function = discover_austritt_kaltwasser_1,
    check_function = check_austritt_kaltwasser_1,
)

register.snmp_section(
    name = "austritt_kaltwasser_1",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '508.0',    # Temperatur Kaltwasser Kältemaschine 1
        ],
    ),
)