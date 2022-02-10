from .agent_based_api.v1 import *
import pprint

def discover_eintritt_kaltwasser_2(section):
    yield Service()

def check_eintritt_kaltwasser_2(section):
    aussen_temp = int(section[0][0]) / 10
    state = State.UNKNOWN

    if aussen_temp <= 2:
        state = State.CRIT

    if aussen_temp > 2 and aussen_temp < 7:
        state = State.WARN

    if aussen_temp >= 7 and aussen_temp < 22:
        state = State.OK

    if aussen_temp >= 22 and aussen_temp < 26:
        state = State.WARN

    if aussen_temp >= 26:
        state = State.CRIT

    yield Metric("Temperatur_Kaltwasser_Kaeltemaschine_2", aussen_temp, boundaries=(-40,100))

    yield Result(
        state=state,
        summary="Temperatur Kaltwasser Kältemaschine 2: % 6.1f° Celcius" % (aussen_temp)
    )
    return

register.check_plugin(
    name = "eintritt_kaltwasser_2",
    service_name = "Kaltwasser Kältemaschine 2 Eintritt Temperatur",
    discovery_function = discover_eintritt_kaltwasser_2,
    check_function = check_eintritt_kaltwasser_2,
)

register.snmp_section(
    name = "eintritt_kaltwasser_2",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '509.0',    # Temperatur Kaltwasser Kältemaschine 2
        ],
    ),
)