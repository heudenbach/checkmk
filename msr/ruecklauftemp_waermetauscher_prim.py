from .agent_based_api.v1 import *
import pprint

def discover_ruecklauftemp_waermetauscher_prim(section):
    yield Service()

def check_ruecklauftemp_waermetauscher_prim(section):
    aussen_temp = int(section[0][0]) / 10
    state = State.UNKNOWN

    if aussen_temp <= 8:
        state = State.CRIT

    if aussen_temp > 8 and aussen_temp < 11:
        state = State.WARN

    if aussen_temp >= 11 and aussen_temp < 21:
        state = State.OK

    if aussen_temp >= 21 and aussen_temp < 26:
        state = State.WARN

    if aussen_temp >= 26:
        state = State.CRIT

    yield Metric("Rücklauftemperatur_Wärmetauscher_Primär", aussen_temp, boundaries=(-40,100))

    yield Result(
        state=state,
        summary="Rücklauftemperatur Wärmetauscher Primär: % 6.1f° Celcius" % (aussen_temp)
    )
    return

register.check_plugin(
    name = "ruecklauftemp_waermetauscher_prim",
    service_name = "Wärmetauscher Primär Rücklauftemperatur",
    discovery_function = discover_ruecklauftemp_waermetauscher_prim,
    check_function = check_ruecklauftemp_waermetauscher_prim,
)

register.snmp_section(
    name = "ruecklauftemp_waermetauscher_prim",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '504.0',    # ruecklauftemperatur Wärmetauscher Primär
        ],
    ),
)