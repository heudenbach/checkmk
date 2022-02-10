from .agent_based_api.v1 import *
import pprint

def discover_anlagendruck_wasserkreis_sec(section):
    yield Service()

def check_anlagendruck_wasserkreis_sec(section):
    aussen_temp = int(section[0][0]) / 10
    state = State.UNKNOWN

    if aussen_temp <= 1:
        state = State.CRIT

    if aussen_temp > 1 and aussen_temp < 1.2:
        state = State.WARN

    if aussen_temp >= 1.2 and aussen_temp < 2.2:
        state = State.OK

    if aussen_temp >= 2.2 and aussen_temp < 2.5:
        state = State.WARN

    if aussen_temp >= 2.5:
        state = State.CRIT

    yield Metric("Anlagendruck", aussen_temp, boundaries=(-40,100))

    yield Result(
        state=state,
        summary="Wasserkreis Sekundär Anlagendruck: % 6.1f Bar" % (aussen_temp)
    )
    return

register.check_plugin(
    name = "anlagendruck_wasserkreis_sec",
    service_name = "Wasserkreis Sekundär Anlagendruck",
    discovery_function = discover_anlagendruck_wasserkreis_sec,
    check_function = check_anlagendruck_wasserkreis_sec,
)

register.snmp_section(
    name = "anlagendruck_wasserkreis_sec",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '512.0',    # Wasserkreis Sekundär Anlagendruck
        ],
    ),
)
