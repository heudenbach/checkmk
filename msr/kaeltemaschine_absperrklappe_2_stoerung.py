from .agent_based_api.v1 import *
import pprint

def discover_kaeltemaschine_absperrklappe_2_stoer(section):
    yield Service()

def check_kaeltemaschine_absperrklappe_2_stoer(section):
    meldung = int(section[0][0])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.OK
        yield Result(
            state=state,
            summary="nein"
        )

    if meldung == 1:
        state = State.CRIT
        yield Result(
            state=state,
            summary="ja"
        )

    return

register.check_plugin(
    name = "kaeltemaschine_absperrklappe_2_stoer",
    service_name = "Kältemaschine 2 Absperrklappe Störung",
    discovery_function = discover_kaeltemaschine_absperrklappe_2_stoer,
    check_function = check_kaeltemaschine_absperrklappe_2_stoer,
)

register.snmp_section(
    name = "kaeltemaschine_absperrklappe_2_stoer",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '527.0',    # Kältemaschine 2 Absperrklappe Störung
        ],
    ),
)