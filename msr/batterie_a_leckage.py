from .agent_based_api.v1 import *
import pprint

def discover_batterie_a_leckage(section):
    yield Service()

def check_batterie_a_leckage(section):
    meldung = int(section[0][0])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.OK
        yield Result(
            state=state,
            summary="keine Meldungen"
        )

    if meldung == 1:
        state = State.CRIT
        yield Result(
            state=state,
            summary="Störung"
        )

    return

register.check_plugin(
    name = "batterie_a_leckage",
    service_name = "Batterie A Leckagesensor",
    discovery_function = discover_batterie_a_leckage,
    check_function = check_batterie_a_leckage,
)

register.snmp_section(
    name = "batterie_a_leckage",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '566.0',    # Batterie A Leckagesensor
        ],
    ),
)