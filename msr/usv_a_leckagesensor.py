from .agent_based_api.v1 import *
import pprint

def discover_usv_a_leckagesensor(section):
    yield Service()

def check_usv_a_leckagesensor(section):
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
    name = "usv_a_leckagesensor",
    service_name = "USV A Leckagesensor",
    discovery_function = discover_usv_a_leckagesensor,
    check_function = check_usv_a_leckagesensor,
)

register.snmp_section(
    name = "usv_a_leckagesensor",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '567.0',    # USV A Leckagesensor
        ],
    ),
)