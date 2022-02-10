from .agent_based_api.v1 import *
import pprint

def discover_nshv_b_leckage(section):
    yield Service()

def check_nshv_b_leckage(section):
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
    name = "nshv_b_leckage",
    service_name = "NSHV B Leckagesensor",
    discovery_function = discover_nshv_b_leckage,
    check_function = check_nshv_b_leckage,
)

register.snmp_section(
    name = "nshv_b_leckage",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '573.0',    # NSHV B Leckagesensor
        ],
    ),
)