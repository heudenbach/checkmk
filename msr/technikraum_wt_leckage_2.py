from .agent_based_api.v1 import *
import pprint

def discover_technikraum_wt_leckage_2(section):
    yield Service()

def check_technikraum_wt_leckage_2(section):
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
    name = "technikraum_wt_leckage_2",
    service_name = "Technikraum WT Leckagesensor 2",
    discovery_function = discover_technikraum_wt_leckage_2,
    check_function = check_technikraum_wt_leckage_2,
)

register.snmp_section(
    name = "technikraum_wt_leckage_2",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '576.0',    # Technikraum WT Leckagesensor 2
        ],
    ),
)