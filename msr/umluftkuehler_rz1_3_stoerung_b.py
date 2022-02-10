from .agent_based_api.v1 import *
import pprint

def discover_umluftkuehler_3_rz1_stoerung_b(section):
    yield Service()

def check_umluftkuehler_3_rz1_stoerung_b(section):
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
    name = "umluftkuehler_3_rz1_stoerung_b",
    service_name = "Umluftkühler 3 RZ1 Störung B",
    discovery_function = discover_umluftkuehler_3_rz1_stoerung_b,
    check_function = check_umluftkuehler_3_rz1_stoerung_b,
)

register.snmp_section(
    name = "umluftkuehler_3_rz1_stoerung_b",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '513.0',    # Umluftkühler 3 RZ1 Störung B
        ],
    ),
)