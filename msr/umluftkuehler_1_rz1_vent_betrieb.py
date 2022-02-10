from .agent_based_api.v1 import *
import pprint

def discover_umluftkuehler_1_rz1_vent_betrieb(section):
    yield Service()

def check_umluftkuehler_1_rz1_vent_betrieb(section):
    meldung = int(section[0][0])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.OK
        yield Result(
            state=state,
            summary="ausgeschaltet"
        )

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary="eingeschaltet"
        )

    return

register.check_plugin(
    name = "umluftkuehler_1_rz1_vent_betrieb",
    service_name = "Umluftkühler 1 RZ1 Umluftventilator Betrieb",
    discovery_function = discover_umluftkuehler_1_rz1_vent_betrieb,
    check_function = check_umluftkuehler_1_rz1_vent_betrieb,
)

register.snmp_section(
    name = "umluftkuehler_1_rz1_vent_betrieb",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '518.0',    # Umluftkühler 1 RZ1 Umluftventilator Betrieb
        ],
    ),
)