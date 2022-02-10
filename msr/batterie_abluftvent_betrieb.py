from .agent_based_api.v1 import *
import pprint

def discover_batterie_abluftvent_betrieb(section):
    yield Service()

def check_batterie_abluftvent_betrieb(section):
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
    name = "batterie_abluftvent_betrieb",
    service_name = "Batterie Abluftventilator Betrieb",
    discovery_function = discover_batterie_abluftvent_betrieb,
    check_function = check_batterie_abluftvent_betrieb,
)

register.snmp_section(
    name = "batterie_abluftvent_betrieb",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '560.0',    # Batterie Abluftventilator Betrieb
        ],
    ),
)