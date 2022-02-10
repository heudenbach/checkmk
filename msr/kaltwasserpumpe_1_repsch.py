from .agent_based_api.v1 import *
import pprint

def discover_kaltwasserpumpe_1_repsch(section):
    yield Service()

def check_kaltwasserpumpe_1_repsch(section):
    meldung = int(section[0][0])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.OK
        yield Result(
            state=state,
            summary="keine Wartung"
        )

    if meldung == 1:
        state = State.WARN
        yield Result(
            state=state,
            summary="Wartung"
        )

    return

register.check_plugin(
    name = "kaltwasserpumpe_1_repsch",
    service_name = "Kaltwasserpumpe 1 Rep.Schalter",
    discovery_function = discover_kaltwasserpumpe_1_repsch,
    check_function = check_kaltwasserpumpe_1_repsch,
)

register.snmp_section(
    name = "kaltwasserpumpe_1_repsch",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '540.0',    # Kaltwasserpumpe 1 Rep.Schalter
        ],
    ),
)