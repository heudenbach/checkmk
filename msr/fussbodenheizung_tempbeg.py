from .agent_based_api.v1 import *
import pprint

def discover_fussbodenheizung_tempbeg(section):
    yield Service()

def check_fussbodenheizung_tempbeg(section):
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
    name = "fussbodenheizung_tempbeg",
    service_name = "Fußbodenheizung Temperaturbegrenzer",
    discovery_function = discover_fussbodenheizung_tempbeg,
    check_function = check_fussbodenheizung_tempbeg,
)

register.snmp_section(
    name = "fussbodenheizung_tempbeg",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '545.0',    # Fußbodenheizung Temperaturbegrenzer
        ],
    ),
)