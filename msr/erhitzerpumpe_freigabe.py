from .agent_based_api.v1 import *
import pprint

def discover_erhitzerpumpe_freigabe(section):
    yield Service()

def check_erhitzerpumpe_freigabe(section):
    meldung = int(section[0][0])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.OK
        yield Result(
            state=state,
            summary="ja"
        )

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary="nein"
        )

    return

register.check_plugin(
    name = "erhitzerpumpe_freigabe",
    service_name = "Erhitzerpumpe Freigabe",
    discovery_function = discover_erhitzerpumpe_freigabe,
    check_function = check_erhitzerpumpe_freigabe,
)

register.snmp_section(
    name = "erhitzerpumpe_freigabe",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '556.0',    # Erhitzerpumpe Freigabe
        ],
    ),
)