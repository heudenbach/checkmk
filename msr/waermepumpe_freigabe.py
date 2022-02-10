from .agent_based_api.v1 import *
import pprint

def discover_waermepumpe_freigabe(section):
    yield Service()

def check_waermepumpe_freigabe(section):
    meldung = int(section[0][0])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.OK
        yield Result(
            state=state,
            summary="eingeschaltet"
        )

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary="ausgeschaltet"
        )

    return

register.check_plugin(
    name = "waermepumpe_freigabe",
    service_name = "Wärmepumpe Freigabe",
    discovery_function = discover_waermepumpe_freigabe,
    check_function = check_waermepumpe_freigabe,
)

register.snmp_section(
    name = "waermepumpe_freigabe",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '548.0',    # Wärmepumpe Freigabe
        ],
    ),
)