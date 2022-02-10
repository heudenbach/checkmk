from .agent_based_api.v1 import *
import pprint

def discover_kaeltemaschine_1_arbeitet(section):
    yield Service()

def check_kaeltemaschine_1_arbeitet(section):
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
    name = "kaeltemaschine_1_arbeitet",
    service_name = "Kältemaschine 1 arbeitet",
    discovery_function = discover_kaeltemaschine_1_arbeitet,
    check_function = check_kaeltemaschine_1_arbeitet,
)

register.snmp_section(
    name = "kaeltemaschine_1_arbeitet",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '504.0',    # Kältemaschine 1 arbeitet
        ],
    ),
)