from .agent_based_api.v1 import *
import pprint

def discover_kaeltemaschine_2_prioalarm(section):
    yield Service()

def check_kaeltemaschine_2_prioalarm(section):
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
    name = "kaeltemaschine_2_prioalarm",
    service_name = "Kältemaschine 2 Prioalarm Störung",
    discovery_function = discover_kaeltemaschine_2_prioalarm,
    check_function = check_kaeltemaschine_2_prioalarm,
)

register.snmp_section(
    name = "kaeltemaschine_2_prioalarm",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '503.0',    # Kältemaschine 2 Prioalarm Störung
        ],
    ),
)