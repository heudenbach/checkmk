from .agent_based_api.v1 import *
import pprint

def discover_kaeltemaschine_1_prioalarm(section):
    yield Service()

def check_kaeltemaschine_1_prioalarm(section):
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
    name = "kaeltemaschine_1_prioalarm",
    service_name = "Kältemaschine 1 Prioalarm Störung",
    discovery_function = discover_kaeltemaschine_1_prioalarm,
    check_function = check_kaeltemaschine_1_prioalarm,
)

register.snmp_section(
    name = "kaeltemaschine_1_prioalarm",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '502.0',    # Kältemaschine 1 Prioalarm Störung
        ],
    ),
)