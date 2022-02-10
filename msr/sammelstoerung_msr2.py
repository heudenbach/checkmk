from .agent_based_api.v1 import *
import pprint

def discover_sammelstoerung_msr2(section):
    yield Service()

def check_sammelstoerung_msr2(section):
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
    name = "sammelstoerung_msr2",
    service_name = "Sammelstörung MSR2",
    discovery_function = discover_sammelstoerung_msr2,
    check_function = check_sammelstoerung_msr2,
)

register.snmp_section(
    name = "sammelstoerung_msr2",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '501.0',    # Sammelstörung MSR2
        ],
    ),
)