from .agent_based_api.v1 import *
import pprint

def discover_rlt_zuluftventilator(section):
    yield Service()

def check_rlt_zuluftventilator(section):
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
    name = "rlt_zuluftventilator",
    service_name = "RLT Zuluftventilator",
    discovery_function = discover_rlt_zuluftventilator,
    check_function = check_rlt_zuluftventilator,
)

register.snmp_section(
    name = "rlt_zuluftventilator",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '550.0',    # RLT Zuluftventilator
        ],
    ),
)