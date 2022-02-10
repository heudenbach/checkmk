from .agent_based_api.v1 import *
import pprint

def discover_rlt_abluftventilator(section):
    yield Service()

def check_rlt_abluftventilator(section):
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
    name = "rlt_abluftventilator",
    service_name = "RLT Abluftventilator",
    discovery_function = discover_rlt_abluftventilator,
    check_function = check_rlt_abluftventilator,
)

register.snmp_section(
    name = "rlt_abluftventilator",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '553.0',    # RLT Abluftventilator
        ],
    ),
)