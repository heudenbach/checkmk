from .agent_based_api.v1 import *
import pprint

def discover_rlt_zuluftventilator_betrieb(section):
    yield Service()

def check_rlt_zuluftventilator_betrieb(section):
    meldung = int(section[0][0])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.OK
        yield Result(
            state=state,
            summary="ausgeschaltet"
        )

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary="eingeschaltet"
        )

    return

register.check_plugin(
    name = "rlt_zuluftventilator_betrieb",
    service_name = "RLT Zuluftventilator Betrieb",
    discovery_function = discover_rlt_zuluftventilator_betrieb,
    check_function = check_rlt_zuluftventilator_betrieb,
)

register.snmp_section(
    name = "rlt_zuluftventilator_betrieb",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '549.0',    # RLT Zuluftventilator Betrieb
        ],
    ),
)