from .agent_based_api.v1 import *
import pprint

def discover_ema_stoerung(section):
    yield Service()

def check_ema_stoerung(section):
    meldung = int(section[0][0])
    state = State.UNKNOWN

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary="keine Störung"
        )

    if meldung == 0:
        state = State.CRIT
        yield Result(
            state=state,
            summary="STÖRUNG"
        )

    return

register.check_plugin(
    name = "ema_stoerung",
    service_name = "EMA Störung",
    discovery_function = discover_ema_stoerung,
    check_function = check_ema_stoerung,
)

register.snmp_section(
    name = "ema_stoerung",
    detect = all_of(
    exists(".1.3.6.1.3.1.0.10"),
    exists(".1.3.6.1.3.1.0.11"),
    exists(".1.3.6.1.3.1.0.12"),
    exists(".1.3.6.1.3.1.0.13"),
    exists(".1.3.6.1.3.1.0.14"),
    exists(".1.3.6.1.3.1.0.15"),
    exists(".1.3.6.1.3.1.0.16"),
    exists(".1.3.6.1.3.1.0.17"),
    exists(".1.3.6.1.3.1.0.18"),
    exists(".1.3.6.1.3.1.0.19"),
    exists(".1.3.6.1.3.1.0.20"),
    exists(".1.3.6.1.3.1.0.21"),
    exists(".1.3.6.1.3.1.0.22"),
    exists(".1.3.6.1.3.1.0.23"),
    exists(".1.3.6.1.3.1.0.24"),
    exists(".1.3.6.1.3.1.0.25")
    ),
        fetch = SNMPTree(
        base = '.1.3.6.1.3.1.3',
        oids = [
            '13.0',    # Einruch Alarm
        ],
    ),
)