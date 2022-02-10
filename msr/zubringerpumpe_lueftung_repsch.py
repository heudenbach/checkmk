from .agent_based_api.v1 import *
import pprint

def discover_zubringerpumpe_lueftung_repsch(section):
    yield Service()

def check_zubringerpumpe_lueftung_repsch(section):
    meldung = int(section[0][0])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.OK
        yield Result(
            state=state,
            summary="keine Wartung"
        )

    if meldung == 1:
        state = State.WARN
        yield Result(
            state=state,
            summary="Wartung"
        )

    return

register.check_plugin(
    name = "zubringerpumpe_lueftung_repsch",
    service_name = "Zubringerpumpe Lüftung Rep.Schalter",
    discovery_function = discover_zubringerpumpe_lueftung_repsch,
    check_function = check_zubringerpumpe_lueftung_repsch,
)

register.snmp_section(
    name = "zubringerpumpe_lueftung_repsch",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '546.0',    # Zubringerpumpe Lüftung Rep.Schalter
        ],
    ),
)