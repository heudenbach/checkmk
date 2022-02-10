from .agent_based_api.v1 import *
import pprint

def discover_bsk_abluft_batterie_usvb(section):
    yield Service()

def check_bsk_abluft_batterie_usvb(section):
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
    name = "bsk_abluft_batterie_usvb",
    service_name = "BSK Abluft Batterie USV B Störung",
    discovery_function = discover_bsk_abluft_batterie_usvb,
    check_function = check_bsk_abluft_batterie_usvb,
)

register.snmp_section(
    name = "bsk_abluft_batterie_usvb",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '564.0',    # BSK Abluft Batterie USV B Störung
        ],
    ),
)