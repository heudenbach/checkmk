from .agent_based_api.v1 import *
import pprint

def discover_kaelteversorgung_absperrklappe_buero_zu(section):
    yield Service()

def check_kaelteversorgung_absperrklappe_buero_zu(section):
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
    name = "kaelteversorgung_absperrklappe_buero_zu",
    service_name = "Kälteversorgung Absperrklappe Bürobereich ZU",
    discovery_function = discover_kaelteversorgung_absperrklappe_buero_zu,
    check_function = check_kaelteversorgung_absperrklappe_buero_zu,
)

register.snmp_section(
    name = "kaelteversorgung_absperrklappe_buero_zu",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '536.0',    # Kälteversorgung Absperrklappe Bürobereich ZU
        ],
    ),
)