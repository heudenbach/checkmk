from .agent_based_api.v1 import *
import pprint

def discover_kaeltemaschine_1_absperrklappe(section):
    yield Service()

def check_kaeltemaschine_1_absperrklappe(section):
    meldung = int(section[0][0])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.OK
        yield Result(
            state=state,
            summary="Absperrklappe geschlossen"
        )

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary=" "
        )

    meldung = int(section[0][1])
    state = State.UNKNOWN    

    if meldung == 0:
        state = State.OK
        yield Result(
            state=state,
            summary="Absperrklappe offen"
        )

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary=" "
        )

    meldung = int(section[0][2])
    state = State.UNKNOWN    

    if meldung == 0:
        state = State.OK
        yield Result(
            state=state,
            summary="keine Störung"
        )

    if meldung == 1:
        state = State.CRIT
        yield Result(
            state=state,
            summary="ACHTUNG STÖRUNG"
        )    

    return

register.check_plugin(
    name = "kaeltemaschine_1_absperrklappe",
    service_name = "Kältemaschine 1 Absperrklappe",
    discovery_function = discover_kaeltemaschine_1_absperrklappe,
    check_function = check_kaeltemaschine_1_absperrklappe,
)

register.snmp_section(
    name = "kaeltemaschine_1_absperrklappe",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '522.0',    # Kältemaschine 1 Absperrklappe ZU
            '523.0',    # Kältemaschine 1 Absperrklappe AUF
            '524.0',    # Kältemaschine 1 Absperrklappe Störung
        ],
    ),
)