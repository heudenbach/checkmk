from .agent_based_api.v1 import *
import pprint

def discover_pv01_nshv(section):
    yield Service()

def check_pv01_nshv(section):
    meldung = int(section[0][0])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.WARN
        yield Result(
            state=state,
            summary="Bypasschalter A EIN"
        )

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary="Bypasschalter A AUS"
        )

    meldung = int(section[0][1])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.WARN
        yield Result(
            state=state,
            summary="Einspeiseschalter A EIN"
        )

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary="Einspeiseschalter A AUS"
        )

    meldung = int(section[0][2])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.WARN
        yield Result(
            state=state,
            summary="Netzw A EIN"
        )

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary="Netzw A AUS"
        )    

    meldung = int(section[0][3])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.WARN
        yield Result(
            state=state,
            summary="Bypasschalter B EIN"
        )

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary="Bypasschalter B AUS"
        )

    meldung = int(section[0][4])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.WARN
        yield Result(
            state=state,
            summary="Einspeiseschalter B EIN"
        )

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary="Einspeiseschalter B AUS"
        )

    meldung = int(section[0][5])
    state = State.UNKNOWN

    if meldung == 0:
        state = State.WARN
        yield Result(
            state=state,
            summary="Netzw B EIN"
        )

    if meldung == 1:
        state = State.OK
        yield Result(
            state=state,
            summary="Netzw B AUS"
        )

    return


register.check_plugin(
    name = "pv01_nshv",
    service_name = "PV01 NSHV Bypassschalter",
    discovery_function = discover_pv01_nshv,
    check_function = check_pv01_nshv,
)

register.snmp_section(
    name = "pv01_nshv",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '802.0',    # pv01-nshv-a-bypassschalter
            '803.0',    # pv01-nshv-a-einspeiseschalter
            '804.0',    # pv01-nshv-a-netzw
            '805.0',    # pv01-nshv-b-bypassschalter
            '806.0',    # pv01-nshv-b-einspeiseschalter
            '807.0',    # pv01-nshv-b-netzw
        ],
    ),
)