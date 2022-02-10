from .agent_based_api.v1 import *
import pprint

def discover_aussenluftfilter_verschmutzt(section):
    yield Service()

def check_aussenluftfilter_verschmutzt(section):
    meldung = int(section[0][0])
    state = State.UNKNOWN

    if meldung == 1:
        state = State.WARM
        yield Result(
            state=state,
            summary="ja"
        )

    if meldung == 0:
        state = State.OK
        yield Result(
            state=state,
            summary="nein"
        )

    return

register.check_plugin(
    name = "aussenluftfilter_verschmutzt",
    service_name = "Außenluftfilter verschmutzt",
    discovery_function = discover_aussenluftfilter_verschmutzt,
    check_function = check_aussenluftfilter_verschmutzt,
)

register.snmp_section(
    name = "aussenluftfilter_verschmutzt",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
        fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.2.1.2',
        oids = [
            '558.0',    # Außenluftfilter verschmutzt
        ],
    ),
)