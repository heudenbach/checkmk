from .agent_based_api.v1 import *
import pprint

def discover_provider_2_luftfeuchte(section):
    yield Service()

def check_provider_2_luftfeuchte(section):
    luftfeuchte = float(str(section[0][0]))
    state = State.UNKNOWN

    if luftfeuchte <= 10:
        state = State.CRIT

    if luftfeuchte > 10 and luftfeuchte < 15:
        state = State.WARN

    if luftfeuchte >= 15 and luftfeuchte < 75:
        state = State.OK

    if luftfeuchte >= 75 and luftfeuchte < 80:
        state = State.WARN

    if luftfeuchte >= 80:
        state = State.CRIT

    yield Metric("Luftfeuchtigkeit", luftfeuchte, boundaries=(0,100))

    yield Result(
        state=state,
        summary="Luftfeuchtigkeit: % 6.1f" % (luftfeuchte)
    )
    return

register.check_plugin(
    name = "provider_2_luftfeuchte",
    service_name = "Provider 2 Luftfeuchtigkeit",
    discovery_function = discover_provider_2_luftfeuchte,
    check_function = check_provider_2_luftfeuchte,
)

register.snmp_section(
    name = "provider_2_luftfeuchte",
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
        base = '.1.3.6.1.3.1.2',
        oids = [
            '3.0',    # Provider 2 Luftfeuchtigkeit
        ],
    ),
)