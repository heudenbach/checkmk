from .agent_based_api.v1 import *
import pprint

def discover_umluftkuehler_1_ausblastemp(section):
    yield Service()

def check_umluftkuehler_1_ausblastemp(section):
    speicher_temp = int(section[0][0]) / 10
    state = State.UNKNOWN

    if speicher_temp <= 5:
        state = State.CRIT

    if speicher_temp > 5 and speicher_temp < 10:
        state = State.WARN

    if speicher_temp >= 10 and speicher_temp < 30:
        state = State.OK

    if speicher_temp >= 30 and speicher_temp < 35:
        state = State.WARN

    if speicher_temp >= 35:
        state = State.CRIT

    yield Metric("Ausblastemperatur", speicher_temp, levels=(56,60), boundaries=(0,100))

    yield Result(
        state=state,
        summary="Umluftkühler 1 RZ1 Ausblastemperatur: % 6.1f° Celcius" % (speicher_temp)
    )
    return

register.check_plugin(
    name = "umluftkuehler_1_ausblastemp",
    service_name = "Umluftkühler 1 RZ1 Ausblastemperatur",
    discovery_function = discover_umluftkuehler_1_ausblastemp,
    check_function = check_umluftkuehler_1_ausblastemp,
)

register.snmp_section(
    name = "umluftkuehler_1_ausblastemp",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '514.0',    # Umluftkühler 1 RZ1 Ausblastemperatur
        ],
    ),
)
