from .agent_based_api.v1 import *
import pprint

def discover_umluftkuehler_4_ansaugtemp(section):
    yield Service()

def check_umluftkuehler_4_ansaugtemp(section):
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

    yield Metric("Ansaugtemperatur", speicher_temp, levels=(56,60), boundaries=(0,100))

    yield Result(
        state=state,
        summary="Umluftkühler 4 RZ1 Ansaugtemperatur: % 6.1f° Celcius" % (speicher_temp)
    )
    return

register.check_plugin(
    name = "umluftkuehler_4_ansaugtemp",
    service_name = "Umluftkühler 4 RZ1 Ansaugtemperatur",
    discovery_function = discover_umluftkuehler_4_ansaugtemp,
    check_function = check_umluftkuehler_4_ansaugtemp,
)

register.snmp_section(
    name = "umluftkuehler_4_ansaugtemp",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '519.0',    # Umluftkühler 4 RZ1 Ansaugtemperatur
        ],
    ),
)
