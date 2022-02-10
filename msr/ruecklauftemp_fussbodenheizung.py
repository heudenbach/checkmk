from .agent_based_api.v1 import *
import pprint

def discover_ruecklauftemp_fussbodenheizung(section):
    yield Service()

def check_ruecklauftemp_fussbodenheizung(section):
    speicher_temp = int(section[0][0]) / 10
    state = State.UNKNOWN

    if speicher_temp <= 15:
        state = State.CRIT

    if speicher_temp > 15 and speicher_temp < 20:
        state = State.WARN

    if speicher_temp >= 20 and speicher_temp < 40:
        state = State.OK

    if speicher_temp >= 40 and speicher_temp < 45:
        state = State.WARN

    if speicher_temp >= 45:
        state = State.CRIT

    yield Metric("ruecklauftemperatur", speicher_temp, levels=(56,60), boundaries=(0,100))

    yield Result(
        state=state,
        summary="Fussbodenheizung Ruecklauftemperatur: % 6.1f° Celcius" % (speicher_temp)
    )
    return

register.check_plugin(
    name = "ruecklauftemp_fussbodenheizung",
    service_name = "Fußbodenheizung Rücklauftemperatur",
    discovery_function = discover_ruecklauftemp_fussbodenheizung,
    check_function = check_ruecklauftemp_fussbodenheizung,
)

register.snmp_section(
    name = "ruecklauftemp_fussbodenheizung",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '529.0',    # Fußbodenheizung Rücklauftemperatur
        ],
    ),
)
