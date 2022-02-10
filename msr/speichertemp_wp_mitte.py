from .agent_based_api.v1 import *
import pprint

def discover_speichertemp_wp_mitte(section):
    yield Service()

def check_speichertemp_wp_mitte(section):
    speicher_temp = int(section[0][0]) / 10
    state = State.UNKNOWN
    
    if speicher_temp <= 26:
        state = State.CRIT

    if speicher_temp > 26 and speicher_temp < 29:
        state = State.WARN

    if speicher_temp >= 29 and speicher_temp < 56:
        state = State.OK

    if speicher_temp >= 56 and speicher_temp < 60:
        state = State.WARN

    if speicher_temp >= 60:
        state = State.CRIT

    yield Metric("Speichertemperatur", speicher_temp, levels=(56,60), boundaries=(0,100))

    yield Result(
        state=state,
        summary="Wärmepumpe Mitte Speichertemperatur: % 6.1f° Celcius" % (speicher_temp)
    )
    return

register.check_plugin(
    name = "speichertemp_wp_mitte",
    service_name = "Wärmepumpe Mitte Speichertemperatur",
    discovery_function = discover_speichertemp_wp_mitte,
    check_function = check_speichertemp_wp_mitte,
)

register.snmp_section(
    name = "speichertemp_wp_mitte",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '525.0',    # Speichertemperatur Wärmepumpe Mitte
        ],
    ),
)
