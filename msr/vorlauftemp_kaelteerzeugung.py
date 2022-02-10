from .agent_based_api.v1 import *
import pprint

def discover_vorlauftemp_kaelteerzeugung(section):
    yield Service()

def check_vorlauftemp_kaelteerzeugung(section):
    speicher_temp = int(section[0][0]) / 10
    state = State.UNKNOWN

    if speicher_temp <= 8:
        state = State.CRIT

    if speicher_temp > 8 and speicher_temp < 10:
        state = State.WARN

    if speicher_temp >= 10 and speicher_temp < 22:
        state = State.OK

    if speicher_temp >= 22 and speicher_temp < 24:
        state = State.WARN

    if speicher_temp >= 24:
        state = State.CRIT

    yield Metric("Vorlauftemperatur", speicher_temp, levels=(56,60), boundaries=(0,100))

    yield Result(
        state=state,
        summary="Kälteerzeugung Vorlauftemperatur: % 6.1f° Celcius" % (speicher_temp)
    )
    return

register.check_plugin(
    name = "vorlauftemp_kaelteerzeugung",
    service_name = "Kälteerzeugung Vorlauftemperatur",
    discovery_function = discover_vorlauftemp_kaelteerzeugung,
    check_function = check_vorlauftemp_kaelteerzeugung,
)

register.snmp_section(
    name = "vorlauftemp_kaelteerzeugung",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '501.0',    # Kälteerzeugung Vorlauftemperatur
        ],
    ),
)
