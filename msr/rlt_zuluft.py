from .agent_based_api.v1 import *
import pprint

def discover_rlt_zuluft(section):
    yield Service()

def check_rlt_zuluft(section):
    speicher_temp = int(section[0][0]) / 10
    state = State.UNKNOWN

    if speicher_temp <= -5:
        state = State.CRIT

    if speicher_temp > -5 and speicher_temp < 0:
        state = State.WARN

    if speicher_temp >= 0 and speicher_temp < 35:
        state = State.OK

    if speicher_temp >= 35 and speicher_temp < 40:
        state = State.WARN

    if speicher_temp >= 40:
        state = State.CRIT

    yield Metric("Zulufttemperatur", speicher_temp, levels=(56,60), boundaries=(0,100))

    yield Result(
        state=state,
        summary="RLT Zulufttemperatur: % 6.1f° Celcius" % (speicher_temp)
    )
    return

register.check_plugin(
    name = "rlt_zuluft",
    service_name = "RLT Zulufttemperatur",
    discovery_function = discover_rlt_zuluft,
    check_function = check_rlt_zuluft,
)

register.snmp_section(
    name = "rlt_zuluft",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '530.0',    # RLT Zulufttemperatur
        ],
    ),
)
