from .agent_based_api.v1 import *
import pprint

def discover_kaltgantemp_1_rz1(section):
    yield Service()

def check_kaltgantemp_1_rz1(section):
    speicher_temp = int(section[0][0]) / 10
    state = State.UNKNOWN

    if speicher_temp <= 5:
        state = State.CRIT

    if speicher_temp > 5 and speicher_temp < 10:
        state = State.WARN

    if speicher_temp >= 10 and speicher_temp < 27:
        state = State.OK

    if speicher_temp >= 27 and speicher_temp < 28:
        state = State.WARN

    if speicher_temp >= 28:
        state = State.CRIT

    yield Metric("Kaltgangtemperatur", speicher_temp, levels=(56,60), boundaries=(0,100))

    yield Result(
        state=state,
        summary="Kaltgangtemperatur 1 RZ1: % 6.1f° Celcius" % (speicher_temp)
    )
    return

register.check_plugin(
    name = "kaltgantemp_1_rz1",
    service_name = "Kaltgangtemperatur 1 RZ",
    discovery_function = discover_kaltgantemp_1_rz1,
    check_function = check_kaltgantemp_1_rz1,
)

register.snmp_section(
    name = "kaltgantemp_1_rz1",
    detect = startswith(".1.3.6.1.2.1.1.1.0", "Saia Burgess Controls - Saia PCD Operating System"),
    fetch = SNMPTree(
        base = '.1.3.6.1.4.1.31977.4.3.1.3',
        oids = [
            '521.0',    # Kaltgangtemperatur 1 RZ
        ],
    ),
)
