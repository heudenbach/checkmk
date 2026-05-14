#!/usr/bin/env python3

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
)


def parse_html_content_check(string_table):
    parsed = {}

    for row in string_table:
        if len(row) not in (3, 4):
            continue

        service_name, state, message = row[:3]

        data = {
            "state": int(state),
            "message": message,
        }

        if len(row) == 4:
            try:
                data["metric_value"] = float(row[3])
            except ValueError:
                pass

        parsed[service_name] = data

    return parsed


agent_section_html_content_check = AgentSection(
    name="html_content_check",
    parse_function=parse_html_content_check,
)


def discover_html_content_check(section):
    for item in section:
        yield Service(item=item)


def check_html_content_check(item, section):
    data = section.get(item)

    if not data:
        yield Result(
            state=State.UNKNOWN,
            summary="No data received",
        )
        return

    state_map = {
        0: State.OK,
        1: State.WARN,
        2: State.CRIT,
        3: State.UNKNOWN,
    }

    yield Result(
        state=state_map.get(data["state"], State.UNKNOWN),
        summary=data["message"],
    )

    if "metric_value" in data:
        yield Metric(
            "file_content_value",
            data["metric_value"],
        )


check_plugin_html_content_check = CheckPlugin(
    name="html_content_check",
    service_name="%s",
    discovery_function=discover_html_content_check,
    check_function=check_html_content_check,
)
