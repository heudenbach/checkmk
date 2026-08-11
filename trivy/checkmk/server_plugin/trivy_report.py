#!/usr/bin/env python3

import json

from datetime import datetime, timezone

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    Metric,
    Result,
    Service,
    State,
)


DEFAULT_PARAMETERS = {
    "ranges": [
        {
            "minimum": 9.0,
            "maximum": 10.0,
            "warn_count": ("disabled", None),
            "crit_count": ("enabled", 1),
        },
        {
            "minimum": 7.0,
            "maximum": 8.9,
            "warn_count": ("enabled", 1),
            "crit_count": ("disabled", None),
        },
        {
            "minimum": 0.0,
            "maximum": 6.9,
            "warn_count": ("disabled", None),
            "crit_count": ("disabled", None),
        },
    ],

    "unknown_warn": ("disabled", None),
    "unknown_crit": ("disabled", None),

    "age_warn": ("enabled", 8),
    "age_crit": ("enabled", 14),
}


def parse_trivy_report(string_table):
    if not string_table:
        return None

    try:
        raw = "\n".join(line[0] for line in string_table)
        return json.loads(raw)

    except (json.JSONDecodeError, IndexError, TypeError):
        return None


agent_section_trivy_report = AgentSection(
    name="trivy_report",
    parse_function=parse_trivy_report,
)


def discover_trivy_report(section):
    if section is not None:
        yield Service()


def _threshold_value(config):
    if not config:
        return None

    try:
        choice, value = config
    except (TypeError, ValueError):
        return None

    if choice != "enabled":
        return None

    if value is None:
        return None

    return int(value)


def _state_for_count(count, warn=None, crit=None):
    if crit is not None and count >= crit:
        return State.CRIT

    if warn is not None and count >= warn:
        return State.WARN

    return State.OK


def _worst_state(states):
    if State.CRIT in states:
        return State.CRIT

    if State.UNKNOWN in states:
        return State.UNKNOWN

    if State.WARN in states:
        return State.WARN

    return State.OK


def _validate_ranges(ranges):
    normalized = []

    for entry in ranges:
        try:
            minimum = float(entry["minimum"])
            maximum = float(entry["maximum"])
        except (KeyError, TypeError, ValueError):
            return False, "Invalid CVSS range configuration"

        if minimum > maximum:
            return (
                False,
                (
                    f"Invalid CVSS range {minimum:g}-{maximum:g}: "
                    "minimum is greater than maximum"
                ),
            )

        normalized.append(
            (
                minimum,
                maximum,
            )
        )

    normalized.sort()

    for index in range(1, len(normalized)):
        previous_min, previous_max = normalized[index - 1]
        current_min, current_max = normalized[index]

        if current_min <= previous_max:
            return (
                False,
                (
                    "Overlapping CVSS ranges: "
                    f"{previous_min:g}-{previous_max:g} and "
                    f"{current_min:g}-{current_max:g}"
                ),
            )

    return True, ""


def _report_age_hours(generated):
    if not generated:
        return None

    try:
        timestamp = generated.replace("Z", "+00:00")
        generated_time = datetime.fromisoformat(timestamp)

        if generated_time.tzinfo is None:
            generated_time = generated_time.replace(
                tzinfo=timezone.utc
            )

        now = datetime.now(timezone.utc)

        age_seconds = (
            now - generated_time.astimezone(timezone.utc)
        ).total_seconds()

        if age_seconds < 0:
            return 0.0

        return age_seconds / 3600.0

    except (TypeError, ValueError):
        return None


def _format_age(hours):
    if hours < 1:
        return f"{int(hours * 60)} min"

    if hours < 24:
        return f"{hours:.1f} h"

    return f"{hours / 24.0:.1f} d"


def _metric_component(value):
    """
    Convert a score into a safe metric-name component.

    Examples:
        9.0  -> 9_0
        8.9  -> 8_9
        10.0 -> 10_0
    """
    return f"{float(value):.1f}".replace(".", "_")


def _metric_name(minimum, maximum):
    return (
        "trivy_cvss_"
        f"{_metric_component(minimum)}_"
        f"{_metric_component(maximum)}"
    )


def check_trivy_report(params, section):
    if section is None:
        yield Result(
            state=State.UNKNOWN,
            summary="No valid Trivy report data",
        )
        return

    ranges = params.get("ranges", [])

    valid, error = _validate_ranges(ranges)

    if not valid:
        yield Result(
            state=State.UNKNOWN,
            summary=error,
        )
        return

    cves = section.get("cves", [])

    states = []
    result_parts = []
    matched_cves = set()

    sorted_ranges = sorted(
        ranges,
        key=lambda entry: float(entry["minimum"]),
        reverse=True,
    )

    #
    # CVSS ranges
    #
    for entry in sorted_ranges:
        minimum = float(entry["minimum"])
        maximum = float(entry["maximum"])

        warn_count = _threshold_value(
            entry.get("warn_count")
        )

        crit_count = _threshold_value(
            entry.get("crit_count")
        )

        matching = [
            cve
            for cve in cves
            if cve.get("score") is not None
            and minimum <= float(cve["score"]) <= maximum
        ]

        count = len(matching)

        for cve in matching:
            cve_id = cve.get("id")

            if cve_id is not None:
                matched_cves.add(cve_id)

        state = _state_for_count(
            count,
            warn_count,
            crit_count,
        )

        states.append(state)

        result_parts.append(
            f"CVSS {minimum:g}-{maximum:g}: {count}"
        )

        #
        # Performance metric for this CVSS range
        #
        metric_levels = None

        if warn_count is not None and crit_count is not None:
            metric_levels = (
                float(warn_count),
                float(crit_count),
            )

        yield Metric(
            name=_metric_name(minimum, maximum),
            value=count,
            levels=metric_levels,
            boundaries=(0.0, None),
        )

    #
    # Numerical CVSS values outside configured ranges
    #
    unmatched = [
        cve
        for cve in cves
        if cve.get("score") is not None
        and cve.get("id") not in matched_cves
    ]

    if unmatched:
        states.append(State.UNKNOWN)

        result_parts.append(
            f"Unmatched CVSS: {len(unmatched)}"
        )

        yield Metric(
            name="trivy_unmatched_cvss",
            value=len(unmatched),
            boundaries=(0.0, None),
        )

    #
    # CVEs without numerical CVSS score
    #
    unknown_count = sum(
        1
        for cve in cves
        if cve.get("score") is None
    )

    unknown_warn = _threshold_value(
        params.get("unknown_warn")
    )

    unknown_crit = _threshold_value(
        params.get("unknown_crit")
    )

    unknown_state = _state_for_count(
        unknown_count,
        unknown_warn,
        unknown_crit,
    )

    states.append(unknown_state)

    result_parts.append(
        f"No CVSS: {unknown_count}"
    )

    unknown_levels = None

    if unknown_warn is not None and unknown_crit is not None:
        unknown_levels = (
            float(unknown_warn),
            float(unknown_crit),
        )

    yield Metric(
        name="trivy_no_cvss",
        value=unknown_count,
        levels=unknown_levels,
        boundaries=(0.0, None),
    )

    #
    # Trivy report age
    #
    generated = section.get("generated")
    age_hours = _report_age_hours(generated)

    age_warn = _threshold_value(
        params.get("age_warn")
    )

    age_crit = _threshold_value(
        params.get("age_crit")
    )

    if age_hours is None:
        states.append(State.UNKNOWN)
        result_parts.append("Report age: UNKNOWN")

    else:
        age_state = State.OK

        if (
            age_crit is not None
            and age_hours >= age_crit
        ):
            age_state = State.CRIT

        elif (
            age_warn is not None
            and age_hours >= age_warn
        ):
            age_state = State.WARN

        states.append(age_state)

        result_parts.append(
            f"Report age: {_format_age(age_hours)}"
        )

        age_levels = None

        if age_warn is not None and age_crit is not None:
            age_levels = (
                float(age_warn),
                float(age_crit),
            )

        yield Metric(
            name="trivy_report_age",
            value=age_hours,
            levels=age_levels,
            boundaries=(0.0, None),
        )
    #
    # Total CVEs metric
    #
    yield Metric(
        name="trivy_total_cves",
        value=len(cves),
    )

    #
    # Final service state and summary
    #
    yield Result(
        state=_worst_state(states),
        summary=", ".join(result_parts),
    )


check_plugin_trivy_report = CheckPlugin(
    name="trivy_report",
    service_name="Trivy Report",
    sections=["trivy_report"],
    discovery_function=discover_trivy_report,
    check_function=check_trivy_report,
    check_default_parameters=DEFAULT_PARAMETERS,
    check_ruleset_name="trivy_report",
)