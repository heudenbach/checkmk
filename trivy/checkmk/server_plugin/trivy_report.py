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
    "critical": {
        "warn_count": ("disabled", None),
        "crit_count": ("enabled", 1),
    },

    "high": {
        "warn_count": ("enabled", 1),
        "crit_count": ("disabled", None),
    },

    "medium": {
        "warn_count": ("disabled", None),
        "crit_count": ("disabled", None),
    },

    "low": {
        "warn_count": ("disabled", None),
        "crit_count": ("disabled", None),
    },

    "unknown": {
        "warn_count": ("enabled", 1),
        "crit_count": ("disabled", None),
    },

    "age_warn": ("enabled", 8),
    "age_crit": ("enabled", 14),
}


SEVERITIES = (
    "critical",
    "high",
    "medium",
    "low",
    "unknown",
)


def parse_trivy_report(string_table):
    if not string_table:
        return None

    try:
        raw = "\n".join(
            line[0]
            for line in string_table
        )

        return json.loads(raw)

    except (
        json.JSONDecodeError,
        IndexError,
        TypeError,
    ):
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


def _report_age_hours(generated):
    if not generated:
        return None

    try:
        timestamp = generated.replace(
            "Z",
            "+00:00",
        )

        generated_time = datetime.fromisoformat(
            timestamp
        )

        if generated_time.tzinfo is None:
            generated_time = generated_time.replace(
                tzinfo=timezone.utc
            )

        now = datetime.now(
            timezone.utc
        )

        age_seconds = (
            now
            - generated_time.astimezone(
                timezone.utc
            )
        ).total_seconds()

        if age_seconds < 0:
            return 0.0

        return age_seconds / 3600.0

    except (
        TypeError,
        ValueError,
    ):
        return None


def _format_age(hours):
    if hours < 1:
        return f"{int(hours * 60)} min"

    if hours < 24:
        return f"{hours:.1f} h"

    return f"{hours / 24.0:.1f} d"


def _severity_counts(cves):
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    for cve in cves:
        severity = str(
            cve.get("severity")
            or "UNKNOWN"
        ).lower()

        if severity not in counts:
            severity = "unknown"

        counts[severity] += 1

    return counts


def check_trivy_report(params, section):
    if section is None:
        yield Result(
            state=State.UNKNOWN,
            summary="No valid Trivy report data",
        )
        return

    cves = section.get(
        "cves",
        [],
    )

    counts = _severity_counts(
        cves
    )

    states = []
    result_parts = []

    #
    # Evaluate Trivy/Vendor severity categories.
    #
    for severity in SEVERITIES:
        count = counts[severity]

        severity_params = params.get(
            severity,
            {},
        )

        warn_count = _threshold_value(
            severity_params.get(
                "warn_count"
            )
        )

        crit_count = _threshold_value(
            severity_params.get(
                "crit_count"
            )
        )

        state = _state_for_count(
            count,
            warn_count,
            crit_count,
        )

        states.append(
            state
        )

        result_parts.append(
            f"{severity.upper()}: {count}"
        )

        #
        # Metric per severity.
        #
        yield Metric(
            name=f"trivy_{severity}",
            value=count,
        )

    #
    # Stable total CVE metric.
    #
    yield Metric(
        name="trivy_total_cves",
        value=len(cves),
    )

    #
    # Report age.
    #
    generated = section.get(
        "generated"
    )

    age_hours = _report_age_hours(
        generated
    )

    age_warn = _threshold_value(
        params.get("age_warn")
    )

    age_crit = _threshold_value(
        params.get("age_crit")
    )

    if age_hours is None:
        states.append(
            State.UNKNOWN
        )

        result_parts.append(
            "Report age: UNKNOWN"
        )

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

        states.append(
            age_state
        )

        result_parts.append(
            f"Report age: {_format_age(age_hours)}"
        )

        yield Metric(
            name="trivy_report_age",
            value=age_hours,
        )

    #
    # Final Checkmk result.
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