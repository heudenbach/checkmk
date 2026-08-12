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
    "p1": {
        "warn_count": ("disabled", None),
        "crit_count": ("enabled", 1),
    },
    "p2": {
        "warn_count": ("enabled", 1),
        "crit_count": ("disabled", None),
    },
    "p3": {
        "warn_count": ("disabled", None),
        "crit_count": ("disabled", None),
    },
    "p4": {
        "warn_count": ("disabled", None),
        "crit_count": ("disabled", None),
    },
    "kev": {
        "warn_count": ("disabled", None),
        "crit_count": ("enabled", 1),
    },
    "age_warn": ("enabled", 8),
    "age_crit": ("enabled", 14),
}

PRIORITIES = ("p1", "p2", "p3", "p4")
SEVERITIES = ("critical", "high", "medium", "low", "unknown")


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
    if choice != "enabled" or value is None:
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
        timestamp = generated.replace("Z", "+00:00")
        generated_time = datetime.fromisoformat(timestamp)
        if generated_time.tzinfo is None:
            generated_time = generated_time.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age_seconds = (
            now - generated_time.astimezone(timezone.utc)
        ).total_seconds()
        return max(0.0, age_seconds / 3600.0)
    except (TypeError, ValueError):
        return None


def _format_age(hours):
    if hours < 1:
        return f"{int(hours * 60)} min"
    if hours < 24:
        return f"{hours:.1f} h"
    return f"{hours / 24.0:.1f} d"


def _severity_counts(cves):
    counts = {severity: 0 for severity in SEVERITIES}

    for cve in cves:
        # The reducer currently exposes the vendor-aware value as
        # vendor_severity_name. Keep fallbacks for older report versions.
        severity = str(
            cve.get("vendor_severity_name")
            or cve.get("severity")
            or "UNKNOWN"
        ).lower()

        if severity not in counts:
            severity = "unknown"
        counts[severity] += 1

    return counts


def _priority_counts(section, cves):
    supplied = section.get("priority_counts") or {}
    counts = {}

    for priority in PRIORITIES:
        value = supplied.get(priority)
        if value is None:
            # Compatibility fallback: count per-CVE priority data.
            value = sum(
                1
                for cve in cves
                if str(
                    (cve.get("priority") or {}).get("level") or "P4"
                ).lower() == priority
            )
        try:
            counts[priority] = int(value)
        except (TypeError, ValueError):
            counts[priority] = 0

    return counts


def _operational_counts(section):
    operational = section.get("operational_counts") or {}
    result = {}
    for key in ("action_required", "review", "suppressed", "remediation_required", "fix_available"):
        try:
            result[key] = int(operational.get(key, 0))
        except (TypeError, ValueError):
            result[key] = 0
    return result


def _kev_count(section, cves):
    threat_intel = section.get("threat_intel") or {}
    kev_meta = threat_intel.get("cisa_kev") or {}

    value = kev_meta.get("matched_cves")
    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            pass

    return sum(
        1
        for cve in cves
        if bool(
            (
                (cve.get("threat_intel") or {})
                .get("cisa_kev", {})
                .get("known_exploited")
            )
        )
    )


def _epss_scored_count(section, cves):
    threat_intel = section.get("threat_intel") or {}
    epss_meta = threat_intel.get("epss") or {}

    value = epss_meta.get("scored_cves")
    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            pass

    return sum(
        1
        for cve in cves
        if (
            (cve.get("threat_intel") or {})
            .get("epss", {})
            .get("score")
        ) is not None
    )


def check_trivy_report(params, section):
    if section is None:
        yield Result(
            state=State.UNKNOWN,
            summary="No valid Trivy report data",
        )
        return

    cves = section.get("cves", [])
    priority_counts = _priority_counts(section, cves)
    severity_counts = _severity_counts(cves)
    operational_counts = _operational_counts(section)
    kev_count = _kev_count(section, cves)
    epss_scored = _epss_scored_count(section, cves)

    states = []
    result_parts = []

    # Primary monitoring logic: operational P1-P4 priority.
    for priority in PRIORITIES:
        count = priority_counts[priority]
        priority_params = params.get(priority, {})

        state = _state_for_count(
            count,
            _threshold_value(priority_params.get("warn_count")),
            _threshold_value(priority_params.get("crit_count")),
        )
        states.append(state)
        result_parts.append(f"{priority.upper()}: {count}")

        yield Metric(
            name=f"trivy_priority_{priority}",
            value=count,
        )

    # CISA KEV is an explicit exploitation signal and can independently alarm.
    kev_params = params.get("kev", {})
    kev_state = _state_for_count(
        kev_count,
        _threshold_value(kev_params.get("warn_count")),
        _threshold_value(kev_params.get("crit_count")),
    )
    states.append(kev_state)
    result_parts.append(f"KEV: {kev_count}")

    yield Metric(name="trivy_kev", value=kev_count)
    yield Metric(name="trivy_epss_scored", value=epss_scored)

    # Operational metrics from the reducer.
    for key, value in operational_counts.items():
        yield Metric(
            name=f"trivy_{key}",
            value=value,
        )

    # Vendor/Trivy severity remains visible as metrics, but no longer
    # determines the service state by itself.
    for severity in SEVERITIES:
        yield Metric(
            name=f"trivy_{severity}",
            value=severity_counts[severity],
        )

    yield Metric(
        name="trivy_total_cves",
        value=len(cves),
    )

    generated = section.get("generated")
    age_hours = _report_age_hours(generated)

    age_warn = _threshold_value(params.get("age_warn"))
    age_crit = _threshold_value(params.get("age_crit"))

    if age_hours is None:
        states.append(State.UNKNOWN)
        result_parts.append("Report age: UNKNOWN")
    else:
        age_state = State.OK
        if age_crit is not None and age_hours >= age_crit:
            age_state = State.CRIT
        elif age_warn is not None and age_hours >= age_warn:
            age_state = State.WARN

        states.append(age_state)
        result_parts.append(f"Report age: {_format_age(age_hours)}")

        yield Metric(
            name="trivy_report_age",
            value=age_hours,
        )

    yield Result(
        state=_worst_state(states),
        summary=", ".join(result_parts),
        details=(
            "Operational counts: "
            f"ACTION_REQUIRED={operational_counts['action_required']}, "
            f"REVIEW={operational_counts['review']}, "
            f"SUPPRESSED={operational_counts['suppressed']}, "
            f"FIX_AVAILABLE={operational_counts['fix_available']}; "
            "Vendor severity: "
            f"CRITICAL={severity_counts['critical']}, "
            f"HIGH={severity_counts['high']}, "
            f"MEDIUM={severity_counts['medium']}, "
            f"LOW={severity_counts['low']}, "
            f"UNKNOWN={severity_counts['unknown']}; "
            f"EPSS scored={epss_scored}"
        ),
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