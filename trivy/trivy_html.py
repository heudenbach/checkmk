#!/usr/bin/env python3

import argparse
import html
import json
import sys
from datetime import datetime
from pathlib import Path


VENDOR_SEVERITY_NAMES = {
    0: "UNKNOWN",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}

SEVERITY_ORDER = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

CLASSIFICATION_ORDER = {
    "SUPPRESSED": 0,
    "REVIEW": 1,
    "ACTION_REQUIRED": 2,
}


def e(value, fallback=""):
    if value is None or value == "":
        return html.escape(fallback)
    return html.escape(str(value))


def severity_class(severity):
    severity = str(severity or "UNKNOWN").upper()

    return {
        "UNKNOWN": "unknown",
        "LOW": "low",
        "MEDIUM": "medium",
        "HIGH": "high",
        "CRITICAL": "critical",
    }.get(severity, "unknown")


def classification_class(classification):
    classification = str(
        classification or "REVIEW"
    ).upper()

    return {
        "ACTION_REQUIRED": "action-required",
        "REVIEW": "review",
        "SUPPRESSED": "suppressed",
    }.get(classification, "review")


def classification_text(classification):
    classification = str(
        classification or "REVIEW"
    ).upper()

    return {
        "ACTION_REQUIRED": "ACTION REQUIRED",
        "REVIEW": "REVIEW",
        "SUPPRESSED": "SUPPRESSED",
    }.get(
        classification,
        classification.replace("_", " "),
    )


def score_text(score):
    if score is None:
        return "No CVSS"

    try:
        return f"{float(score):.1f}"
    except (TypeError, ValueError):
        return str(score)


def vendor_severity_text(value):
    if value is None:
        return "Not provided"

    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value)

    name = VENDOR_SEVERITY_NAMES.get(
        number,
        "UNKNOWN",
    )

    return f"{name} ({number})"


def bool_text(value):
    return "Yes" if value else "No"


def link_button(url, text):
    if not url:
        return ""

    safe_url = html.escape(
        str(url),
        quote=True,
    )

    safe_text = html.escape(text)

    return (
        f'<a class="external-link" '
        f'href="{safe_url}" '
        f'target="_blank" '
        f'rel="noopener noreferrer">'
        f'{safe_text} ↗'
        f'</a>'
    )


def render_badges(items, css_class="neutral"):
    items = [
        str(item)
        for item in items
        if item not in (None, "")
    ]

    if not items:
        return '<span class="muted">None</span>'

    return "".join(
        f'<span class="mini-badge {css_class}">'
        f'{e(item)}'
        f'</span>'
        for item in items
    )


def render_findings(findings):
    if not findings:
        return """
        <div class="finding">
            No package or location information was provided by Trivy.
        </div>
        """

    blocks = []

    for finding in findings:

        package = e(
            finding.get("package"),
            "Not provided",
        )

        installed = e(
            finding.get("installed_version"),
            "Not provided",
        )

        fixed_value = finding.get(
            "fixed_version"
        )

        path_value = finding.get(
            "path"
        )

        if fixed_value:
            fixed = e(fixed_value)
            fixed_class = ""
        else:
            fixed = "No fixed version provided"
            fixed_class = "muted"

        if path_value:
            path = (
                f"<code>"
                f"{e(path_value)}"
                f"</code>"
            )

            path_class = ""
        else:
            path = (
                "OS/package finding – "
                "no file path provided"
            )

            path_class = "muted"

        extra_rows = []

        if finding.get("kernel_package"):

            extra_rows.extend(
                [
                    (
                        '<div class="property-name">'
                        'Kernel package'
                        '</div>'
                        '<div>Yes</div>'
                    ),
                    (
                        '<div class="property-name">'
                        'Kernel runtime package'
                        '</div>'
                        f'<div>'
                        f'{e(bool_text(finding.get("kernel_runtime_package")))}'
                        f'</div>'
                    ),
                    (
                        '<div class="property-name">'
                        'Kernel support package'
                        '</div>'
                        f'<div>'
                        f'{e(bool_text(finding.get("kernel_support_package")))}'
                        f'</div>'
                    ),
                    (
                        '<div class="property-name">'
                        'Kernel ABI'
                        '</div>'
                        f'<div>'
                        f'{e(finding.get("kernel_abi"), "Unknown")}'
                        f'</div>'
                    ),
                    (
                        '<div class="property-name">'
                        'Old kernel ABI'
                        '</div>'
                        f'<div>'
                        f'{e(bool_text(finding.get("old_kernel")))}'
                        f'</div>'
                    ),
                ]
            )

        blocks.append(
            f"""
            <div class="finding">

                <div class="finding-package">
                    {package}
                </div>

                <div class="property-grid">

                    <div class="property-name">
                        Installed
                    </div>

                    <div>
                        {installed}
                    </div>

                    <div class="property-name">
                        Fixed
                    </div>

                    <div class="{fixed_class}">
                        {fixed}
                    </div>

                    <div class="property-name">
                        Location
                    </div>

                    <div class="{path_class}">
                        {path}
                    </div>

                    {''.join(extra_rows)}

                </div>

            </div>
            """
        )

    return "\n".join(blocks)


def render_runtime_section(cve):
    category = str(
        cve.get("category") or ""
    ).lower()

    if category == "kernel":

        kernel = cve.get("kernel") or {}
        runtime = kernel.get("runtime") or {}

        component = kernel.get(
            "component"
        )

        runtime_state = runtime.get(
            "state"
        )

        runtime_reason = runtime.get(
            "reason"
        )

        return f"""
        <section class="info-section">

            <h3>Kernel relevance</h3>

            <div class="property-grid">

                <div class="property-name">
                    Component
                </div>

                <div>
                    {e(component, "Not determined")}
                </div>

                <div class="property-name">
                    Runtime state
                </div>

                <div>
                    {e(runtime_state, "Unknown")}
                </div>

                <div class="property-name">
                    Architecture in title
                </div>

                <div>
                    {e(
                        kernel.get("title_architecture"),
                        "Not specific"
                    )}
                </div>

                <div class="property-name">
                    Host architecture
                </div>

                <div>
                    {e(
                        kernel.get("host_architecture"),
                        "Unknown"
                    )}
                </div>

                <div class="property-name">
                    Current-kernel findings
                </div>

                <div>
                    {e(
                        kernel.get(
                            "current_kernel_runtime_findings"
                        ),
                        "0"
                    )}
                </div>

                <div class="property-name">
                    Old-kernel findings
                </div>

                <div>
                    {e(
                        kernel.get(
                            "old_kernel_findings"
                        ),
                        "0"
                    )}
                </div>

                <div class="property-name">
                    Supporting-package findings
                </div>

                <div>
                    {e(
                        kernel.get(
                            "supporting_package_findings"
                        ),
                        "0"
                    )}
                </div>

                <div class="property-name">
                    Runtime evidence
                </div>

                <div>
                    {e(
                        runtime_reason,
                        "No additional runtime evidence"
                    )}
                </div>

            </div>

        </section>
        """

    runtime_packages = (
        cve.get("runtime_used_packages")
        or []
    )

    return f"""
    <section class="info-section">

        <h3>Package runtime relevance</h3>

        <div class="property-grid">

            <div class="property-name">
                Runtime-used packages
            </div>

            <div>
                {
                    render_badges(
                        runtime_packages,
                        "runtime"
                    )
                }
            </div>

        </div>

        <div class="section-note">
            Runtime evidence is based on packages used by
            processes that have been running for at least
            60 seconds when the reducer executes.
        </div>

    </section>
    """


def create_html(data):

    generated = e(
        data.get("generated"),
        "Unknown",
    )

    host = (
        data.get("host")
        or {}
    )

    operational_counts = (
        data.get("operational_counts")
        or {}
    )

    os_name = e(
        host.get("os_name"),
        "Unknown Linux",
    )

    os_version = e(
        host.get("os_version"),
        "",
    )

    running_kernel = e(
        host.get("running_kernel"),
        "Unknown",
    )

    architecture = e(
        host.get("architecture"),
        "Unknown",
    )

    vendor_key = e(
        host.get("vendor_key"),
        "Unknown",
    )

    runtime_packages_count = (
        host.get("runtime_packages_count")
    )

    loaded_modules_count = (
        host.get(
            "loaded_kernel_modules_count"
        )
    )

    available_modules_count = (
        host.get(
            "available_kernel_modules_count"
        )
    )

    cves = list(
        data.get("cves")
        or []
    )

    #
    # --------------------------------------------------------
    # Sort:
    #
    # ACTION_REQUIRED
    # REVIEW
    # SUPPRESSED
    #
    # then Vendor/Trivy severity
    # then CVSS
    # --------------------------------------------------------
    #

    def sort_key(cve):

        classification = str(
            cve.get("classification")
            or "REVIEW"
        ).upper()

        severity = str(
            cve.get("vendor_severity_name")
            or
            cve.get("severity")
            or
            "UNKNOWN"
        ).upper()

        try:
            score = float(
                cve.get("score")
            )
        except (
            TypeError,
            ValueError,
        ):
            score = -1.0

        return (
            CLASSIFICATION_ORDER.get(
                classification,
                1,
            ),
            SEVERITY_ORDER.get(
                severity,
                0,
            ),
            score,
            str(
                cve.get("id")
                or ""
            ),
        )

    cves = sorted(
        cves,
        key=sort_key,
        reverse=True,
    )

    #
    # --------------------------------------------------------
    # Classification counts
    # --------------------------------------------------------
    #

    classification_counts = {

        "ACTION_REQUIRED": sum(
            1
            for cve in cves
            if str(
                cve.get("classification")
                or ""
            ).upper()
            == "ACTION_REQUIRED"
        ),

        "REVIEW": sum(
            1
            for cve in cves
            if str(
                cve.get("classification")
                or ""
            ).upper()
            == "REVIEW"
        ),

        "SUPPRESSED": sum(
            1
            for cve in cves
            if str(
                cve.get("classification")
                or ""
            ).upper()
            == "SUPPRESSED"
        ),
    }

    #
    # --------------------------------------------------------
    # Severity counts
    # --------------------------------------------------------
    #

    severity_counts = {

        severity: sum(

            1

            for cve in cves

            if str(
                cve.get(
                    "vendor_severity_name"
                )
                or
                cve.get("severity")
                or
                "UNKNOWN"
            ).upper()

            == severity

        )

        for severity in (
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNKNOWN",
        )
    }

    kernel_counts = (
        operational_counts.get("kernel")
        or {}
    )

    package_counts = (
        operational_counts.get("packages")
        or {}
    )

    rows = []

    #
    # --------------------------------------------------------
    # CVE cards
    # --------------------------------------------------------
    #

    for index, cve in enumerate(cves):

        cve_id = e(
            cve.get("id"),
            "UNKNOWN",
        )

        score = cve.get("score")

        score_display = score_text(
            score
        )

        raw_severity = str(
            cve.get("severity")
            or "UNKNOWN"
        ).upper()

        preferred_severity = str(
            cve.get(
                "vendor_severity_name"
            )
            or
            raw_severity
            or
            "UNKNOWN"
        ).upper()

        severity_css = severity_class(
            preferred_severity
        )

        classification = str(
            cve.get("classification")
            or "REVIEW"
        ).upper()

        classification_css = (
            classification_class(
                classification
            )
        )

        classification_display = (
            classification_text(
                classification
            )
        )

        category = str(
            cve.get("category")
            or "unknown"
        ).lower()

        title = e(
            cve.get("title"),
            "No title provided",
        )

        status = e(
            cve.get("status"),
            "Unknown",
        )

        relevance = e(
            cve.get("relevance"),
            "Unknown",
        )

        reason = e(
            cve.get("reason"),
            "No assessment reason provided",
        )

        severity_source = e(
            cve.get("severity_source"),
            "Unknown",
        )

        vendor_severity = (
            vendor_severity_text(
                cve.get(
                    "vendor_severity"
                )
            )
        )

        primary_url = (
            cve.get("primary_url")
        )

        data_source = (
            cve.get("data_source")
            or {}
        )

        data_source_name = e(
            data_source.get("name"),
            "Not provided",
        )

        data_source_id = e(
            data_source.get("id"),
            "",
        )

        data_source_url = (
            data_source.get("url")
        )

        findings = (
            cve.get("findings")
            or []
        )

        runtime_used_packages = (
            cve.get(
                "runtime_used_packages"
            )
            or []
        )

        remediation = (
            cve.get("remediation")
            or {}
        )

        remediation_required = bool(
            remediation.get("required")
        )

        fix_available = bool(
            remediation.get(
                "fix_available"
            )
        )

        fixed_versions = (
            remediation.get(
                "fixed_versions"
            )
            or []
        )

        #
        # Search text
        #

        searchable_parts = [
            str(cve.get("id", "")),
            str(cve.get("title", "")),
            str(score_display),
            str(raw_severity),
            str(preferred_severity),
            str(classification),
            str(category),
            str(cve.get("relevance", "")),
            str(cve.get("reason", "")),
            str(cve.get("status", "")),
            str(
                cve.get(
                    "severity_source",
                    "",
                )
            ),
            str(
                data_source.get(
                    "name",
                    "",
                )
            ),
            " ".join(
                str(item)
                for item
                in runtime_used_packages
            ),
        ]

        kernel = (
            cve.get("kernel")
            or {}
        )

        runtime = (
            kernel.get("runtime")
            or {}
        )

        searchable_parts.extend(
            [
                str(
                    kernel.get(
                        "component",
                        "",
                    )
                ),
                str(
                    runtime.get(
                        "state",
                        "",
                    )
                ),
                str(
                    runtime.get(
                        "reason",
                        "",
                    )
                ),
            ]
        )

        for finding in findings:

            searchable_parts.extend(
                [
                    str(
                        finding.get(
                            "package",
                            "",
                        )
                    ),
                    str(
                        finding.get(
                            "installed_version",
                            "",
                        )
                    ),
                    str(
                        finding.get(
                            "fixed_version",
                            "",
                        )
                    ),
                    str(
                        finding.get(
                            "path",
                            "",
                        )
                    ),
                ]
            )

        searchable = " ".join(
            searchable_parts
        ).lower()

        #
        # Links
        #

        source_links = []

        if primary_url:

            source_links.append(
                link_button(
                    primary_url,
                    "Primary vulnerability information",
                )
            )

        if data_source_url:

            source_links.append(
                link_button(
                    data_source_url,
                    (
                        "Data source: "
                        + html.unescape(
                            data_source_name
                        )
                    ),
                )
            )

        if source_links:
            source_html = "".join(
                source_links
            )
        else:
            source_html = """
            <span class="muted">
                No source links provided by Trivy
            </span>
            """

        #
        # Remediation section
        #

        remediation_html = f"""
        <section class="info-section">

            <h3>Remediation</h3>

            <div class="property-grid">

                <div class="property-name">
                    Remediation required
                </div>

                <div>
                    {
                        e(
                            bool_text(
                                remediation_required
                            )
                        )
                    }
                </div>

                <div class="property-name">
                    Fix available
                </div>

                <div>
                    {
                        e(
                            bool_text(
                                fix_available
                            )
                        )
                    }
                </div>

                <div class="property-name">
                    Fixed versions
                </div>

                <div>
                    {
                        render_badges(
                            fixed_versions,
                            "fix"
                        )
                    }
                </div>

            </div>

        </section>
        """

        #
        # Full CVE card
        #

        rows.append(
            f"""
            <article
                class="
                    cve-card
                    {classification_css}
                    sev-{severity_css}
                "
                data-classification="{classification_css}"
                data-severity="{severity_css}"
                data-category="{e(category)}"
                data-search="{html.escape(searchable, quote=True)}"
            >

                <div
                    class="cve-header"
                    onclick="toggleDetails('details-{index}')"
                >

                    <div class="cve-main">

                        <div class="cve-topline">

                            <div class="cve-title">
                                {cve_id}
                            </div>

                            <span
                                class="
                                    classification-badge
                                    {classification_css}
                                "
                            >
                                {e(classification_display)}
                            </span>

                            <span class="category-badge">
                                {e(category.upper())}
                            </span>

                        </div>

                        <div class="cve-short-title">
                            {title}
                        </div>

                        <div class="assessment-line">

                            <strong>
                                {relevance}
                            </strong>

                            <span class="assessment-separator">
                                —
                            </span>

                            {reason}

                        </div>

                    </div>

                    <div
                        class="
                            score
                            score-{severity_css}
                        "
                    >

                        <div class="severity-name">
                            {e(preferred_severity)}
                        </div>

                        <div class="cvss-small">
                            CVSS {e(score_display)}
                        </div>

                    </div>

                </div>

                <div
                    id="details-{index}"
                    class="details"
                >

                    <section class="info-section">

                        <h3>
                            Operational assessment
                        </h3>

                        <div class="property-grid">

                            <div class="property-name">
                                Classification
                            </div>

                            <div>
                                <span
                                    class="
                                        classification-badge
                                        {classification_css}
                                    "
                                >
                                    {e(classification_display)}
                                </span>
                            </div>

                            <div class="property-name">
                                Category
                            </div>

                            <div>
                                {e(category)}
                            </div>

                            <div class="property-name">
                                Relevance
                            </div>

                            <div>
                                {relevance}
                            </div>

                            <div class="property-name">
                                Reason
                            </div>

                            <div>
                                {reason}
                            </div>

                        </div>

                    </section>

                    <section class="info-section">

                        <h3>
                            Vulnerability
                        </h3>

                        <div class="property-grid">

                            <div class="property-name">
                                Status
                            </div>

                            <div>
                                {status}
                            </div>

                            <div class="property-name">
                                Preferred vendor severity
                            </div>

                            <div>
                                <span
                                    class="
                                        severity-inline
                                        sev-{severity_css}
                                    "
                                >
                                    {e(preferred_severity)}
                                </span>
                            </div>

                            <div class="property-name">
                                Trivy severity
                            </div>

                            <div>
                                {e(raw_severity)}
                            </div>

                            <div class="property-name">
                                Vendor severity code
                            </div>

                            <div>
                                {e(vendor_severity)}
                            </div>

                            <div class="property-name">
                                Severity source
                            </div>

                            <div>
                                {severity_source}
                            </div>

                            <div class="property-name">
                                CVSS reference
                            </div>

                            <div>
                                {e(score_display)}
                            </div>

                        </div>

                    </section>

                    {
                        render_runtime_section(
                            cve
                        )
                    }

                    {remediation_html}

                    <section class="info-section">

                        <h3>
                            Packages / locations
                        </h3>

                        {
                            render_findings(
                                findings
                            )
                        }

                    </section>

                    <section class="info-section">

                        <h3>
                            Sources
                        </h3>

                        <div class="property-grid">

                            <div class="property-name">
                                Data source
                            </div>

                            <div>

                                {data_source_name}

                                {
                                    f" ({data_source_id})"
                                    if data_source_id
                                    else ""
                                }

                            </div>

                        </div>

                        <div class="source-links">
                            {source_html}
                        </div>

                    </section>

                </div>

            </article>
            """
        )

    generated_local = (
        datetime.now()
        .astimezone()
        .strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        )
    )

    total_count = len(cves)

    action_count = (
        classification_counts[
            "ACTION_REQUIRED"
        ]
    )

    review_count = (
        classification_counts[
            "REVIEW"
        ]
    )

    suppressed_count = (
        classification_counts[
            "SUPPRESSED"
        ]
    )

    return f"""<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1"
>

<title>
    Trivy Vulnerability Report
</title>

<style>

:root {{
    color-scheme: dark;
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    background: #11151b;
    color: #e8edf2;

    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}}

.container {{
    max-width: 1600px;
    margin: auto;
    padding: 28px;
}}

h1 {{
    margin-bottom: 4px;
}}

h2,
h3 {{
    margin-top: 0;
}}

.subtitle {{
    color: #9ca8b5;
    margin-bottom: 24px;
    line-height: 1.55;
}}

.summary {{
    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(155px, 1fr)
        );

    gap: 14px;
    margin-bottom: 24px;
}}

.summary-card {{
    background: #1b222c;
    border: 1px solid #303945;
    border-radius: 10px;
    padding: 16px;
}}

.summary-card.action {{
    border-color: #8a3131;
}}

.summary-card.review {{
    border-color: #806b29;
}}

.summary-card.suppressed {{
    border-color: #3d6551;
}}

.summary-card.clickable {{
    cursor: pointer;
    transition:
        transform 0.12s ease,
        background 0.12s ease,
        border-color 0.12s ease;
}}

.summary-card.clickable:hover {{
    transform: translateY(-2px);
    background: #222b35;
    border-color: #596879;
}}

.summary-value {{
    font-size: 28px;
    font-weight: 700;
}}

.summary-label {{
    color: #a9b3bd;
    margin-top: 4px;
}}

.summary-sub {{
    color: #77828e;
    font-size: 12px;
    margin-top: 6px;
}}

.controls {{
    position: sticky;
    top: 0;
    z-index: 50;

    background: #11151bea;
    backdrop-filter: blur(10px);

    padding: 14px 0;
    margin-bottom: 16px;
}}

.search {{
    width: 100%;
    padding: 13px 15px;
    font-size: 16px;

    border:
        1px solid #37414d;

    border-radius: 8px;
    background: #171d25;
    color: #fff;

    margin-bottom: 12px;
}}

.filter-section {{
    margin-top: 8px;
}}

.filter-label {{
    display: inline-block;
    color: #8895a2;
    min-width: 105px;
    font-size: 13px;
    font-weight: 700;
}}

.filters {{
    display: inline-flex;
    flex-wrap: wrap;
    gap: 8px;
}}

button {{
    border:
        1px solid #3c4652;

    background: #1c232c;
    color: #e8edf2;

    padding: 8px 13px;
    border-radius: 7px;

    cursor: pointer;
}}

button:hover {{
    background: #28313d;
}}

button.active {{
    background: #394758;
    border-color: #657486;
}}

.result-count {{
    margin: 14px 0;
    color: #aeb8c2;
}}

.cve-card {{
    border:
        1px solid #303945;

    border-left-width: 6px;
    border-radius: 9px;

    background: #191f27;

    margin-bottom: 9px;
    overflow: hidden;
}}

.cve-card.action-required {{
    border-left-color: #e24c4b;
}}

.cve-card.review {{
    border-left-color: #d9b94f;
}}

.cve-card.suppressed {{
    border-left-color: #58966f;
    opacity: 0.80;
}}

.cve-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;

    gap: 20px;
    padding: 14px 16px;

    cursor: pointer;
}}

.cve-main {{
    min-width: 0;
}}

.cve-topline {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
}}

.cve-title {{
    font-size: 17px;
    font-weight: 700;
}}

.cve-short-title {{
    color: #aeb8c2;
    margin-top: 5px;
}}

.assessment-line {{
    color: #8f9aa5;

    margin-top: 7px;

    font-size: 13px;
    line-height: 1.4;
}}

.assessment-separator {{
    margin: 0 5px;
}}

.classification-badge {{
    display: inline-block;

    padding: 4px 8px;

    border-radius: 999px;

    font-size: 11px;
    font-weight: 800;
    letter-spacing: 0.25px;
}}

.classification-badge.action-required {{
    background: #5a2020;
    color: #ffd7d7;
    border: 1px solid #8f3a39;
}}

.classification-badge.review {{
    background: #574a1e;
    color: #fff0b5;
    border: 1px solid #82702c;
}}

.classification-badge.suppressed {{
    background: #234535;
    color: #d6f5e3;
    border: 1px solid #3f7358;
}}

.category-badge {{
    display: inline-block;

    padding: 4px 8px;

    border-radius: 999px;

    background: #26303b;
    border: 1px solid #3d4957;

    color: #b8c4d0;

    font-size: 11px;
    font-weight: 700;
}}

.score {{
    min-width: 105px;
    flex-shrink: 0;

    text-align: center;

    padding: 7px 10px;
    border-radius: 7px;

    font-weight: 700;
}}

.score-critical,
.severity-inline.sev-critical {{
    background: #5a2020;
}}

.score-high,
.severity-inline.sev-high {{
    background: #604516;
}}

.score-medium,
.severity-inline.sev-medium {{
    background: #5c5420;
}}

.score-low,
.severity-inline.sev-low {{
    background: #204d2e;
}}

.score-unknown,
.severity-inline.sev-unknown {{
    background: #37404a;
}}

.severity-inline {{
    display: inline-block;
    padding: 4px 8px;
    border-radius: 5px;
    font-weight: 700;
}}

.severity-name {{
    font-size: 13px;
    letter-spacing: 0.3px;
}}

.cvss-small {{
    font-size: 11px;
    font-weight: 500;
    opacity: 0.8;
    margin-top: 2px;
}}

.details {{
    display: none;
    padding: 0 16px 18px;
}}

.info-section {{
    margin-top: 14px;

    background: #141a21;

    border:
        1px solid #29313b;

    border-radius: 8px;

    padding: 16px;
}}

.property-grid {{
    display: grid;

    grid-template-columns:
        220px 1fr;

    gap: 8px 14px;

    align-items: start;
}}

.property-name {{
    color: #9ca8b5;
    font-weight: 600;
}}

.section-note {{
    color: #77828e;

    font-size: 12px;

    margin-top: 12px;

    line-height: 1.45;
}}

.finding {{
    background: #10151b;

    border:
        1px solid #29313b;

    border-radius: 7px;

    padding: 14px;

    margin-top: 10px;
}}

.finding-package {{
    font-size: 16px;
    font-weight: 700;
    margin-bottom: 11px;
}}

.mini-badge {{
    display: inline-block;

    margin:
        2px 5px 2px 0;

    padding: 3px 7px;

    border-radius: 5px;

    border:
        1px solid #3d4957;

    background: #222b35;

    font-size: 12px;
}}

.mini-badge.runtime {{
    background: #243f33;
    border-color: #3d6a52;
}}

.mini-badge.fix {{
    background: #26384a;
    border-color: #405c78;
}}

.source-links {{
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 15px;
}}

.external-link {{
    display: inline-block;

    padding: 8px 11px;

    border-radius: 6px;

    border:
        1px solid #425166;

    background: #202a36;

    color: #dce9f7;

    text-decoration: none;
}}

.external-link:hover {{
    background: #2a3746;
}}

code {{
    color: #d8e2ec;
    overflow-wrap: anywhere;
}}

.muted {{
    color: #8f9aa5;
}}

.footer {{
    margin-top: 30px;

    color: #77828e;

    font-size: 13px;

    line-height: 1.5;
}}

@media (max-width: 800px) {{

    .property-grid {{
        grid-template-columns: 1fr;
    }}

    .property-name {{
        margin-top: 6px;
    }}

    .cve-header {{
        align-items: flex-start;
    }}

    .score {{
        min-width: 88px;
    }}

    .filter-label {{
        display: block;
        margin: 8px 0;
    }}
}}

</style>

</head>

<body>

<div class="container">

<h1>
    Trivy Vulnerability Report
</h1>

<div class="subtitle">

    <strong>System:</strong>
    {os_name} {os_version}

    <br>

    <strong>Architecture:</strong>
    {architecture}

    &nbsp; | &nbsp;

    <strong>Running kernel:</strong>
    {running_kernel}

    <br>

    <strong>Vendor key:</strong>
    {vendor_key}

    &nbsp; | &nbsp;

    <strong>Runtime packages:</strong>
    {
        e(
            runtime_packages_count,
            "Unknown"
        )
    }

    &nbsp; | &nbsp;

    <strong>Loaded kernel modules:</strong>
    {
        e(
            loaded_modules_count,
            "Unknown"
        )
    }

    &nbsp; | &nbsp;

    <strong>Available kernel modules:</strong>
    {
        e(
            available_modules_count,
            "Unknown"
        )
    }

    <br>

    <strong>Trivy report generated:</strong>
    {generated}

    <br>

    <strong>HTML generated:</strong>
    {generated_local}

</div>


<section class="summary">

    <div class="summary-card clickable" onclick="resetAllFilters()">

        <div class="summary-value">
            {total_count}
        </div>

        <div class="summary-label">
            Total CVEs
        </div>

    </div>


    <div class="summary-card action clickable" onclick="filterByClassification('action-required')">

        <div class="summary-value">
            {action_count}
        </div>

        <div class="summary-label">
            Action required
        </div>

        <div class="summary-sub">

            Kernel
            {
                e(
                    kernel_counts.get(
                        "action_required"
                    ),
                    "0"
                )
            }

            /

            Packages
            {
                e(
                    package_counts.get(
                        "action_required"
                    ),
                    "0"
                )
            }

        </div>

    </div>


    <div class="summary-card review clickable" onclick="filterByClassification('review')">

        <div class="summary-value">
            {review_count}
        </div>

        <div class="summary-label">
            Review
        </div>

        <div class="summary-sub">

            Kernel
            {
                e(
                    kernel_counts.get(
                        "review"
                    ),
                    "0"
                )
            }

            /

            Packages
            {
                e(
                    package_counts.get(
                        "review"
                    ),
                    "0"
                )
            }

        </div>

    </div>


    <div class="summary-card suppressed clickable" onclick="filterByClassification('suppressed')">

        <div class="summary-value">
            {suppressed_count}
        </div>

        <div class="summary-label">
            Suppressed
        </div>

        <div class="summary-sub">

            Kernel
            {
                e(
                    kernel_counts.get(
                        "suppressed"
                    ),
                    "0"
                )
            }

            /

            Packages
            {
                e(
                    package_counts.get(
                        "suppressed"
                    ),
                    "0"
                )
            }

        </div>

    </div>


    <div class="summary-card clickable" onclick="filterBySeverity('critical')">

        <div class="summary-value">
            {severity_counts["CRITICAL"]}
        </div>

        <div class="summary-label">
            Critical
        </div>

    </div>


    <div class="summary-card clickable" onclick="filterBySeverity('high')">

        <div class="summary-value">
            {severity_counts["HIGH"]}
        </div>

        <div class="summary-label">
            High
        </div>

    </div>


    <div class="summary-card clickable" onclick="filterBySeverity('medium')">

        <div class="summary-value">
            {severity_counts["MEDIUM"]}
        </div>

        <div class="summary-label">
            Medium
        </div>

    </div>


    <div class="summary-card clickable" onclick="filterBySeverity('low')">

        <div class="summary-value">
            {severity_counts["LOW"]}
        </div>

        <div class="summary-label">
            Low
        </div>

    </div>

</section>


<div class="controls">

    <input
        id="search"
        class="search"
        type="search"
        placeholder="
            Search CVE, title, classification,
            relevance, package, component,
            version or source...
        "
        oninput="applyFilters()"
    >


    <div class="filter-section">

        <span class="filter-label">
            Classification
        </span>

        <div class="filters">

            <button
                class="class-filter active"
                data-filter="all"
                onclick="setClassFilter(this)"
            >
                All
            </button>

            <button
                class="class-filter"
                data-filter="action-required"
                onclick="setClassFilter(this)"
            >
                Action required
            </button>

            <button
                class="class-filter"
                data-filter="review"
                onclick="setClassFilter(this)"
            >
                Review
            </button>

            <button
                class="class-filter"
                data-filter="suppressed"
                onclick="setClassFilter(this)"
            >
                Suppressed
            </button>

        </div>

    </div>


    <div class="filter-section">

        <span class="filter-label">
            Severity
        </span>

        <div class="filters">

            <button
                class="severity-filter active"
                data-filter="all"
                onclick="setSeverityFilter(this)"
            >
                All
            </button>

            <button
                class="severity-filter"
                data-filter="critical"
                onclick="setSeverityFilter(this)"
            >
                Critical
            </button>

            <button
                class="severity-filter"
                data-filter="high"
                onclick="setSeverityFilter(this)"
            >
                High
            </button>

            <button
                class="severity-filter"
                data-filter="medium"
                onclick="setSeverityFilter(this)"
            >
                Medium
            </button>

            <button
                class="severity-filter"
                data-filter="low"
                onclick="setSeverityFilter(this)"
            >
                Low
            </button>

            <button
                class="severity-filter"
                data-filter="unknown"
                onclick="setSeverityFilter(this)"
            >
                Unknown
            </button>

        </div>

    </div>


    <div class="filter-section">

        <span class="filter-label">
            Category
        </span>

        <div class="filters">

            <button
                class="category-filter active"
                data-filter="all"
                onclick="setCategoryFilter(this)"
            >
                All
            </button>

            <button
                class="category-filter"
                data-filter="kernel"
                onclick="setCategoryFilter(this)"
            >
                Kernel
            </button>

            <button
                class="category-filter"
                data-filter="package"
                onclick="setCategoryFilter(this)"
            >
                Packages
            </button>

            <button onclick="expandAll()">
                Expand all
            </button>

            <button onclick="collapseAll()">
                Collapse all
            </button>

        </div>

    </div>

</div>


<div
    id="result-count"
    class="result-count"
>
</div>


<section id="cve-list">

{"".join(rows)}

</section>


<div class="footer">

    Operational classification is based on
    reducer runtime relevance.

    Vendor/Trivy severity remains the
    vulnerability severity indicator.

    CVSS is shown as reference information only.

    SUPPRESSED means the reducer found technical
    evidence that the finding is not applicable
    or inactive on the current host.

    The original Trivy scan is not modified.

</div>

</div>


<script>

let activeClassFilter = "all";
let activeSeverityFilter = "all";
let activeCategoryFilter = "all";


function activateFilterButton(selector, value) {{

    document
        .querySelectorAll(selector)
        .forEach(button => {{

            button.classList.remove("active");

            if (button.dataset.filter === value) {{
                button.classList.add("active");
            }}

        }});
}}


function scrollToResults() {{

    document
        .getElementById("cve-list")
        .scrollIntoView({{
            behavior: "smooth",
            block: "start"
        }});
}}


function filterByClassification(value) {{

    activeClassFilter = value;

    activateFilterButton(
        ".class-filter",
        value
    );

    applyFilters();
    scrollToResults();
}}


function filterBySeverity(value) {{

    activeSeverityFilter = value;

    activateFilterButton(
        ".severity-filter",
        value
    );

    applyFilters();
    scrollToResults();
}}


function resetAllFilters() {{

    activeClassFilter = "all";
    activeSeverityFilter = "all";
    activeCategoryFilter = "all";

    document
        .getElementById("search")
        .value = "";

    activateFilterButton(
        ".class-filter",
        "all"
    );

    activateFilterButton(
        ".severity-filter",
        "all"
    );

    activateFilterButton(
        ".category-filter",
        "all"
    );

    applyFilters();
    scrollToResults();
}}


function toggleDetails(id) {{

    const element =
        document.getElementById(id);

    element.style.display =
        element.style.display === "block"
            ? "none"
            : "block";
}}


function setClassFilter(button) {{

    activeClassFilter =
        button.dataset.filter;

    activateFilterButton(
        ".class-filter",
        activeClassFilter
    );

    applyFilters();
}}


function setSeverityFilter(button) {{

    activeSeverityFilter =
        button.dataset.filter;

    activateFilterButton(
        ".severity-filter",
        activeSeverityFilter
    );

    applyFilters();
}}


function setCategoryFilter(button) {{

    activeCategoryFilter =
        button.dataset.filter;

    activateFilterButton(
        ".category-filter",
        activeCategoryFilter
    );

    applyFilters();
}}


function applyFilters() {{

    const search =
        document
            .getElementById(
                "search"
            )
            .value
            .toLowerCase()
            .trim();

    let visible = 0;

    document
        .querySelectorAll(
            ".cve-card"
        )
        .forEach(card => {{

            const matchesClass =

                activeClassFilter
                === "all"

                ||

                card.dataset.classification
                === activeClassFilter;


            const matchesSeverity =

                activeSeverityFilter
                === "all"

                ||

                card.dataset.severity
                === activeSeverityFilter;


            const matchesCategory =

                activeCategoryFilter
                === "all"

                ||

                card.dataset.category
                === activeCategoryFilter;


            const matchesSearch =

                !search

                ||

                card.dataset.search
                    .includes(search);


            const show =

                matchesClass

                &&

                matchesSeverity

                &&

                matchesCategory

                &&

                matchesSearch;


            card.style.display =

                show
                    ? "block"
                    : "none";


            if (show) {{
                visible++;
            }}

        }});


    document
        .getElementById(
            "result-count"
        )
        .textContent =
        `${{visible}} CVEs shown`;
}}


function expandAll() {{

    document
        .querySelectorAll(
            ".cve-card"
        )
        .forEach(card => {{

            if (
                card.style.display
                !== "none"
            ) {{

                const details =
                    card.querySelector(
                        ".details"
                    );

                if (details) {{

                    details.style.display =
                        "block";

                }}

            }}

        }});
}}


function collapseAll() {{

    document
        .querySelectorAll(
            ".details"
        )
        .forEach(
            detail =>
                detail.style.display =
                    "none"
        );
}}


applyFilters();

</script>

</body>

</html>
"""


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Generate searchable HTML report "
            "from reduced Trivy JSON."
        )
    )

    parser.add_argument(
        "input",
        help="Reduced Trivy JSON file",
    )

    parser.add_argument(
        "output",
        help="HTML output file",
    )

    args = parser.parse_args()

    input_path = Path(
        args.input
    )

    output_path = Path(
        args.output
    )

    if not input_path.is_file():

        print(
            (
                "Input file does not exist: "
                f"{input_path}"
            ),
            file=sys.stderr,
        )

        return 1

    try:

        with input_path.open(
            "r",
            encoding="utf-8",
        ) as handle:

            data = json.load(
                handle
            )

    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:

        print(
            f"Unable to read JSON: {exc}",
            file=sys.stderr,
        )

        return 2

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    document = create_html(
        data
    )

    tmp_path = (
        output_path.with_suffix(
            output_path.suffix
            + ".tmp"
        )
    )

    try:

        tmp_path.write_text(
            document,
            encoding="utf-8",
        )

        tmp_path.replace(
            output_path
        )

    except OSError as exc:

        print(
            (
                "Unable to write HTML: "
                f"{exc}"
            ),
            file=sys.stderr,
        )

        return 3

    print(
        (
            "HTML report written to "
            f"{output_path}"
        )
    )

    return 0


if __name__ == "__main__":
    sys.exit(
        main()
    )