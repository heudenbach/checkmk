#!/usr/bin/env python3

import argparse
import html
import json
import sys
from pathlib import Path
from datetime import datetime


def score_class(score):
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    return "low"


def score_text(score):
    if score is None:
        return "No CVSS"
    return f"{float(score):.1f}"


def render_findings(findings):
    if not findings:
        return '<div class="finding muted">No package/location information</div>'

    blocks = []

    for finding in findings:
        package = html.escape(str(finding.get("package") or "-"))
        installed = html.escape(str(finding.get("installed_version") or "-"))
        fixed = html.escape(str(finding.get("fixed_version") or "-"))
        path = html.escape(str(finding.get("path") or "-"))

        blocks.append(
            f"""
            <div class="finding">
                <div><strong>Package:</strong> {package}</div>
                <div><strong>Installed:</strong> {installed}</div>
                <div><strong>Fixed:</strong> {fixed}</div>
                <div><strong>Path:</strong> <code>{path}</code></div>
            </div>
            """
        )

    return "\n".join(blocks)


def create_html(data):
    generated = html.escape(str(data.get("generated", "unknown")))
    cves = data.get("cves", [])

    # Reducer is already sorting, but do it again for safety.
    cves = sorted(
        cves,
        key=lambda cve: (
            cve.get("score") is not None,
            cve.get("score") if cve.get("score") is not None else -1
        ),
        reverse=True,
    )

    count_critical = sum(
        1 for cve in cves
        if cve.get("score") is not None and float(cve["score"]) >= 9.0
    )

    count_high = sum(
        1 for cve in cves
        if cve.get("score") is not None
        and 7.0 <= float(cve["score"]) < 9.0
    )

    count_low = sum(
        1 for cve in cves
        if cve.get("score") is not None and float(cve["score"]) < 7.0
    )

    count_unknown = sum(
        1 for cve in cves
        if cve.get("score") is None
    )

    rows = []

    for index, cve in enumerate(cves):
        cve_id = html.escape(str(cve.get("id", "UNKNOWN")))
        score = cve.get("score")
        css_class = score_class(score)
        score_display = score_text(score)

        findings = cve.get("findings", [])

        searchable = " ".join(
            [
                str(cve.get("id", "")),
                str(score_display),
                *[
                    " ".join([
                        str(f.get("package", "")),
                        str(f.get("installed_version", "")),
                        str(f.get("fixed_version", "")),
                        str(f.get("path", "")),
                    ])
                    for f in findings
                ],
            ]
        ).lower()

        rows.append(
            f"""
            <article
                class="cve-card {css_class}"
                data-score-class="{css_class}"
                data-search="{html.escape(searchable, quote=True)}"
                data-score="{score if score is not None else -1}"
            >
                <div class="cve-header" onclick="toggleDetails('details-{index}')">
                    <div class="cve-title">{cve_id}</div>

                    <div class="score score-{css_class}">
                        {score_display}
                    </div>
                </div>

                <div id="details-{index}" class="details">
                    {render_findings(findings)}
                </div>
            </article>
            """
        )

    generated_local = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    return f"""<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Trivy Vulnerability Report</title>

<style>

:root {{
    color-scheme: dark;
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
    background: #11151b;
    color: #e8edf2;
}}

.container {{
    max-width: 1500px;
    margin: auto;
    padding: 28px;
}}

h1 {{
    margin-bottom: 6px;
}}

.subtitle {{
    color: #9ca8b5;
    margin-bottom: 24px;
}}

.summary {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 14px;
    margin-bottom: 24px;
}}

.summary-card {{
    background: #1b222c;
    border: 1px solid #303945;
    border-radius: 10px;
    padding: 16px;
}}

.summary-value {{
    font-size: 28px;
    font-weight: 700;
}}

.summary-label {{
    color: #a9b3bd;
    margin-top: 4px;
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
    border: 1px solid #37414d;
    border-radius: 8px;
    background: #171d25;
    color: #fff;
    margin-bottom: 12px;
}}

.filters {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}}

button {{
    border: 1px solid #3c4652;
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
}}

.result-count {{
    margin: 14px 0;
    color: #aeb8c2;
}}

.cve-card {{
    border: 1px solid #303945;
    border-left-width: 5px;
    border-radius: 9px;
    background: #191f27;
    margin-bottom: 9px;
    overflow: hidden;
}}

.cve-card.critical {{
    border-left-color: #e24c4b;
}}

.cve-card.high {{
    border-left-color: #e8a23b;
}}

.cve-card.low {{
    border-left-color: #56a36c;
}}

.cve-card.unknown {{
    border-left-color: #8a94a2;
}}

.cve-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 13px 16px;
    cursor: pointer;
}}

.cve-title {{
    font-size: 17px;
    font-weight: 650;
}}

.score {{
    min-width: 90px;
    text-align: center;
    padding: 5px 10px;
    border-radius: 6px;
    font-weight: 700;
}}

.score-critical {{
    background: #5a2020;
}}

.score-high {{
    background: #604516;
}}

.score-low {{
    background: #204d2e;
}}

.score-unknown {{
    background: #37404a;
}}

.details {{
    display: none;
    padding: 0 16px 15px;
}}

.finding {{
    background: #12171d;
    border: 1px solid #2b333d;
    border-radius: 7px;
    padding: 12px;
    margin-top: 9px;
    line-height: 1.55;
}}

code {{
    color: #d8e2ec;
    overflow-wrap: anywhere;
}}

.muted {{
    color: #9ba5af;
}}

.footer {{
    margin-top: 30px;
    color: #77828e;
    font-size: 13px;
}}

</style>
</head>

<body>

<div class="container">

<h1>Trivy Vulnerability Report</h1>

<div class="subtitle">
    Trivy scan: {generated}<br>
    HTML generated: {generated_local}
</div>

<section class="summary">

    <div class="summary-card">
        <div class="summary-value">{len(cves)}</div>
        <div class="summary-label">Total CVEs</div>
    </div>

    <div class="summary-card">
        <div class="summary-value">{count_critical}</div>
        <div class="summary-label">CVSS ≥ 9.0</div>
    </div>

    <div class="summary-card">
        <div class="summary-value">{count_high}</div>
        <div class="summary-label">CVSS 7.0 – 8.9</div>
    </div>

    <div class="summary-card">
        <div class="summary-value">{count_low}</div>
        <div class="summary-label">CVSS &lt; 7.0</div>
    </div>

    <div class="summary-card">
        <div class="summary-value">{count_unknown}</div>
        <div class="summary-label">No CVSS</div>
    </div>

</section>

<div class="controls">

    <input
        id="search"
        class="search"
        type="search"
        placeholder="Search CVE, package, version or path..."
        oninput="applyFilters()"
    >

    <div class="filters">
        <button class="filter active" data-filter="all" onclick="setFilter(this)">All</button>
        <button class="filter" data-filter="critical" onclick="setFilter(this)">CVSS ≥ 9</button>
        <button class="filter" data-filter="high" onclick="setFilter(this)">CVSS 7 – 8.9</button>
        <button class="filter" data-filter="low" onclick="setFilter(this)">CVSS &lt; 7</button>
        <button class="filter" data-filter="unknown" onclick="setFilter(this)">No CVSS</button>

        <button onclick="expandAll()">Expand all</button>
        <button onclick="collapseAll()">Collapse all</button>
    </div>

</div>

<div id="result-count" class="result-count"></div>

<section id="cve-list">
{"".join(rows)}
</section>

<div class="footer">
    Generated from reduced Trivy JSON.
</div>

</div>

<script>

let activeFilter = "all";

function toggleDetails(id) {{
    const element = document.getElementById(id);

    if (element.style.display === "block") {{
        element.style.display = "none";
    }} else {{
        element.style.display = "block";
    }}
}}

function setFilter(button) {{
    document.querySelectorAll(".filter").forEach(
        b => b.classList.remove("active")
    );

    button.classList.add("active");

    activeFilter = button.dataset.filter;

    applyFilters();
}}

function applyFilters() {{
    const search = document
        .getElementById("search")
        .value
        .toLowerCase()
        .trim();

    let visible = 0;

    document.querySelectorAll(".cve-card").forEach(card => {{
        const matchesFilter =
            activeFilter === "all" ||
            card.dataset.scoreClass === activeFilter;

        const matchesSearch =
            !search ||
            card.dataset.search.includes(search);

        const show = matchesFilter && matchesSearch;

        card.style.display = show ? "block" : "none";

        if (show) {{
            visible++;
        }}
    }});

    document.getElementById("result-count").textContent =
        `${{visible}} findings shown`;
}}

function expandAll() {{
    document
        .querySelectorAll(".cve-card")
        .forEach(card => {{
            if (card.style.display !== "none") {{
                const detail = card.querySelector(".details");
                detail.style.display = "block";
            }}
        }});
}}

function collapseAll() {{
    document
        .querySelectorAll(".details")
        .forEach(detail => {{
            detail.style.display = "none";
        }});
}}

applyFilters();

</script>

</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(
        description="Generate searchable HTML report from reduced Trivy JSON."
    )

    parser.add_argument(
        "input",
        help="Reduced Trivy JSON file"
    )

    parser.add_argument(
        "output",
        help="HTML output file"
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.is_file():
        print(
            f"Input file does not exist: {input_path}",
            file=sys.stderr
        )
        return 1

    try:
        with input_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)

    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"Unable to read JSON: {exc}",
            file=sys.stderr
        )
        return 2

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    document = create_html(data)

    tmp_path = output_path.with_suffix(
        output_path.suffix + ".tmp"
    )

    try:
        tmp_path.write_text(
            document,
            encoding="utf-8"
        )

        tmp_path.replace(output_path)

    except OSError as exc:
        print(
            f"Unable to write HTML: {exc}",
            file=sys.stderr
        )
        return 3

    print(
        f"HTML report written to {output_path}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())