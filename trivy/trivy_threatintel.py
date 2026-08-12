#!/usr/bin/env python3

import argparse
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

DEFAULT_CACHE_DIR = "/var/lib/trivy/cache"
DEFAULT_TIMEOUT = 30
DEFAULT_KEV_MAX_AGE = 24 * 3600
DEFAULT_EPSS_MAX_AGE = 24 * 3600
EPSS_BATCH_SIZE = 100

USER_AGENT = "trivy-checkmk-threatintel/1.0"


def utc_now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso8601(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def age_seconds(timestamp):
    dt = parse_iso8601(timestamp)
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    return max(0.0, (now - dt.astimezone(timezone.utc)).total_seconds())


def atomic_write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(tmp_name, path)

    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def load_json(path, default=None):
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return default


def http_get_json(url, timeout=DEFAULT_TIMEOUT):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        body = response.read().decode(charset)
        return json.loads(body)


def load_kev_cache(path):
    data = load_json(path, default={}) or {}
    entries = data.get("entries") or {}
    fetched_at = data.get("fetched_at")
    return entries, fetched_at


def refresh_kev(cache_file, timeout, max_age):
    cached_entries, cached_at = load_kev_cache(cache_file)
    cached_age = age_seconds(cached_at)

    if cached_entries and cached_age is not None and cached_age <= max_age:
        return cached_entries, {
            "source": "cache",
            "fetched_at": cached_at,
            "age_seconds": int(cached_age),
            "error": None,
        }

    try:
        payload = http_get_json(KEV_URL, timeout=timeout)

        entries = {}
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cveID")
            if not cve:
                continue

            entries[cve] = {
                "cve": cve,
                "vendor_project": item.get("vendorProject"),
                "product": item.get("product"),
                "vulnerability_name": item.get("vulnerabilityName"),
                "date_added": item.get("dateAdded"),
                "short_description": item.get("shortDescription"),
                "required_action": item.get("requiredAction"),
                "due_date": item.get("dueDate"),
                "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
                "notes": item.get("notes"),
            }

        fetched_at = utc_now_iso()

        atomic_write_json(
            cache_file,
            {
                "fetched_at": fetched_at,
                "catalog_version": payload.get("catalogVersion"),
                "date_released": payload.get("dateReleased"),
                "count": len(entries),
                "entries": entries,
            },
        )

        return entries, {
            "source": "network",
            "fetched_at": fetched_at,
            "age_seconds": 0,
            "error": None,
        }

    except Exception as exc:
        if cached_entries:
            return cached_entries, {
                "source": "stale_cache",
                "fetched_at": cached_at,
                "age_seconds": int(cached_age) if cached_age is not None else None,
                "error": str(exc),
            }

        return {}, {
            "source": "unavailable",
            "fetched_at": None,
            "age_seconds": None,
            "error": str(exc),
        }


def load_epss_cache(path):
    data = load_json(path, default={}) or {}
    return data.get("entries") or {}


def save_epss_cache(path, entries):
    atomic_write_json(
        path,
        {
            "updated_at": utc_now_iso(),
            "entries": entries,
        },
    )


def epss_entry_fresh(entry, max_age):
    if not entry:
        return False
    fetched_at = entry.get("_fetched_at")
    age = age_seconds(fetched_at)
    return age is not None and age <= max_age


def fetch_epss_batch(cves, timeout):
    params = urllib.parse.urlencode(
        {
            "cve": ",".join(cves),
        }
    )
    url = f"{EPSS_URL}?{params}"
    payload = http_get_json(url, timeout=timeout)

    result = {}

    for item in payload.get("data", []):
        cve = item.get("cve")
        if not cve:
            continue

        try:
            epss = float(item["epss"]) if item.get("epss") not in (None, "") else None
        except (TypeError, ValueError):
            epss = None

        try:
            percentile = (
                float(item["percentile"])
                if item.get("percentile") not in (None, "")
                else None
            )
        except (TypeError, ValueError):
            percentile = None

        result[cve] = {
            "cve": cve,
            "epss": epss,
            "percentile": percentile,
            "date": item.get("date"),
            "_fetched_at": utc_now_iso(),
        }

    return result


def refresh_epss(cves, cache_file, timeout, max_age):
    cache = load_epss_cache(cache_file)

    needed = [
        cve
        for cve in cves
        if not epss_entry_fresh(cache.get(cve), max_age)
    ]

    network_errors = []

    for start in range(0, len(needed), EPSS_BATCH_SIZE):
        batch = needed[start:start + EPSS_BATCH_SIZE]

        try:
            fresh = fetch_epss_batch(batch, timeout=timeout)
            cache.update(fresh)

            # Mark CVEs absent from the API response so they do not get
            # queried repeatedly on every run.
            fetched_at = utc_now_iso()
            for cve in batch:
                if cve not in fresh:
                    cache[cve] = {
                        "cve": cve,
                        "epss": None,
                        "percentile": None,
                        "date": None,
                        "_fetched_at": fetched_at,
                    }

        except Exception as exc:
            network_errors.append(str(exc))
            # Continue with remaining batches; stale cache may still exist.

    try:
        save_epss_cache(cache_file, cache)
    except Exception as exc:
        network_errors.append(f"Unable to save EPSS cache: {exc}")

    output = {}
    stale_count = 0

    for cve in cves:
        entry = cache.get(cve)
        if not entry:
            continue

        age = age_seconds(entry.get("_fetched_at"))
        if age is not None and age > max_age:
            stale_count += 1

        output[cve] = {
            "epss": entry.get("epss"),
            "percentile": entry.get("percentile"),
            "date": entry.get("date"),
            "fetched_at": entry.get("_fetched_at"),
            "age_seconds": int(age) if age is not None else None,
        }

    if needed and not network_errors:
        source = "network"
    elif network_errors and output:
        source = "cache_or_partial"
    elif output:
        source = "cache"
    else:
        source = "unavailable"

    return output, {
        "source": source,
        "requested_cves": len(cves),
        "refreshed_cves": max(0, len(needed) - len(network_errors) * EPSS_BATCH_SIZE),
        "available_cves": len(output),
        "stale_entries": stale_count,
        "errors": network_errors,
    }




PRIORITY_ORDER = {
    "P1": 1,
    "P2": 2,
    "P3": 3,
    "P4": 4,
}


def determine_priority(cve):
    classification = str(
        cve.get("classification") or "REVIEW"
    ).upper()

    severity = str(
        cve.get("vendor_severity_name")
        or cve.get("severity")
        or "UNKNOWN"
    ).upper()

    threat_intel = cve.get("threat_intel") or {}
    kev = threat_intel.get("cisa_kev") or {}
    epss = threat_intel.get("epss") or {}

    known_exploited = bool(
        kev.get("known_exploited")
    )

    try:
        epss_score = (
            float(epss.get("score"))
            if epss.get("score") is not None
            else None
        )
    except (TypeError, ValueError):
        epss_score = None

    if (
        known_exploited
        and classification == "ACTION_REQUIRED"
    ):
        return {
            "level": "P1",
            "name": "IMMEDIATE",
            "reason": (
                "CISA KEV and runtime classification "
                "ACTION_REQUIRED"
            ),
        }

    if (
        epss_score is not None
        and epss_score >= 0.50
        and classification == "ACTION_REQUIRED"
    ):
        return {
            "level": "P1",
            "name": "IMMEDIATE",
            "reason": (
                "EPSS >= 50% and runtime classification "
                "ACTION_REQUIRED"
            ),
        }

    if (
        severity == "CRITICAL"
        and classification == "ACTION_REQUIRED"
    ):
        return {
            "level": "P1",
            "name": "IMMEDIATE",
            "reason": (
                "Vendor severity CRITICAL and runtime "
                "classification ACTION_REQUIRED"
            ),
        }

    if (
        known_exploited
        and classification == "REVIEW"
    ):
        return {
            "level": "P2",
            "name": "HIGH",
            "reason": (
                "CISA KEV with runtime classification REVIEW"
            ),
        }

    if (
        epss_score is not None
        and epss_score >= 0.10
        and classification == "ACTION_REQUIRED"
    ):
        return {
            "level": "P2",
            "name": "HIGH",
            "reason": (
                "EPSS >= 10% and runtime classification "
                "ACTION_REQUIRED"
            ),
        }

    if (
        severity == "HIGH"
        and classification == "ACTION_REQUIRED"
    ):
        return {
            "level": "P2",
            "name": "HIGH",
            "reason": (
                "Vendor severity HIGH and runtime "
                "classification ACTION_REQUIRED"
            ),
        }

    if (
        epss_score is not None
        and epss_score >= 0.50
        and classification == "REVIEW"
    ):
        return {
            "level": "P2",
            "name": "HIGH",
            "reason": (
                "EPSS >= 50% with runtime classification REVIEW"
            ),
        }

    if classification == "ACTION_REQUIRED":
        return {
            "level": "P3",
            "name": "NORMAL",
            "reason": (
                "Runtime classification ACTION_REQUIRED "
                "without P1/P2 threat indicators"
            ),
        }

    return {
        "level": "P4",
        "name": "REVIEW",
        "reason": (
            "No active-runtime priority trigger; "
            "manual review remains required"
        ),
    }


def add_priorities(report):
    counts = {
        "p1": 0,
        "p2": 0,
        "p3": 0,
        "p4": 0,
    }

    signals = {
        "kev_action_required": 0,
        "kev_review": 0,
        "epss_10_action_required": 0,
        "epss_50_action_required": 0,
        "epss_50_review": 0,
    }

    for cve in report.get("cves") or []:
        priority = determine_priority(cve)
        cve["priority"] = priority
        counts[priority["level"].lower()] += 1

        classification = str(
            cve.get("classification") or "REVIEW"
        ).upper()

        threat_intel = cve.get("threat_intel") or {}
        kev = threat_intel.get("cisa_kev") or {}
        epss = threat_intel.get("epss") or {}

        if kev.get("known_exploited"):
            if classification == "ACTION_REQUIRED":
                signals["kev_action_required"] += 1
            elif classification == "REVIEW":
                signals["kev_review"] += 1

        try:
            epss_score = (
                float(epss.get("score"))
                if epss.get("score") is not None
                else None
            )
        except (TypeError, ValueError):
            epss_score = None

        if epss_score is not None:
            if (
                epss_score >= 0.10
                and classification == "ACTION_REQUIRED"
            ):
                signals["epss_10_action_required"] += 1

            if (
                epss_score >= 0.50
                and classification == "ACTION_REQUIRED"
            ):
                signals["epss_50_action_required"] += 1

            if (
                epss_score >= 0.50
                and classification == "REVIEW"
            ):
                signals["epss_50_review"] += 1

    report["priority_counts"] = counts
    report["priority_meta"] = {
        "model": "operational-threat-priority-v1",
        "generated": utc_now_iso(),
        "rules": {
            "P1": [
                "CISA KEV + ACTION_REQUIRED",
                "EPSS >= 0.50 + ACTION_REQUIRED",
                "Vendor severity CRITICAL + ACTION_REQUIRED",
            ],
            "P2": [
                "CISA KEV + REVIEW",
                "EPSS >= 0.10 + ACTION_REQUIRED",
                "Vendor severity HIGH + ACTION_REQUIRED",
                "EPSS >= 0.50 + REVIEW",
            ],
            "P3": [
                "Remaining ACTION_REQUIRED findings",
            ],
            "P4": [
                "Remaining REVIEW findings",
            ],
        },
        "signals": signals,
    }

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0,
    }

    def sort_key(cve):
        priority = (
            cve.get("priority") or {}
        ).get("level", "P4")

        severity = str(
            cve.get("vendor_severity_name")
            or cve.get("severity")
            or "UNKNOWN"
        ).upper()

        epss = (
            cve.get("threat_intel") or {}
        ).get("epss") or {}

        try:
            epss_score = float(epss.get("score"))
        except (TypeError, ValueError):
            epss_score = -1.0

        try:
            cvss = float(cve.get("score"))
        except (TypeError, ValueError):
            cvss = -1.0

        return (
            -PRIORITY_ORDER.get(priority, 4),
            severity_order.get(severity, 0),
            epss_score,
            cvss,
            str(cve.get("id") or ""),
        )

    report["cves"] = sorted(
        report.get("cves") or [],
        key=sort_key,
        reverse=True,
    )

    return report


def enrich_report(report, kev_entries, epss_entries, kev_meta, epss_meta):
    cves = report.get("cves") or []

    kev_count = 0
    epss_count = 0

    for cve in cves:
        cve_id = cve.get("id")
        if not cve_id:
            continue

        kev = kev_entries.get(cve_id)
        epss = epss_entries.get(cve_id)

        if kev:
            kev_count += 1

        if epss and epss.get("epss") is not None:
            epss_count += 1

        cve["threat_intel"] = {
            "cisa_kev": {
                "known_exploited": bool(kev),
                "vendor_project": kev.get("vendor_project") if kev else None,
                "product": kev.get("product") if kev else None,
                "vulnerability_name": kev.get("vulnerability_name") if kev else None,
                "date_added": kev.get("date_added") if kev else None,
                "required_action": kev.get("required_action") if kev else None,
                "due_date": kev.get("due_date") if kev else None,
                "known_ransomware_campaign_use": (
                    kev.get("known_ransomware_campaign_use")
                    if kev else None
                ),
                "notes": kev.get("notes") if kev else None,
            },
            "epss": {
                "score": epss.get("epss") if epss else None,
                "percentile": epss.get("percentile") if epss else None,
                "date": epss.get("date") if epss else None,
                "fetched_at": epss.get("fetched_at") if epss else None,
                "age_seconds": epss.get("age_seconds") if epss else None,
            },
        }

    report["threat_intel"] = {
        "generated": utc_now_iso(),
        "cisa_kev": {
            **kev_meta,
            "matched_cves": kev_count,
        },
        "epss": {
            **epss_meta,
            "scored_cves": epss_count,
        },
    }

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Enrich reduced Trivy JSON with CISA KEV and FIRST EPSS."
    )

    parser.add_argument(
        "input",
        help="Reduced Trivy JSON, typically /var/lib/trivy/results/checkmk.json",
    )

    parser.add_argument(
        "--output",
        help="Output JSON. Defaults to replacing input atomically.",
    )

    parser.add_argument(
        "--cache-dir",
        default=DEFAULT_CACHE_DIR,
        help=f"Cache directory (default: {DEFAULT_CACHE_DIR})",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )

    parser.add_argument(
        "--kev-max-age",
        type=int,
        default=DEFAULT_KEV_MAX_AGE,
        help="KEV cache maximum age in seconds (default: 86400)",
    )

    parser.add_argument(
        "--epss-max-age",
        type=int,
        default=DEFAULT_EPSS_MAX_AGE,
        help="EPSS cache maximum age in seconds (default: 86400)",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else input_path
    cache_dir = Path(args.cache_dir)

    if not input_path.is_file():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 1

    report = load_json(input_path)
    if not isinstance(report, dict):
        print(f"Unable to read valid JSON from {input_path}", file=sys.stderr)
        return 2

    cve_ids = sorted(
        {
            str(cve.get("id"))
            for cve in (report.get("cves") or [])
            if cve.get("id")
        }
    )

    cache_dir.mkdir(parents=True, exist_ok=True)

    kev_cache = cache_dir / "cisa_kev.json"
    epss_cache = cache_dir / "epss.json"

    kev_entries, kev_meta = refresh_kev(
        kev_cache,
        timeout=args.timeout,
        max_age=args.kev_max_age,
    )

    epss_entries, epss_meta = refresh_epss(
        cve_ids,
        epss_cache,
        timeout=args.timeout,
        max_age=args.epss_max_age,
    )

    enriched = enrich_report(
        report,
        kev_entries,
        epss_entries,
        kev_meta,
        epss_meta,
    )

    enriched = add_priorities(
        enriched
    )

    try:
        atomic_write_json(output_path, enriched)
    except OSError as exc:
        print(f"Unable to write enriched report: {exc}", file=sys.stderr)
        return 3

    print(f"Threat intelligence enrichment written to: {output_path}")
    print(f"CISA KEV matches: {enriched['threat_intel']['cisa_kev']['matched_cves']}")
    print(f"EPSS scores: {enriched['threat_intel']['epss']['scored_cves']}")

    priority_counts = enriched.get(
        "priority_counts",
        {}
    )

    print(
        "Priorities: "
        f"P1={priority_counts.get('p1', 0)} "
        f"P2={priority_counts.get('p2', 0)} "
        f"P3={priority_counts.get('p3', 0)} "
        f"P4={priority_counts.get('p4', 0)}"
    )

    if kev_meta.get("error"):
        print(
            f"WARNING: CISA KEV refresh issue: {kev_meta['error']}",
            file=sys.stderr,
        )

    for error in epss_meta.get("errors", []):
        print(f"WARNING: EPSS refresh issue: {error}", file=sys.stderr)

    # Threat intel is deliberately non-fatal when cached/no data is available.
    return 0


if __name__ == "__main__":
    sys.exit(main())