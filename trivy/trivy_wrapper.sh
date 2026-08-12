#!/bin/bash

TRIVY_SCRIPT="/usr/local/bin/trivy_scan.sh"
REDUCER_SCRIPT="/usr/local/bin/trivy_reduce.sh"
THREATINTEL_SCRIPT="/usr/local/bin/trivy_threatintel.py"
HTML_SCRIPT="/usr/local/bin/trivy_html.py"

RESULT_DIR="/var/lib/trivy/results"
REDUCED_JSON="${RESULT_DIR}/checkmk.json"

LOG="/var/log/trivy_checkmk.log"

#
# ------------------------------------------------------------
# Host-specific report names
# ------------------------------------------------------------
#
# Prefer the FQDN. If hostname -f fails or returns nothing,
# fall back to the short hostname.
#
HOSTNAME_FQDN="$(
    hostname -f 2>/dev/null
)"

if [[ -z "$HOSTNAME_FQDN" ]]; then
    HOSTNAME_FQDN="$(
        hostname 2>/dev/null
    )"
fi

if [[ -z "$HOSTNAME_FQDN" ]]; then
    HOSTNAME_FQDN="unknown-host"
fi

#
# Normalize the hostname for use in filenames.
#
SAFE_HOSTNAME="$(
    printf '%s' "$HOSTNAME_FQDN" \
        | tr '[:upper:]' '[:lower:]' \
        | sed 's/[^a-z0-9._-]/_/g'
)"

HTML_REPORT="${RESULT_DIR}/trivy_report_${SAFE_HOSTNAME}.html"
JSON_REPORT="${RESULT_DIR}/trivy_report_${SAFE_HOSTNAME}.json"

mkdir -p "$RESULT_DIR"

echo "$(date '+%F %T') - Starting Trivy scan for ${HOSTNAME_FQDN}" >> "$LOG"

if "$TRIVY_SCRIPT" >> "$LOG" 2>&1; then

    echo "$(date '+%F %T') - Trivy scan finished successfully" >> "$LOG"

    if "$REDUCER_SCRIPT" >> "$LOG" 2>&1; then

        echo "$(date '+%F %T') - Reducer finished successfully" >> "$LOG"

        #
        # Threat intelligence is enrichment, not a hard dependency.
        # trivy_threatintel.py itself uses cache/fallback logic.
        #
        if "$THREATINTEL_SCRIPT" \
            "$REDUCED_JSON" >> "$LOG" 2>&1
        then
            echo "$(date '+%F %T') - Threat intelligence enrichment finished successfully" >> "$LOG"
        else
            echo "$(date '+%F %T') - WARNING: Threat intelligence enrichment failed; continuing with reduced report" >> "$LOG"
        fi

        #
        # Keep checkmk.json as the working file for the Checkmk agent plugin,
        # and additionally publish a host-specific JSON file for later
        # collection by a central reporting system.
        #
        JSON_TMP="${JSON_REPORT}.tmp"

        if cp --preserve=mode,timestamps \
            "$REDUCED_JSON" \
            "$JSON_TMP" >> "$LOG" 2>&1
        then
            if mv -f \
                "$JSON_TMP" \
                "$JSON_REPORT" >> "$LOG" 2>&1
            then
                echo "$(date '+%F %T') - Host JSON report written to ${JSON_REPORT}" >> "$LOG"
            else
                echo "$(date '+%F %T') - ERROR: Unable to publish host JSON report" >> "$LOG"
                rm -f "$JSON_TMP"
                exit 4
            fi
        else
            echo "$(date '+%F %T') - ERROR: Unable to create host JSON report" >> "$LOG"
            rm -f "$JSON_TMP"
            exit 4
        fi

        #
        # Generate host-specific HTML report.
        #
        if "$HTML_SCRIPT" \
            "$REDUCED_JSON" \
            "$HTML_REPORT" >> "$LOG" 2>&1
        then
            echo "$(date '+%F %T') - HTML report generated successfully: ${HTML_REPORT}" >> "$LOG"
        else
            echo "$(date '+%F %T') - ERROR: HTML report generation failed" >> "$LOG"
            exit 3
        fi

    else
        echo "$(date '+%F %T') - ERROR: Reducer failed" >> "$LOG"
        exit 2
    fi

else
    echo "$(date '+%F %T') - ERROR: Trivy scan failed" >> "$LOG"
    exit 1
fi

echo "$(date '+%F %T') - Trivy workflow completed successfully" >> "$LOG"
echo "$(date '+%F %T') - JSON report: ${JSON_REPORT}" >> "$LOG"
echo "$(date '+%F %T') - HTML report: ${HTML_REPORT}" >> "$LOG"

exit 0