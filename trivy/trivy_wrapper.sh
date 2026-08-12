#!/bin/bash

TRIVY_SCRIPT="/usr/local/bin/trivy_scan.sh"
REDUCER_SCRIPT="/usr/local/bin/trivy_reduce.sh"
THREATINTEL_SCRIPT="/usr/local/bin/trivy_threatintel.py"
HTML_SCRIPT="/usr/local/bin/trivy_html.py"

REDUCED_JSON="/var/lib/trivy/results/checkmk.json"
HTML_REPORT="/var/lib/trivy/results/trivy_report.html"

LOG="/var/log/trivy_checkmk.log"

echo "$(date '+%F %T') - Starting Trivy scan" >> "$LOG"

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

        if "$HTML_SCRIPT" \
            "$REDUCED_JSON" \
            "$HTML_REPORT" >> "$LOG" 2>&1
        then
            echo "$(date '+%F %T') - HTML report generated successfully" >> "$LOG"
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

exit 0