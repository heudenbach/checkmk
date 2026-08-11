#!/bin/bash
#
# This Reducer will Filter the rootfs.json Report from trivy, down to
#
# CVE; CVSS; Pakage; Installed/Fixed Version and Location
#

INPUT="/var/lib/trivy/results/rootfs.json"
OUTPUT="/var/lib/trivy/results/checkmk.json"

if [[ ! -f "$INPUT" ]]; then
    echo "Input file not found: $INPUT" >&2
    exit 1
fi

TMP="${OUTPUT}.tmp"

jq '
[
  .Results[]?
  | .Vulnerabilities[]?
  | {
      id: .VulnerabilityID,
      package: .PkgName,
      installed_version: (.InstalledVersion // ""),
      fixed_version: (.FixedVersion // ""),
      path: (.PkgPath // ""),
      score: (
        [
          (.CVSS // {} | to_entries[]? | .value.V40Score?),
          (.CVSS // {} | to_entries[]? | .value.V3Score?),
          (.CVSS // {} | to_entries[]? | .value.V2Score?)
        ]
        | map(select(. != null))
        | if length > 0 then max else null end
      )
    }
]
| group_by(.id)
| map(
    {
      id: .[0].id,

      score: (
        map(.score)
        | map(select(. != null))
        | if length > 0 then max else null end
      ),

      findings: (
        map({
          package,
          installed_version,
          fixed_version,
          path
        })
        | unique
      )
    }
  )
| sort_by(
    if .score == null then -1 else .score end
  )
| reverse
| {
    generated: (now | todate),

    counts: {
      score_9_plus:
        ([.[] | select(.score != null and .score >= 9)] | length),

      score_7_to_8_99:
        ([.[] | select(.score != null and .score >= 7 and .score < 9)] | length),

      score_0_to_6_99:
        ([.[] | select(.score != null and .score < 7)] | length),

      unknown:
        ([.[] | select(.score == null)] | length)
    },

    cves: .
  }
' "$INPUT" > "$TMP"

if [[ $? -ne 0 ]]; then
    echo "Failed to reduce Trivy JSON" >&2
    rm -f "$TMP"
    exit 1
fi

mv "$TMP" "$OUTPUT"

echo "Reduced Trivy result written to: $OUTPUT"
