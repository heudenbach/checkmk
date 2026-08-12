# Trivy Vulnerability Monitoring for Checkmk

**Documentation:** 🇬🇧 **English** | 🇩🇪 [Deutsch](README.md)

Integration of Trivy with Checkmk using vendor severity, runtime relevance,
CISA KEV, EPSS, and P1--P4 prioritization.

> Version: MKP `trivy_report` 1.3.0, Checkmk >= 2.5.0p10.

## What does this integration do?

This solution combines a local Trivy vulnerability scan with an
operations-oriented assessment and Checkmk monitoring.

The workflow consists of several stages:

1. **Trivy** scans the Linux host for known vulnerabilities.
2. The **Reducer** evaluates the results in the context of the system that is
   actually running, including distribution, architecture, running packages,
   kernel, and kernel modules.
3. **Threat Intelligence** enriches the CVEs with CISA KEV and EPSS.
4. Vendor severity, runtime relevance, and threat intelligence are combined
   into an operational **P1--P4 prioritization**.
5. **Checkmk** monitors these priorities and can generate WARN and CRIT states
   using freely configurable thresholds.
6. A detailed **HTML report** is generated as well, exposing the individual
   findings and their assessment.

### Checkmk Service

The Checkmk service shows the operational summary directly in monitoring:

![Trivy Service in Checkmk](https://cf.eude.rocks/gitimg/trivy_service_cmk.png)

### Checkmk Metrics

The integration also provides metrics for priorities, vendor severity,
operational classification, CISA KEV, EPSS, and report age:

![Trivy Checkmk Metrics](https://cf.eude.rocks/gitimg/trivy_service_metrics.png)

### HTML Vulnerability Report

In addition to the compact Checkmk view, every successful run generates a
standalone, detailed **HTML Vulnerability Report**:

![Trivy HTML Vulnerability Report](https://cf.eude.rocks/gitimg/trivy_html_report_example.png)

The HTML report is intended for detailed analysis: Checkmk primarily answers
the question **whether action is required**, while the HTML report shows the
underlying CVEs and their assessment.

It is stored under `/var/lib/trivy/results/`. The hostname is included in the
filename, for example:

```text
trivy_report_mail.html
trivy_report_she2-mon-l-001.html
```

The HTML file can be opened directly in a browser, served through a web
server, or collected together with reports from other hosts at a central
location.

## 1. Architecture

```text
Trivy
  -> trivy_scan.sh -> /var/lib/trivy/results/rootfs.json
  -> trivy_reduce.sh -> /var/lib/trivy/results/checkmk.json
  -> trivy_threatintel.py -> CISA KEV + EPSS + P1-P4
  -> trivy_html.py -> trivy_report_<hostname>.html
  -> Checkmk Agent Plugin -> <<<trivy_report>>>
  -> Checkmk Server / MKP -> Service "Trivy Report"
```

The operational assessment preferably uses the rating provided by the
distribution/package vendor. CVSS remains available as technical information
but does not determine priority on its own. Runtime and kernel relevance as
well as KEV/EPSS complement the assessment.

## 2. Requirements

The monitored Linux host requires:

- Trivy
- Python 3
- `jq`
- Checkmk Agent
- outbound HTTPS access for Trivy and threat intelligence

The logic has been tested in particular with Ubuntu/Debian and RHEL;
Rocky Linux and AlmaLinux use the RPM package backend as well.

## 3. Install Trivy

### Ubuntu / Debian

```bash
apt-get update
apt-get install -y wget gnupg jq python3

wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
  | gpg --dearmor \
  | tee /usr/share/keyrings/trivy.gpg >/dev/null

echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
  > /etc/apt/sources.list.d/trivy.list

apt-get update
apt-get install -y trivy
trivy --version
```

### RHEL / Rocky Linux / AlmaLinux

```bash
cat >/etc/yum.repos.d/trivy.repo <<'EOF'
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF

dnf install -y trivy jq python3
trivy --version
```

## 4. Directories

```bash
mkdir -p /var/lib/trivy/results
chmod 755 /var/lib/trivy /var/lib/trivy/results
```

The scripts are stored under `/usr/local/bin/`, while results are stored under
`/var/lib/trivy/results/`.

## 5. Install the scripts

The required host scripts for release 1.3.0 are provided together as an
archive:

```text
trivy-host-scripts-1.3.0.tar.gz
```

The archive contains:

```text
trivy_scan.sh
trivy_reduce.sh
trivy_threatintel.py
trivy_html.py
trivy_checkmk_wrapper.sh
```

Extract the archive:

```bash
tar xzf trivy-host-scripts-1.3.0.tar.gz
```

Then copy the extracted scripts to `/usr/local/bin/`:

```bash
cp trivy_scan.sh /usr/local/bin/
cp trivy_reduce.sh /usr/local/bin/
cp trivy_threatintel.py /usr/local/bin/
cp trivy_html.py /usr/local/bin/
cp trivy_checkmk_wrapper.sh /usr/local/bin/
```

Set ownership and permissions:

```bash
chown root:root /usr/local/bin/trivy_*
chmod 755 /usr/local/bin/trivy_*
```

### Processing

`trivy_scan.sh` writes the raw Trivy data to:

```text
/var/lib/trivy/results/rootfs.json
```

`trivy_reduce.sh` creates the report prepared for monitoring and reporting:

```text
/var/lib/trivy/results/checkmk.json
```

The Reducer detects, among other things, distribution, vendor key, package
backend, architecture, running kernel, kernel package, loaded/available kernel
modules, and runtime usage of affected packages.

Kernel states can include:

```text
active
inactive
present_builtin
present_builtin_config
available_not_loaded
not_present
unknown
```

The operational classification primarily uses:

```text
ACTION_REQUIRED
REVIEW
```

`trivy_threatintel.py` enriches `checkmk.json` with CISA KEV, EPSS
score/percentile, and P1--P4 prioritization.

```bash
/usr/local/bin/trivy_threatintel.py /var/lib/trivy/results/checkmk.json
jq '.threat_intel' /var/lib/trivy/results/checkmk.json
jq '.priority_counts, .priority_meta.signals' /var/lib/trivy/results/checkmk.json
```

`trivy_html.py` additionally generates a standalone, detailed HTML report.
The hostname is appended to the filename so reports from multiple hosts can
later be collected centrally.

The report is stored under `/var/lib/trivy/results/`, for example:

```text
/var/lib/trivy/results/trivy_report_mail.html
```

It can be opened directly in a browser or served through a web server. This
provides a detailed view for analyzing individual vulnerabilities in addition
to the compact Checkmk service.

## 6. Run the wrapper

The production workflow is:

```text
1. trivy_scan.sh
2. trivy_reduce.sh
3. trivy_threatintel.py
4. trivy_html.py
```

Threat intelligence is enrichment and a temporary network failure should not
make an existing local report unusable.

Manual test:

```bash
/usr/local/bin/trivy_checkmk_wrapper.sh
echo $?
tail -100 /var/log/trivy_checkmk.log
```

Expected return code: `0`.

Important checks:

```bash
jq '{host: .host, scanner_warnings: .scanner_warnings, operational_counts: .operational_counts}' \
  /var/lib/trivy/results/checkmk.json

jq '.priority_counts' /var/lib/trivy/results/checkmk.json
jq '.threat_intel' /var/lib/trivy/results/checkmk.json
```

## 7. Scheduled execution

The wrapper should run regularly as `root`. Example cron job every six hours:

```cron
0 */6 * * * root /usr/local/bin/trivy_checkmk_wrapper.sh
```

For production systems, a systemd timer is preferable.

## 8. Install MKP `trivy_report` 1.3.0

The MKP requires Checkmk `2.5.0p10` or newer and contains:

```text
Agents
  plugins/trivy_report

Additional Checkmk plug-ins by third parties
  trivy/agent_based/trivy_report.py
  trivy/rulesets/ruleset_trivy_report.py
  trivy/rulesets/ruleset_trivy_bakery.py

Libraries
  python3/cmk/base/cee/plugins/bakery/trivy_report_bakery.py
```

As the Checkmk site user, install/enable the package and verify it:

```bash
mkp list
mkp show trivy_report 1.3.0
cmk-validate-plugins
```

Validation must complete without errors.

## 9. Agent Bakery rule

In Checkmk:

```text
Setup
-> Agents
-> Windows, Linux, Solaris, AIX
-> Agent rules
```

Search for the Trivy rule provided by the MKP, enable it, and restrict it to
the desired hosts. Then run **Bake agents** and deploy the newly built agent
package.

Debian/Ubuntu:

```bash
dpkg -i check-mk-agent_*.deb
```

RHEL/Rocky/Alma:

```bash
rpm -U check-mk-agent-*.rpm
```

Typical plugin path on the host:

```text
/usr/lib/check_mk_agent/plugins/trivy_report
```

Verify:

```bash
/usr/lib/check_mk_agent/plugins/trivy_report | head -30
```

The output must begin with the following section:

```text
<<<trivy_report:sep(0)>>>
```

## 10. Verify data on the Checkmk server

```bash
cmk -d HOSTNAME | grep -A20 -B2 '<<<trivy_report'
```

Then perform service discovery and activate the changes. For a CLI test:

```bash
cmk -IIv HOSTNAME
cmk -nv HOSTNAME
```

## 11. Service rule `Trivy vulnerability report`

Recommended initial configuration:

| Signal | WARN | CRIT |
| --- | ---: | ---: |
| P1 -- Immediate | disabled | 1 |
| P2 -- High | 1 | disabled |
| P3 -- Normal | disabled | disabled |
| P4 -- Review | disabled | disabled |
| CISA KEV | disabled | 1 |
| Report age | 8 h | 14 h |

This means by default:

```text
P1 >= 1       -> CRIT
P2 >= 1       -> WARN
KEV >= 1      -> CRIT
Report >= 8h  -> WARN
Report >= 14h -> CRIT
```

P3 and P4 remain visible and are stored as metrics, but do not trigger an
alert in this default configuration.

## 12. Priority model

**P1 -- Immediate:** highest operational priority, particularly for strong
exploit/threat-intelligence signals combined with actual host relevance.

**P2 -- High:** high operational priority, for example vendor severity `HIGH`
combined with `ACTION_REQUIRED`.

**P3 -- Normal:** operationally relevant on the host and `ACTION_REQUIRED`,
but without P1/P2 escalation.

**P4 -- Review:** findings without immediate remediation escalation that
should still be reviewed or documented.

## 13. Vendor Severity, CVSS, KEV, and EPSS

The system deliberately separates:

```text
CVSS
Vendor Severity
Operational Classification
Threat Intelligence
Priority
```

CVSS is retained. For practical display and prioritization, however, the
rating from the vendor matching the distribution is preferred.
Runtime/kernel relevance additionally determines whether a finding is
actually actionable on the specific host. CISA KEV and EPSS complement this
assessment with known and probable exploitation information.

## 14. Checkmk metrics

The following metrics are generated, among others:

```text
trivy_priority_p1
trivy_priority_p2
trivy_priority_p3
trivy_priority_p4
trivy_kev
trivy_epss_scored
trivy_action_required
trivy_review
trivy_suppressed
trivy_remediation_required
trivy_fix_available
trivy_critical
trivy_high
trivy_medium
trivy_low
trivy_unknown
trivy_total_cves
trivy_report_age
```

Severity metrics remain visible but no longer directly determine the service
state.

## 15. Functional test

```bash
cmk -nv HOSTNAME | grep 'Trivy Report'
```

Example:

```text
Trivy Report  P1: 0, P2: 1, P3: 50, P4: 1233, KEV: 0, Report age: 2.0 h
```

With the recommended rule, this is `WARN` because `P2 = 1`.

Check effective parameters:

```bash
cmk -D HOSTNAME | grep trivy_report
```

Check the stored state through Livestatus:

```bash
lq "GET services
Columns: description state hard_state plugin_output last_check
Filter: host_name = HOSTNAME
Filter: description = Trivy Report"
```

State values:

```text
0 = OK
1 = WARN
2 = CRIT
3 = UNKNOWN
```

## 16. Troubleshooting

Run the agent plugin locally:

```bash
/usr/lib/check_mk_agent/plugins/trivy_report
```

Validate JSON:

```bash
jq empty /var/lib/trivy/results/checkmk.json
echo $?
```

Wrapper/log:

```bash
/usr/local/bin/trivy_checkmk_wrapper.sh
echo $?
tail -100 /var/log/trivy_checkmk.log
```

Threat intelligence/priority:

```bash
jq '.threat_intel' /var/lib/trivy/results/checkmk.json
jq '.priority_counts' /var/lib/trivy/results/checkmk.json
```

Checkmk:

```bash
cmk-validate-plugins
cmk -d HOSTNAME | grep -A20 '<<<trivy_report'
cmk -nv HOSTNAME
cmk -D HOSTNAME | grep trivy_report
```

## 17. Network access

Basic connectivity can be checked with:

```bash
curl -I https://github.com
curl -I https://ghcr.io
curl -I https://aquasecurity.github.io
```

An HTTP `405` response from `ghcr.io` to a HEAD request does not automatically
mean that the registry is blocked.

## 18. Central HTML reports

Because the hostname is included in the filename, reports can later be
collected centrally:

```text
reports/
  trivy_report_host01.html
  trivy_report_host02.html
  trivy_report_host03.html
```

A central overview page for all monitored hosts can then be built on top of
these reports.

## 19. Quick installation

```text
1. Install Trivy + jq + Python 3
2. Create /var/lib/trivy/results
3. Extract trivy-host-scripts-1.3.0.tar.gz and copy scripts to /usr/local/bin
4. Test the wrapper
5. Verify checkmk.json and the HTML report
6. Install MKP trivy_report 1.3.0
7. Run cmk-validate-plugins
8. Create the Trivy Agent Bakery rule
9. Bake and deploy the agent
10. Verify <<<trivy_report>>>
11. Run service discovery
12. Create the Trivy service rule
13. Configure P1/P2/P3/P4/KEV/report age
14. Test with cmk -nv HOSTNAME
```

## External documentation

- Trivy installation:
  https://trivy.dev/docs/latest/getting-started/installation/
- Checkmk Linux Agent:
  https://docs.checkmk.com/latest/en/agent_linux.html

## Note

This project is an independent integration. Trivy and Checkmk are separate
projects and are subject to their respective licenses and support terms.
