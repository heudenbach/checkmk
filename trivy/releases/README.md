# Trivy Vulnerability Monitoring for Checkmk

**Documentation:** 🇬🇧 [English](README_EN.md) | 🇩🇪 **Deutsch**

Integration von Trivy in Checkmk mit Vendor-Severity, Laufzeitrelevanz,
CISA KEV, EPSS und P1--P4-Priorisierung.

> Stand: MKP `trivy_report` 1.3.0, Checkmk >= 2.5.0p10.

## Was macht diese Integration?

Die Lösung verbindet einen lokalen Trivy-Schwachstellenscan mit einer
betriebsorientierten Bewertung und Checkmk-Monitoring.

Der Ablauf besteht aus mehreren Stufen:

1. **Trivy** scannt den Linux-Host auf bekannte Schwachstellen.
2. **Reducer** bewertet die Ergebnisse im Kontext des tatsächlich laufenden
   Systems, unter anderem anhand von Distribution, Architektur, laufenden
   Paketen, Kernel und Kernelmodulen.
3. **Threat Intelligence** ergänzt die CVEs um CISA KEV und EPSS.
4. Aus Vendor-Severity, Runtime-Relevanz und Threat Intelligence entsteht
   eine operative **P1--P4-Priorisierung**.
5. **Checkmk** überwacht diese Prioritäten und kann über frei konfigurierbare
   Schwellwerte WARN und CRIT erzeugen.
6. Zusätzlich wird ein ausführlicher **HTML-Report** erzeugt, der die
   Einzelbefunde und ihre Bewertung sichtbar macht.

### Checkmk Service

Der Checkmk-Service zeigt die operative Zusammenfassung direkt im Monitoring:

![Trivy Service in Checkmk](https://cf.eude.rocks/gitimg/trivy_service_cmk.png)

### Checkmk Metriken

Die Integration liefert zusätzlich Metriken für Prioritäten, Vendor-Severity,
operative Klassifikation, CISA KEV, EPSS und Reportalter:

![Trivy Checkmk Metrics](https://cf.eude.rocks/gitimg/trivy_service_metrics.png)

### HTML Vulnerability Report

Neben der kompakten Checkmk-Ansicht wird bei jedem erfolgreichen Lauf ein
eigenständiger, detaillierter **HTML Vulnerability Report** erzeugt:

![Trivy HTML Vulnerability Report](https://cf.eude.rocks/gitimg/trivy_html_report_example.png)

Der HTML-Report ist für die Detailanalyse gedacht: Checkmk beantwortet
vor allem die Frage, **ob Handlungsbedarf besteht**; der HTML-Report zeigt
die zugrunde liegenden CVEs und deren Bewertung.

Er wird unter `/var/lib/trivy/results/` abgelegt. Der Dateiname enthält den
Hostnamen, beispielsweise:

```text
trivy_report_mail.html
trivy_report_she2-mon-l-001.html
```

Die HTML-Datei kann direkt im Browser geöffnet, über einen Webserver
bereitgestellt oder später zusammen mit den Reports anderer Hosts an einer
zentralen Stelle gesammelt werden.

## 1. Architektur

```text
Trivy
  -> trivy_scan.sh -> /var/lib/trivy/results/rootfs.json
  -> trivy_reduce.sh -> /var/lib/trivy/results/checkmk.json
  -> trivy_threatintel.py -> CISA KEV + EPSS + P1-P4
  -> trivy_html.py -> trivy_report_<hostname>.html
  -> Checkmk Agent Plugin -> <<<trivy_report>>>
  -> Checkmk Server / MKP -> Service "Trivy Report"
```

Die operative Bewertung verwendet bevorzugt die Einschätzung des
jeweiligen Distributions-/Paket-Vendors. CVSS bleibt als technische
Information erhalten, bestimmt aber nicht allein die Priorität. Runtime-
und Kernel-Relevanz sowie KEV/EPSS ergänzen die Bewertung.

## 2. Voraussetzungen

Auf dem überwachten Linux-Host werden benötigt:

- Trivy
- Python 3
- `jq`
- Checkmk Agent
- ausgehender HTTPS-Zugriff für Trivy und Threat Intelligence

Getestet wurde die Logik insbesondere mit Ubuntu/Debian sowie RHEL;
Rocky Linux und AlmaLinux verwenden ebenfalls das RPM-Paketbackend.

## 3. Trivy installieren

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

## 4. Verzeichnisse

```bash
mkdir -p /var/lib/trivy/results
chmod 755 /var/lib/trivy /var/lib/trivy/results
```

Die Skripte liegen unter `/usr/local/bin/`, die Ergebnisse unter
`/var/lib/trivy/results/`.

## 5. Skripte installieren

Die benötigten Host-Skripte werden für Release 1.3.0 gemeinsam als Archiv
bereitgestellt:

```text
trivy-host-scripts-1.3.0.tar.gz
```

Das Archiv enthält:

```text
trivy_scan.sh
trivy_reduce.sh
trivy_threatintel.py
trivy_html.py
trivy_checkmk_wrapper.sh
```

Archiv entpacken:

```bash
tar xzf trivy-host-scripts-1.3.0.tar.gz
```

Anschließend die entpackten Skripte nach `/usr/local/bin/` kopieren:

```bash
cp trivy_scan.sh /usr/local/bin/
cp trivy_reduce.sh /usr/local/bin/
cp trivy_threatintel.py /usr/local/bin/
cp trivy_html.py /usr/local/bin/
cp trivy_checkmk_wrapper.sh /usr/local/bin/
```

Rechte setzen:

```bash
chown root:root /usr/local/bin/trivy_*
chmod 755 /usr/local/bin/trivy_*
```

### Verarbeitung

`trivy_scan.sh` erzeugt die Trivy-Rohdaten in:

```text
/var/lib/trivy/results/rootfs.json
```

`trivy_reduce.sh` erzeugt den für Monitoring und Reporting aufbereiteten Report:

```text
/var/lib/trivy/results/checkmk.json
```

Der Reducer erkennt unter anderem Distribution, Vendor-Key, Paketbackend,
Architektur, laufenden Kernel, Kernelpaket, geladene/verfügbare Kernelmodule
und Runtime-Nutzung betroffener Pakete.

Kernelzustände können beispielsweise sein:

```text
active
inactive
present_builtin
present_builtin_config
available_not_loaded
not_present
unknown
```

Die operative Klassifikation verwendet insbesondere:

```text
ACTION_REQUIRED
REVIEW
```

`trivy_threatintel.py` ergänzt `checkmk.json` um CISA KEV, EPSS
Score/Percentile und die P1--P4-Priorisierung.

```bash
/usr/local/bin/trivy_threatintel.py /var/lib/trivy/results/checkmk.json
jq '.threat_intel' /var/lib/trivy/results/checkmk.json
jq '.priority_counts, .priority_meta.signals' /var/lib/trivy/results/checkmk.json
```

`trivy_html.py` erzeugt zusätzlich einen eigenständigen, detaillierten
HTML-Report. Der Hostname wird an den Dateinamen angehängt, damit Reports
mehrerer Hosts später zentral gesammelt werden können.

Der Report liegt unter `/var/lib/trivy/results/`, zum Beispiel:

```text
/var/lib/trivy/results/trivy_report_mail.html
```

Er kann direkt mit einem Browser geöffnet oder über einen Webserver
bereitgestellt werden. Damit steht neben dem kompakten Checkmk-Service
eine ausführliche Ansicht für die Analyse der einzelnen Schwachstellen zur
Verfügung.

## 6. Wrapper ausführen

Der produktive Ablauf ist:

```text
1. trivy_scan.sh
2. trivy_reduce.sh
3. trivy_threatintel.py
4. trivy_html.py
```

Threat Intelligence ist Enrichment und soll bei einem temporären
Netzwerkfehler nicht den vorhandenen lokalen Report unbrauchbar machen.

Manueller Test:

```bash
/usr/local/bin/trivy_checkmk_wrapper.sh
echo $?
tail -100 /var/log/trivy_checkmk.log
```

Erwarteter Returncode: `0`.

Wichtige Prüfungen:

```bash
jq '{host: .host, scanner_warnings: .scanner_warnings, operational_counts: .operational_counts}' \
  /var/lib/trivy/results/checkmk.json

jq '.priority_counts' /var/lib/trivy/results/checkmk.json
jq '.threat_intel' /var/lib/trivy/results/checkmk.json
```

## 7. Regelmäßige Ausführung

Der Wrapper sollte regelmäßig als `root` laufen. Beispiel Cron alle
sechs Stunden:

```cron
0 */6 * * * root /usr/local/bin/trivy_checkmk_wrapper.sh
```

Für produktive Systeme ist ein systemd Timer vorzuziehen.

## 8. MKP `trivy_report` 1.3.0 installieren

Das MKP benötigt Checkmk `2.5.0p10` oder neuer und enthält:

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

Als Checkmk-Site-User Paket installieren/aktivieren und prüfen:

```bash
mkp list
mkp show trivy_report 1.3.0
cmk-validate-plugins
```

Die Validierung muss ohne Fehler durchlaufen.

## 9. Agent-Bakery-Regel

In Checkmk:

```text
Setup
-> Agents
-> Windows, Linux, Solaris, AIX
-> Agent rules
```

Nach der vom MKP bereitgestellten Trivy-Regel suchen, sie aktivieren und
auf die gewünschten Hosts einschränken. Danach **Bake agents** ausführen
und das neue Agentpaket verteilen.

Debian/Ubuntu:

```bash
dpkg -i check-mk-agent_*.deb
```

RHEL/Rocky/Alma:

```bash
rpm -U check-mk-agent-*.rpm
```

Typischer Pluginpfad auf dem Host:

```text
/usr/lib/check_mk_agent/plugins/trivy_report
```

Prüfen:

```bash
/usr/lib/check_mk_agent/plugins/trivy_report | head -30
```

Die Ausgabe muss mit folgender Section beginnen:

```text
<<<trivy_report:sep(0)>>>
```

## 10. Daten auf dem Checkmk-Server prüfen

```bash
cmk -d HOSTNAME | grep -A20 -B2 '<<<trivy_report'
```

Danach Service Discovery durchführen und Changes aktivieren. Für einen CLI-Test:

```bash
cmk -IIv HOSTNAME
cmk -nv HOSTNAME
```

## 11. Service-Regel `Trivy vulnerability report`

Empfohlene Ausgangskonfiguration:

| Signal | WARN | CRIT |
| --- | ---: | ---: |
| P1 -- Immediate | disabled | 1 |
| P2 -- High | 1 | disabled |
| P3 -- Normal | disabled | disabled |
| P4 -- Review | disabled | disabled |
| CISA KEV | disabled | 1 |
| Report age | 8 h | 14 h |

Damit gilt standardmäßig:

```text
P1 >= 1       -> CRIT
P2 >= 1       -> WARN
KEV >= 1      -> CRIT
Report >= 8h  -> WARN
Report >= 14h -> CRIT
```

P3 und P4 bleiben sichtbar und werden als Metriken gespeichert, lösen
aber in dieser Standardkonfiguration keinen Alarm aus.

## 12. Prioritätsmodell

**P1 -- Immediate:** höchste operative Priorität, insbesondere bei
starken Exploit-/Threat-Intelligence-Signalen und tatsächlicher Hostrelevanz.

**P2 -- High:** hohe operative Priorität, z. B. Vendor Severity `HIGH`
zusammen mit `ACTION_REQUIRED`.

**P3 -- Normal:** auf dem Host operativ relevant und `ACTION_REQUIRED`,
aber ohne P1-/P2-Eskalation.

**P4 -- Review:** Befunde ohne unmittelbare Remediation-Eskalation, die
geprüft bzw. dokumentiert werden sollen.

## 13. Vendor Severity, CVSS, KEV und EPSS

Das System trennt bewusst:

```text
CVSS
Vendor Severity
Operational Classification
Threat Intelligence
Priority
```

CVSS bleibt erhalten. Für die praktische Darstellung und Priorisierung
wird jedoch bevorzugt die Bewertung des zur Distribution passenden
Vendors verwendet. Runtime-/Kernel-Relevanz entscheidet zusätzlich, ob
ein Befund auf dem konkreten Host tatsächlich handlungsrelevant ist.
CISA KEV und EPSS ergänzen diese Bewertung um bekannte bzw.
wahrscheinliche Ausnutzung.

## 14. Checkmk-Metriken

Unter anderem werden erzeugt:

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

Severity-Metriken bleiben sichtbar, bestimmen aber nicht mehr direkt den
Servicezustand.

## 15. Funktionstest

```bash
cmk -nv HOSTNAME | grep 'Trivy Report'
```

Beispiel:

```text
Trivy Report  P1: 0, P2: 1, P3: 50, P4: 1233, KEV: 0, Report age: 2.0 h
```

Mit der empfohlenen Regel ist dies `WARN`, weil `P2 = 1`.

Effektive Parameter prüfen:

```bash
cmk -D HOSTNAME | grep trivy_report
```

Gespeicherten Zustand via Livestatus prüfen:

```bash
lq "GET services
Columns: description state hard_state plugin_output last_check
Filter: host_name = HOSTNAME
Filter: description = Trivy Report"
```

Statuswerte:

```text
0 = OK
1 = WARN
2 = CRIT
3 = UNKNOWN
```

## 16. Fehlersuche

Agentplugin lokal:

```bash
/usr/lib/check_mk_agent/plugins/trivy_report
```

JSON validieren:

```bash
jq empty /var/lib/trivy/results/checkmk.json
echo $?
```

Wrapper/Log:

```bash
/usr/local/bin/trivy_checkmk_wrapper.sh
echo $?
tail -100 /var/log/trivy_checkmk.log
```

Threat Intelligence/Priorität:

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

## 17. Netzwerkzugriff

Grundlegende Erreichbarkeit kann geprüft werden mit:

```bash
curl -I https://github.com
curl -I https://ghcr.io
curl -I https://aquasecurity.github.io
```

Ein HTTP `405` von `ghcr.io` auf einen HEAD-Request bedeutet nicht
automatisch, dass die Registry blockiert ist.

## 18. Zentrale HTML-Reports

Durch den Hostnamen im Dateinamen können Reports später zentral
gesammelt werden:

```text
reports/
  trivy_report_host01.html
  trivy_report_host02.html
  trivy_report_host03.html
```

Darauf kann später eine zentrale Übersichtsseite über alle überwachten
Hosts aufgebaut werden.

## 19. Kurzinstallation

```text
1. Trivy + jq + Python 3 installieren
2. /var/lib/trivy/results anlegen
3. trivy-host-scripts-1.3.0.tar.gz entpacken und Skripte nach /usr/local/bin kopieren
4. Wrapper testen
5. checkmk.json und HTML-Report prüfen
6. MKP trivy_report 1.3.0 installieren
7. cmk-validate-plugins
8. Agent-Bakery-Regel für Trivy erstellen
9. Agent backen und verteilen
10. <<<trivy_report>>> prüfen
11. Service Discovery
12. Trivy-Service-Regel erstellen
13. P1/P2/P3/P4/KEV/Report-age konfigurieren
14. cmk -nv HOSTNAME testen
```

## Externe Dokumentation

- Trivy Installation:
  https://trivy.dev/docs/latest/getting-started/installation/
- Checkmk Linux Agent:
  https://docs.checkmk.com/latest/en/agent_linux.html

## Hinweis

Dieses Projekt ist eine eigene Integration. Trivy und Checkmk sind
eigenständige Projekte und unterliegen ihren jeweiligen Lizenzen und
Supportbedingungen.
