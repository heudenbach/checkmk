First, install Trivy on your Host(s) Example Ubuntu:

sudo apt-get update
sudo apt-get install -y wget gnupg

wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list

sudo apt-get update
sudo apt-get install -y trivy

After this, configure your Trivy to Run


The Scripts i provide, Scan the Host with the exception of:
cifs, smb3, nfs, nfs4, tmpfs

The Full Trivy Report will be available as json under path:
/var/lib/trivy/results/rootfs.json

And the Filtered Report for the CMK-Plugin will be under path:
/var/lib/trivy/results/checkmk.json

The Filtered Report will contain:
CVE; CVSS; Pakage; Installed/Fixed Version and Location

The Filtered Report is generatet with the trivy_reduce.sh Script

The trivy_wrapper.sh executes first the trivy.sh, then the trivy_reduce.sh

place the three trivy scripts at /usr/local/bin/

and att to your crontab:
0 */6 * * * flock -n /var/run/trivy_checkmk.lock /usr/local/bin/trivy_wrapper.sh

This executes all 6 hours - flock checks so that no 2 scans overlap



Trivy Vulnerability Report for Checkmk

Requirements
 ├─ Checkmk >= 2.5.0p10
 ├─ Trivy installed on monitored host
 ├─ Periodic Trivy scan
 └─ /var/lib/trivy/results/checkmk.json

Host
 Trivy
   ↓
 rootfs.json
   ↓ reducer
 checkmk.json
   ↓
 Checkmk Agent Plugin
   ↓
 <<<trivy_report>>>
   ↓
 Checkmk Server
   ├─ Agent Section
   ├─ Check Plugin
   ├─ Ruleset
   └─ Metrics

