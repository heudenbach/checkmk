#!/bin/bash

set -u

INPUT="/var/lib/trivy/results/rootfs.json"
OUTPUT="/var/lib/trivy/results/checkmk.json"
TMP="${OUTPUT}.tmp"

if [[ ! -f "$INPUT" ]]; then
    echo "Input file not found: $INPUT" >&2
    exit 1
fi

#
# ------------------------------------------------------------
# Operating system
# ------------------------------------------------------------
#

OS_ID="unknown"
OS_NAME="Unknown Linux"
OS_VERSION="unknown"

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release

    OS_ID="${ID:-unknown}"
    OS_NAME="${NAME:-Unknown Linux}"
    OS_VERSION="${VERSION_ID:-unknown}"
fi

case "$OS_ID" in
    ubuntu)
        VENDOR_KEY="ubuntu"
        ;;
    debian)
        VENDOR_KEY="debian"
        ;;
    rhel)
        VENDOR_KEY="redhat"
        ;;
    rocky)
        VENDOR_KEY="rocky"
        ;;
    almalinux)
        VENDOR_KEY="alma"
        ;;
    ol)
        VENDOR_KEY="oracle-oval"
        ;;
    amzn)
        VENDOR_KEY="amazon"
        ;;
    azurelinux|mariner)
        VENDOR_KEY="cbl-mariner"
        ;;
    *)
        VENDOR_KEY="$OS_ID"
        ;;
esac

#
# ------------------------------------------------------------
# Host / kernel runtime information
# ------------------------------------------------------------
#

RUNNING_KERNEL="$(uname -r 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"
KERNEL_CONFIG="/boot/config-${RUNNING_KERNEL}"

#
# ------------------------------------------------------------
# Loaded kernel modules
# ------------------------------------------------------------
#

LOADED_MODULES_JSON="$(
    lsmod 2>/dev/null \
        | awk 'NR > 1 {print $1}' \
        | tr '-' '_' \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u \
        | jq -R -s '
            split("\n")
            | map(select(length > 0))
        '
)"

#
# ------------------------------------------------------------
# Available modules for the running kernel
# ------------------------------------------------------------
#

AVAILABLE_MODULES_JSON="$(
    if [[ -d "/lib/modules/${RUNNING_KERNEL}" ]]; then

        find "/lib/modules/${RUNNING_KERNEL}" \
            -type f \
            \( \
                -name '*.ko' \
                -o -name '*.ko.xz' \
                -o -name '*.ko.gz' \
                -o -name '*.ko.zst' \
            \) \
            -printf '%f\n' 2>/dev/null \
        | sed -E \
            -e 's/\.ko(\.(xz|gz|zst))?$//' \
            -e 's/-/_/g' \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u \
        | jq -R -s '
            split("\n")
            | map(select(length > 0))
        '

    else
        echo '[]'
    fi
)"

#
# ------------------------------------------------------------
# Kernel CONFIG_xxx=m
# ------------------------------------------------------------
#

CONFIG_MODULES_JSON="$(
    if [[ -r "$KERNEL_CONFIG" ]]; then

        grep '=m$' "$KERNEL_CONFIG" 2>/dev/null \
            | cut -d= -f1 \
            | sed 's/^CONFIG_//' \
            | tr '[:upper:]' '[:lower:]' \
            | sort -u \
            | jq -R -s '
                split("\n")
                | map(select(length > 0))
            '

    else
        echo '[]'
    fi
)"

#
# ------------------------------------------------------------
# Kernel CONFIG_xxx=y
# ------------------------------------------------------------
#

CONFIG_BUILTIN_JSON="$(
    if [[ -r "$KERNEL_CONFIG" ]]; then

        grep '=y$' "$KERNEL_CONFIG" 2>/dev/null \
            | cut -d= -f1 \
            | sed 's/^CONFIG_//' \
            | tr '[:upper:]' '[:lower:]' \
            | sort -u \
            | jq -R -s '
                split("\n")
                | map(select(length > 0))
            '

    else
        echo '[]'
    fi
)"

#
# ------------------------------------------------------------
# Installed packages
# ------------------------------------------------------------
#

INSTALLED_PACKAGES_JSON="$(
    if command -v dpkg-query >/dev/null 2>&1; then

        dpkg-query -W -f='${binary:Package}\n' 2>/dev/null \
            | sed 's/:.*$//' \
            | sort -u \
            | jq -R -s '
                split("\n")
                | map(select(length > 0))
            '

    elif command -v rpm >/dev/null 2>&1; then

        rpm -qa --qf '%{NAME}\n' 2>/dev/null \
            | sort -u \
            | jq -R -s '
                split("\n")
                | map(select(length > 0))
            '

    else
        echo '[]'
    fi
)"

#
# ------------------------------------------------------------
# Runtime-used packages
# ------------------------------------------------------------
#
# Runtime evidence means:
#
#   - executable belongs to a process running >= 60 seconds
#   OR
#   - file/library from package is mapped by such a process
#
# The 60 second threshold prevents the reducer itself
# (jq, sort, awk, dpkg-query, etc.) from making packages
# look operationally active.
#

RUNTIME_PACKAGES_JSON="$(
    {
        #
        # Running executables
        #

        for proc in /proc/[0-9]*; do

            pid="${proc##*/}"

            etimes="$(
                ps -o etimes= -p "$pid" 2>/dev/null \
                    | tr -d ' '
            )"

            [[ "$etimes" =~ ^[0-9]+$ ]] || continue
            (( etimes >= 60 )) || continue

            exe="$(
                readlink -f "$proc/exe" 2>/dev/null
            )" || continue

            [[ -n "$exe" ]] || continue

            dpkg-query -S "$exe" 2>/dev/null \
                | head -1 \
                | cut -d: -f1
        done

        #
        # Files / libraries mapped by running processes
        #

        for proc in /proc/[0-9]*; do

            pid="${proc##*/}"

            etimes="$(
                ps -o etimes= -p "$pid" 2>/dev/null \
                    | tr -d ' '
            )"

            [[ "$etimes" =~ ^[0-9]+$ ]] || continue
            (( etimes >= 60 )) || continue

            [[ -r "$proc/maps" ]] || continue

            awk '
                $6 ~ /^\// {
                    print $6
                }
            ' "$proc/maps" 2>/dev/null

        done \
        | sort -u \
        | while IFS= read -r file; do

            dpkg-query -S "$file" 2>/dev/null \
                | head -1 \
                | cut -d: -f1

        done

    } \
    | sed 's/:.*$//' \
    | grep -v '^$' \
    | sort -u \
    | jq -R -s '
        split("\n")
        | map(select(length > 0))
    '
)"

#
# ------------------------------------------------------------
# Reducer
# ------------------------------------------------------------
#

jq \
    --arg os_id "$OS_ID" \
    --arg os_name "$OS_NAME" \
    --arg os_version "$OS_VERSION" \
    --arg vendor_key "$VENDOR_KEY" \
    --arg running_kernel "$RUNNING_KERNEL" \
    --arg arch "$ARCH" \
    --argjson loaded_modules "$LOADED_MODULES_JSON" \
    --argjson available_modules "$AVAILABLE_MODULES_JSON" \
    --argjson config_modules "$CONFIG_MODULES_JSON" \
    --argjson config_builtin "$CONFIG_BUILTIN_JSON" \
    --argjson installed_packages "$INSTALLED_PACKAGES_JSON" \
    --argjson runtime_packages "$RUNTIME_PACKAGES_JSON" \
'
#
# ------------------------------------------------------------
# Severity helpers
# ------------------------------------------------------------
#

def severity_rank:

    if . == "CRITICAL" then 5
    elif . == "HIGH" then 4
    elif . == "MEDIUM" then 3
    elif . == "LOW" then 2
    elif . == "UNKNOWN" then 1
    else 0
    end;

#
# Trivy VendorSeverity is an enum, not CVSS:
#
# 4 = CRITICAL
# 3 = HIGH
# 2 = MEDIUM
# 1 = LOW
# 0 = UNKNOWN
#

def vendor_severity_name:

    if . == 4 then "CRITICAL"
    elif . == 3 then "HIGH"
    elif . == 2 then "MEDIUM"
    elif . == 1 then "LOW"
    elif . == 0 then "UNKNOWN"
    else null
    end;

#
# ------------------------------------------------------------
# Package/runtime helpers
# ------------------------------------------------------------
#

def package_installed($p):
    ($installed_packages | index($p)) != null;

def package_runtime_used($p):
    ($runtime_packages | index($p)) != null;

#
# ------------------------------------------------------------
# Module helpers
# ------------------------------------------------------------
#

def normalize_module:

    ascii_downcase
    | gsub("-"; "_");

def module_loaded($m):

    ($m | normalize_module) as $n
    | ($loaded_modules | index($n)) != null;

def module_available($m):

    ($m | normalize_module) as $n
    | ($available_modules | index($n)) != null;

def config_symbol($component):

    $component
    | ascii_downcase
    | gsub("-"; "_");

def config_module($component):

    config_symbol($component) as $c
    | ($config_modules | index($c)) != null;

def config_builtin($component):

    config_symbol($component) as $c
    | ($config_builtin | index($c)) != null;

#
# ------------------------------------------------------------
# Kernel package detection
# ------------------------------------------------------------
#

def is_kernel_package:

    (.package // "") as $p
    |
    (
        ($p | test("^linux-image-"))
        or
        ($p | test("^linux-modules-"))
        or
        ($p | test("^linux-modules-extra-"))
        or
        ($p | test("^linux-headers-"))
        or
        ($p | test("^linux-tools-"))
        or
        ($p == "linux-tools-common")
        or
        ($p == "linux-libc-dev")
    );

def is_kernel_support_package:

    (.package // "") as $p
    |
    (
        ($p | test("^linux-headers-"))
        or
        ($p | test("^linux-tools-"))
        or
        ($p == "linux-tools-common")
        or
        ($p == "linux-libc-dev")
    );

def is_kernel_runtime_package:

    (.package // "") as $p
    |
    (
        ($p | test("^linux-image-"))
        or
        ($p | test("^linux-modules-"))
        or
        ($p | test("^linux-modules-extra-"))
    );

#
# ------------------------------------------------------------
# Kernel ABI helpers
# ------------------------------------------------------------
#

def kernel_abi_from_package:

    (.package // "") as $p
    |
    (
        [
            $p
            | capture(
                "(?<abi>[0-9]+\\.[0-9]+\\.[0-9]+-[0-9]+)"
            )?
            | .abi
        ]
        | first // null
    );

def running_kernel_abi:

    (
        [
            $running_kernel
            | capture(
                "(?<abi>[0-9]+\\.[0-9]+\\.[0-9]+-[0-9]+)"
            )?
            | .abi
        ]
        | first // null
    );

def is_old_kernel:

    kernel_abi_from_package as $pkg
    | running_kernel_abi as $run
    |
    (
        $pkg != null
        and
        $run != null
        and
        $pkg != $run
    );

#
# ------------------------------------------------------------
# Architecture detection
# ------------------------------------------------------------
#

def title_architecture:

    (.title // "") as $t
    |

    if ($t | test("(^|:) *riscv *:"; "i"))
    then "riscv"

    elif ($t | test("(^|:) *arm64 *:"; "i"))
    then "arm64"

    elif ($t | test("(^|:) *arm *:"; "i"))
    then "arm"

    elif ($t | test("(^|:) *powerpc *:"; "i"))
    then "powerpc"

    elif ($t | test("(^|:) *ppc *:"; "i"))
    then "powerpc"

    elif ($t | test("(^|:) *s390 *:"; "i"))
    then "s390"

    elif ($t | test("(^|:) *mips *:"; "i"))
    then "mips"

    elif ($t | test("(^|:) *x86 *:"; "i"))
    then "x86"

    else null
    end;

def host_architecture_family:

    if ($arch | test("^x86_64$|^amd64$"; "i"))
    then "x86"

    elif ($arch | test("^aarch64$|^arm64$"; "i"))
    then "arm64"

    elif ($arch | test("^arm"; "i"))
    then "arm"

    elif ($arch | test("riscv"; "i"))
    then "riscv"

    elif ($arch | test("ppc|powerpc"; "i"))
    then "powerpc"

    elif ($arch | test("s390"; "i"))
    then "s390"

    else $arch
    end;

def architecture_mismatch:

    title_architecture as $ta
    | host_architecture_family as $ha
    |
    (
        $ta != null
        and
        $ha != null
        and
        $ta != $ha
    );

#
# ------------------------------------------------------------
# Kernel component extraction
# ------------------------------------------------------------
#

def kernel_component_candidate:

    (.title // "") as $t

    | ($t | split(":")) as $parts

    | (
        $parts
        | map(
            gsub("^ +| +$"; "")
        )
    ) as $p

    |

    (
        if ($p | length) < 3 then

            null

        #
        # kernel: KVM: x86: ...
        #

        elif (
            ($p[1] // "")
            | test("^KVM$"; "i")
        )
        then

            "kvm"

        #
        # kernel: net: ethernet: DRIVER: ...
        #

        elif (
            (($p[1] // "") | ascii_downcase) == "net"
            and
            (($p[2] // "") | ascii_downcase) == "ethernet"
            and
            ($p | length) >= 4
        )
        then

            ($p[3] | ascii_downcase)

        #
        # kernel: net: usb: DRIVER: ...
        #

        elif (
            (($p[1] // "") | ascii_downcase) == "net"
            and
            (($p[2] // "") | ascii_downcase) == "usb"
            and
            ($p | length) >= 4
        )
        then

            ($p[3] | ascii_downcase)

        #
        # kernel: netfilter: COMPONENT: ...
        #

        elif (
            (($p[1] // "") | ascii_downcase) == "netfilter"
            and
            ($p | length) >= 3
        )
        then

            ($p[2] | ascii_downcase)

        #
        # kernel: net: COMPONENT: ...
        #

        elif (
            (($p[1] // "") | ascii_downcase) == "net"
            and
            ($p | length) >= 3
        )
        then

            ($p[2] | ascii_downcase)

        #
        # Generic:
        # kernel: subsystem: component: ...
        #

        elif ($p | length) >= 3
        then

            ($p[2] | ascii_downcase)

        else

            null

        end
    ) as $candidate

    |

    if $candidate == null then

        null

    elif (
        [
            "x86",
            "arm",
            "arm64",
            "riscv",
            "ethernet",
            "usb",
            "input",
            "pm",
            "crypto",
            "quota",
            "net",
            "mm",
            "kernel",
            "linux",
            "memory-failure"
        ]
        | index($candidate)
    ) != null
    then

        null

    elif (
        ($candidate | test("^[a-zA-Z0-9_-]+$"))
        and
        (($candidate | length) >= 2)
        and
        (($candidate | length) <= 40)
    )
    then

        $candidate

    else

        null

    end;

#
# ------------------------------------------------------------
# Known userspace/kernel relationships
# ------------------------------------------------------------
#

def userspace_package_for_component($component):

    if $component == "openvswitch"
    then "openvswitch-switch"
    else null
    end;

#
# ------------------------------------------------------------
# Kernel component runtime assessment
# ------------------------------------------------------------
#

def assess_kernel_component($component):

    if $component == null then

        {
            state: "unknown",
            reason:
                "Kernel component could not be determined safely"
        }

    elif module_loaded($component) then

        {
            state: "active",
            reason:
                (
                    "Kernel module "
                    + $component
                    + " is loaded"
                )
        }

    elif config_builtin($component) then

        {
            state: "present_builtin",
            reason:
                (
                    "Kernel component "
                    + $component
                    + " is built into the running kernel"
                )
        }

    elif module_available($component) then

        userspace_package_for_component($component) as $upkg

        |

        if (
            $upkg != null
            and
            package_installed($upkg)
        )
        then

            {
                state: "potentially_active",
                reason:
                    (
                        "Kernel module "
                        + $component
                        + " is available and userspace package "
                        + $upkg
                        + " is installed"
                    )
            }

        elif $upkg != null
        then

            {
                state: "inactive",
                reason:
                    (
                        "Kernel module "
                        + $component
                        + " is available but not loaded; userspace package "
                        + $upkg
                        + " is not installed"
                    )
            }

        else

            {
                state: "available_not_loaded",
                reason:
                    (
                        "Kernel module "
                        + $component
                        + " is available but not loaded"
                    )
            }

        end

    elif config_module($component) then

        {
            state: "available_not_loaded",
            reason:
                (
                    "Kernel CONFIG_"
                    + (
                        $component
                        | ascii_upcase
                        | gsub("-"; "_")
                    )
                    + "=m exists but module is not loaded"
                )
        }

    else

        {
            state: "not_present",
            reason:
                (
                    "Kernel component "
                    + $component
                    + " is neither loaded, available nor enabled in the running kernel configuration"
                )
        }

    end;

#
# ------------------------------------------------------------
# Read Trivy findings
# ------------------------------------------------------------
#

[
    .Results[]?
    | .Vulnerabilities[]?
    |
    {
        id:
            .VulnerabilityID,

        package:
            (.PkgName // null),

        installed_version:
            (.InstalledVersion // null),

        fixed_version:
            (.FixedVersion // null),

        path:
            (.PkgPath // null),

        title:
            (.Title // null),

        description:
            (.Description // null),

        status:
            (.Status // null),

        severity:
            (.Severity // null),

        severity_source:
            (.SeveritySource // null),

        vendor_severity: (
            if .VendorSeverity == null
            then
                null
            else
                .VendorSeverity[$vendor_key] // null
            end
        ),

        primary_url:
            (.PrimaryURL // null),

        data_source: (
            if .DataSource == null
            then
                null
            else
                {
                    id:
                        (.DataSource.ID // null),

                    name:
                        (.DataSource.Name // null),

                    url:
                        (.DataSource.URL // null)
                }
            end
        ),

        score: (
            [
                (
                    .CVSS // {}
                    | to_entries[]?
                    | .value.V40Score?
                ),
                (
                    .CVSS // {}
                    | to_entries[]?
                    | .value.V3Score?
                ),
                (
                    .CVSS // {}
                    | to_entries[]?
                    | .value.V2Score?
                )
            ]
            | map(
                select(. != null)
            )
            | if length > 0
              then max
              else null
              end
        )
    }

    |
    . + {
        kernel_package:
            is_kernel_package,

        kernel_support_package:
            is_kernel_support_package,

        kernel_runtime_package:
            is_kernel_runtime_package,

        kernel_abi:
            kernel_abi_from_package,

        old_kernel:
            is_old_kernel
    }
]

#
# ------------------------------------------------------------
# One CVE = one object
# ------------------------------------------------------------
#

| group_by(.id)

| map(

    . as $group

    #
    # Kernel CVE?
    #

    | (
        [
            $group[]
            | select(
                .kernel_package == true
            )
        ]
        | length > 0
    ) as $is_kernel

    #
    # Highest severity
    #

    | (
        $group
        | map(.severity)
        | map(
            select(. != null)
        )
        | sort_by(severity_rank)
        | reverse
        | first // null
    ) as $severity

    #
    # Vendor severity
    #

    | (
        $group
        | map(.vendor_severity)
        | map(
            select(. != null)
        )
        | if length > 0
          then max
          else null
          end
    ) as $vendor_severity

    #
    # Fixed versions
    #

    | (
        $group
        | map(.fixed_version)
        | map(
            select(
                . != null
                and
                . != ""
            )
        )
        | unique
    ) as $fixed_versions

    | (
        $fixed_versions
        | length > 0
    ) as $fix_available

    #
    # Current kernel runtime findings
    #

    | (
        [
            $group[]
            | select(
                .kernel_runtime_package == true
                and
                .old_kernel == false
            )
        ]
        | length
    ) as $current_kernel_runtime_count

    #
    # Old kernel findings
    #

    | (
        [
            $group[]
            | select(
                .old_kernel == true
            )
        ]
        | length
    ) as $old_kernel_count

    #
    # Kernel support packages
    #

    | (
        [
            $group[]
            | select(
                .kernel_support_package == true
            )
        ]
        | length
    ) as $support_count

    #
    # Representative title
    #

    | (
        $group
        | map(.title)
        | map(
            select(
                . != null
                and
                . != ""
            )
        )
        | first // null
    ) as $title

    #
    # Architecture
    #

    | (
        { title: $title }
        | title_architecture
    ) as $title_arch

    | (
        { title: $title }
        | architecture_mismatch
    ) as $arch_mismatch

    #
    # Kernel component
    #

    | (
        { title: $title }
        | kernel_component_candidate
    ) as $kernel_component

    | (
        if $is_kernel
        then
            assess_kernel_component(
                $kernel_component
            )
        else
            null
        end
    ) as $kernel_runtime

    #
    # Runtime-used packages belonging to this CVE
    #

    | (
        [
            $group[]
            | .package
            | select(
                . != null
                and
                package_runtime_used(.)
            )
        ]
        | unique
    ) as $runtime_used_packages

    #
    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------
    #

    | (

        #
        # Normal Ubuntu package
        #

        if ($is_kernel | not) then

            if (
                (
                    [
                        $group[]
                        | select(
                            .status == "affected"
                        )
                    ]
                    | length
                ) > 0
                and
                (
                    $runtime_used_packages
                    | length
                ) > 0
            )
            then

                {
                    classification:
                        "ACTION_REQUIRED",

                    relevance:
                        "runtime_used",

                    reason:
                        (
                            "Affected package is currently used by running processes: "
                            + (
                                $runtime_used_packages
                                | join(", ")
                            )
                        ),

                    remediation_required:
                        true
                }

            elif (
                [
                    $group[]
                    | select(
                        .status == "affected"
                    )
                ]
                | length > 0
            )
            then

                {
                    classification:
                        "REVIEW",

                    relevance:
                        "installed_not_runtime_detected",

                    reason:
                        "Affected package is installed, but no current runtime usage was detected",

                    remediation_required:
                        false
                }

            else

                {
                    classification:
                        "REVIEW",

                    relevance:
                        "unknown",

                    reason:
                        "Package status could not be classified automatically",

                    remediation_required:
                        false
                }

            end

        #
        # Wrong architecture
        #

        elif $arch_mismatch
        then

            {
                classification:
                    "SUPPRESSED",

                relevance:
                    "architecture_not_applicable",

                reason:
                    (
                        "CVE targets architecture "
                        + ($title_arch // "unknown")
                        + ", host architecture is "
                        + $arch
                    ),

                remediation_required:
                    false
            }

        #
        # Only old/supporting kernel packages
        #

        elif (
            $current_kernel_runtime_count == 0
            and
            (
                $old_kernel_count
                + $support_count
            ) == (
                $group
                | length
            )
        )
        then

            {
                classification:
                    "SUPPRESSED",

                relevance:
                    "old_or_supporting_kernel_packages_only",

                reason:
                    "CVE is represented only by supporting packages or a non-running kernel ABI",

                remediation_required:
                    false
            }

        #
        # Component not present
        #

        elif (
            $kernel_runtime.state
            == "not_present"
        )
        then

            {
                classification:
                    "SUPPRESSED",

                relevance:
                    "kernel_component_not_present",

                reason:
                    $kernel_runtime.reason,

                remediation_required:
                    false
            }

        #
        # Component present but inactive
        #

        elif (
            $kernel_runtime.state
            == "inactive"
        )
        then

            {
                classification:
                    "SUPPRESSED",

                relevance:
                    "kernel_component_inactive",

                reason:
                    $kernel_runtime.reason,

                remediation_required:
                    false
            }

        #
        # Loaded or potentially active component
        #

        elif (
            $kernel_runtime.state == "active"
            or
            $kernel_runtime.state == "potentially_active"
        )
        then

            {
                classification:
                    "ACTION_REQUIRED",

                relevance:
                    $kernel_runtime.state,

                reason:
                    $kernel_runtime.reason,

                remediation_required:
                    true
            }

        #
        # Built-in, available but unused, unknown etc.
        #

        else

            {
                classification:
                    "REVIEW",

                relevance:
                    (
                        $kernel_runtime.state
                        // "unknown"
                    ),

                reason:
                    (
                        $kernel_runtime.reason
                        //
                        "Kernel CVE affects running kernel but runtime relevance cannot be safely determined"
                    ),

                remediation_required:
                    false
            }

        end

    ) as $assessment

    #
    # --------------------------------------------------------
    # Final CVE object
    # --------------------------------------------------------
    #

    | {
        id:
            $group[0].id,

        category:
            (
                if $is_kernel
                then "kernel"
                else "package"
                end
            ),

        score: (
            $group
            | map(.score)
            | map(
                select(. != null)
            )
            | if length > 0
              then max
              else null
              end
        ),

        title:
            $title,

        status: (
            $group
            | map(.status)
            | map(
                select(
                    . != null
                    and
                    . != ""
                )
            )
            | first // null
        ),

        severity:
            $severity,

        severity_source: (
            $group
            | map(.severity_source)
            | map(
                select(
                    . != null
                    and
                    . != ""
                )
            )
            | first // null
        ),

        vendor_severity:
            $vendor_severity,

        vendor_severity_name:
            (
                $vendor_severity
                | vendor_severity_name
            ),

        primary_url: (
            $group
            | map(.primary_url)
            | map(
                select(
                    . != null
                    and
                    . != ""
                )
            )
            | first // null
        ),

        data_source: (
            $group
            | map(.data_source)
            | map(
                select(. != null)
            )
            | first // null
        ),

        classification:
            $assessment.classification,

        relevance:
            $assessment.relevance,

        reason:
            $assessment.reason,

        runtime_used_packages:
            $runtime_used_packages,

        kernel: (
            if $is_kernel
            then

                {
                    component:
                        $kernel_component,

                    title_architecture:
                        $title_arch,

                    host_architecture:
                        $arch,

                    runtime:
                        $kernel_runtime,

                    current_kernel_runtime_findings:
                        $current_kernel_runtime_count,

                    old_kernel_findings:
                        $old_kernel_count,

                    supporting_package_findings:
                        $support_count
                }

            else
                null
            end
        ),

        remediation: {

            required:
                $assessment.remediation_required,

            fix_available:
                $fix_available,

            fixed_versions:
                $fixed_versions
        },

        findings: (

            $group

            | map({

                package,
                installed_version,
                fixed_version,
                path,

                kernel_package,
                kernel_support_package,
                kernel_runtime_package,
                kernel_abi,
                old_kernel

            })

            | unique
        )
    }
)

#
# ------------------------------------------------------------
# Sort
# ------------------------------------------------------------
#

| sort_by(

    (
        if .classification == "ACTION_REQUIRED"
        then 3

        elif .classification == "REVIEW"
        then 2

        else 1
        end
    ),

    (.vendor_severity // -1),

    (.score // -1)
)

| reverse

| . as $cves

#
# ------------------------------------------------------------
# Final output JSON
# ------------------------------------------------------------
#

| {

    generated:
        (
            now
            | todate
        ),

    host: {

        os_family:
            $os_id,

        os_name:
            $os_name,

        os_version:
            $os_version,

        vendor_key:
            $vendor_key,

        architecture:
            $arch,

        running_kernel:
            $running_kernel,

        loaded_kernel_modules:
            $loaded_modules,

        loaded_kernel_modules_count:
            (
                $loaded_modules
                | length
            ),

        available_kernel_modules_count:
            (
                $available_modules
                | length
            ),

        runtime_packages_count:
            (
                $runtime_packages
                | length
            )
    },

    #
    # Compatibility counts
    #

    counts: {

        score_9_plus:
            (
                [
                    $cves[]
                    | select(
                        .score != null
                        and
                        .score >= 9
                    )
                ]
                | length
            ),

        score_7_to_8_99:
            (
                [
                    $cves[]
                    | select(
                        .score != null
                        and
                        .score >= 7
                        and
                        .score < 9
                    )
                ]
                | length
            ),

        score_0_to_6_99:
            (
                [
                    $cves[]
                    | select(
                        .score != null
                        and
                        .score < 7
                    )
                ]
                | length
            ),

        unknown:
            (
                [
                    $cves[]
                    | select(
                        .score == null
                    )
                ]
                | length
            )
    },

    #
    # Operational counts
    #

    operational_counts: {

        total:
            (
                $cves
                | length
            ),

        action_required:
            (
                [
                    $cves[]
                    | select(
                        .classification
                        == "ACTION_REQUIRED"
                    )
                ]
                | length
            ),

        review:
            (
                [
                    $cves[]
                    | select(
                        .classification
                        == "REVIEW"
                    )
                ]
                | length
            ),

        suppressed:
            (
                [
                    $cves[]
                    | select(
                        .classification
                        == "SUPPRESSED"
                    )
                ]
                | length
            ),

        remediation_required:
            (
                [
                    $cves[]
                    | select(
                        .remediation.required
                        == true
                    )
                ]
                | length
            ),

        fix_available:
            (
                [
                    $cves[]
                    | select(
                        .remediation.fix_available
                        == true
                    )
                ]
                | length
            ),

        kernel: {

            total:
                (
                    [
                        $cves[]
                        | select(
                            .category == "kernel"
                        )
                    ]
                    | length
                ),

            action_required:
                (
                    [
                        $cves[]
                        | select(
                            .category == "kernel"
                            and
                            .classification
                            == "ACTION_REQUIRED"
                        )
                    ]
                    | length
                ),

            review:
                (
                    [
                        $cves[]
                        | select(
                            .category == "kernel"
                            and
                            .classification
                            == "REVIEW"
                        )
                    ]
                    | length
                ),

            suppressed:
                (
                    [
                        $cves[]
                        | select(
                            .category == "kernel"
                            and
                            .classification
                            == "SUPPRESSED"
                        )
                    ]
                    | length
                )
        },

        packages: {

            total:
                (
                    [
                        $cves[]
                        | select(
                            .category == "package"
                        )
                    ]
                    | length
                ),

            action_required:
                (
                    [
                        $cves[]
                        | select(
                            .category == "package"
                            and
                            .classification
                            == "ACTION_REQUIRED"
                        )
                    ]
                    | length
                ),

            review:
                (
                    [
                        $cves[]
                        | select(
                            .category == "package"
                            and
                            .classification
                            == "REVIEW"
                        )
                    ]
                    | length
                ),

            suppressed:
                (
                    [
                        $cves[]
                        | select(
                            .category == "package"
                            and
                            .classification
                            == "SUPPRESSED"
                        )
                    ]
                    | length
                )
        }
    },

    cves:
        $cves
}
' "$INPUT" > "$TMP"

RC=$?

if [[ $RC -ne 0 ]]; then
    echo "Failed to reduce Trivy JSON" >&2
    rm -f "$TMP"
    exit 1
fi

if ! jq empty "$TMP" >/dev/null 2>&1; then
    echo "Reducer produced invalid JSON" >&2
    rm -f "$TMP"
    exit 1
fi

mv "$TMP" "$OUTPUT"

echo "Reduced Trivy result written to: $OUTPUT"
echo "Operating system: $OS_NAME $OS_VERSION"
echo "Running kernel: $RUNNING_KERNEL"
echo "Architecture: $ARCH"
echo

jq -r '
.operational_counts
|
"TOTAL=\(.total)
ACTION_REQUIRED=\(.action_required)
REVIEW=\(.review)
SUPPRESSED=\(.suppressed)
REMEDIATION_REQUIRED=\(.remediation_required)
FIX_AVAILABLE=\(.fix_available)

KERNEL:
  total=\(.kernel.total)
  action=\(.kernel.action_required)
  review=\(.kernel.review)
  suppressed=\(.kernel.suppressed)

PACKAGES:
  total=\(.packages.total)
  action=\(.packages.action_required)
  review=\(.packages.review)
  suppressed=\(.packages.suppressed)"
' "$OUTPUT"

exit 0