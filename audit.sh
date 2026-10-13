#!/usr/bin/env bash
#
# audit.sh - Checks a Linux system against the hardening baseline and reports PASS / WARN / FAIL.
#
# It changes nothing. Run it before harden.sh to see where a system stands, and after
# to confirm the changes worked.
#
# Usage:
#   sudo ./audit.sh
#
# Exit code is the number of failed checks (0 means everything passed), so it can be
# used in other scripts or scheduled jobs.

set -uo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo $0"
    exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release
case " ${ID} ${ID_LIKE:-} " in
    *" ubuntu "*|*" debian "*) FAMILY=debian ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*) FAMILY=rhel ;;
    *) echo "Unsupported distribution: ${PRETTY_NAME:-unknown}"; exit 1 ;;
esac

pass=0; warns=0; fails=0
PASS() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; pass=$((pass + 1)); }
WARN() { printf '  \033[33mWARN\033[0m  %s\n' "$1"; warns=$((warns + 1)); }
FAIL() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fails=$((fails + 1)); }
section() { printf '\n\033[1m%s\033[0m\n' "$1"; }

echo "Security audit: $(hostname) - ${PRETTY_NAME} - $(date '+%Y-%m-%d %H:%M')"

# ---------------------------------------------------------------------------
section "Updates"
# ---------------------------------------------------------------------------
if [[ $FAMILY == debian ]]; then
    apt-get update -qq >/dev/null 2>&1
    pending=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
    [[ $pending -eq 0 ]] && PASS "No pending updates" || FAIL "$pending packages need updating"
    if grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then
        PASS "Automatic security updates are on"
    else
        FAIL "Automatic security updates are off"
    fi
else
    dnf check-update -q >/dev/null 2>&1
    [[ $? -eq 100 ]] && FAIL "Packages need updating (run: dnf upgrade)" || PASS "No pending updates"
    systemctl is-enabled -q dnf-automatic.timer 2>/dev/null \
        && PASS "Automatic updates are on" || FAIL "Automatic updates are off"
fi

# ---------------------------------------------------------------------------
section "SSH"
# ---------------------------------------------------------------------------
# 'sshd -T' prints the settings SSH is actually using, after all config files are combined.
ssh_conf=$(sshd -T 2>/dev/null)
ssh_get() { awk -v k="$1" '$1 == k {print $2; exit}' <<<"$ssh_conf"; }

[[ $(ssh_get permitrootlogin) == "no" ]] \
    && PASS "Root login over SSH is disabled" || FAIL "Root login over SSH is allowed"

tries=$(ssh_get maxauthtries)
[[ ${tries:-6} -le 3 ]] \
    && PASS "MaxAuthTries is $tries" || FAIL "MaxAuthTries is ${tries:-6} (should be 3 or less)"

[[ $(ssh_get permitemptypasswords) == "no" ]] \
    && PASS "Empty passwords are not accepted" || FAIL "Empty passwords are accepted"

[[ $(ssh_get passwordauthentication) == "no" ]] \
    && PASS "SSH requires keys (password login off)" \
    || WARN "SSH password login is on (consider key-only login)"

# ---------------------------------------------------------------------------
section "Firewall"
# ---------------------------------------------------------------------------
if [[ $FAMILY == debian ]]; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        PASS "UFW firewall is active"
        ufw status verbose | grep -q "deny (incoming)" \
            && PASS "Incoming traffic is denied by default" \
            || FAIL "Incoming traffic is not denied by default"
    else
        FAIL "UFW firewall is not active"
    fi
else
    if systemctl is-active -q firewalld; then
        PASS "firewalld is active"
        info_services=$(firewall-cmd --list-services)
        PASS "Allowed services: ${info_services:-none}"
    else
        FAIL "firewalld is not active"
    fi
fi

# ---------------------------------------------------------------------------
section "Accounts and least privilege"
# ---------------------------------------------------------------------------
empty=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
[[ -z $empty ]] && PASS "No accounts with empty passwords" || FAIL "Accounts with empty passwords: $empty"

uid0=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
[[ -z $uid0 ]] && PASS "Only root has UID 0" || FAIL "Other accounts with root UID 0: $uid0"

admin_group=sudo
[[ $FAMILY == rhel ]] && admin_group=wheel
admins=$(getent group "$admin_group" | cut -d: -f4)
WARN "Review admin users in '$admin_group': ${admins:-none}"

max_days=$(awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs)
[[ ${max_days:-99999} -le 90 ]] \
    && PASS "Password maximum age is $max_days days" \
    || FAIL "Password maximum age is ${max_days:-not set} days (should be 90 or less)"

# ---------------------------------------------------------------------------
section "Mandatory access control"
# ---------------------------------------------------------------------------
if [[ $FAMILY == debian ]]; then
    if command -v aa-status >/dev/null && aa-status --enabled 2>/dev/null; then
        PASS "AppArmor is enabled ($(aa-status --enforced 2>/dev/null) profiles enforcing)"
    else
        FAIL "AppArmor is not enabled"
    fi
else
    mode=$(getenforce 2>/dev/null || echo Unknown)
    [[ $mode == "Enforcing" ]] && PASS "SELinux is enforcing" || FAIL "SELinux is $mode"
fi

# ---------------------------------------------------------------------------
printf '\n\033[1mSummary:\033[0m %d passed, %d warnings, %d failed\n' "$pass" "$warns" "$fails"
exit "$fails"
