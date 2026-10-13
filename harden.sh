#!/usr/bin/env bash
#
# harden.sh - Applies a baseline security configuration to Ubuntu or Red Hat-family Linux.
#
# What it does, in order:
#   1. Installs updates and turns on automatic security updates
#   2. Hardens SSH (no root login, fewer login attempts, idle timeout)
#   3. Turns on the firewall and allows only SSH in
#   4. Reviews accounts for least privilege (admin users, empty passwords, password aging)
#   5. Turns on mandatory access control (AppArmor on Ubuntu, SELinux on Red Hat)
#
# Usage:
#   sudo ./harden.sh                          # apply the baseline
#   sudo ./harden.sh --disable-password-auth  # also require SSH keys (only if keys are set up)
#
# Run ./audit.sh afterward to confirm every check passes.
# Test on a lab VM or take a snapshot first. Changing SSH and firewall settings on a
# remote server can lock you out if something is misconfigured.

set -euo pipefail

DISABLE_PASSWORD_AUTH=false

usage() {
    sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
    case "$arg" in
        --disable-password-auth) DISABLE_PASSWORD_AUTH=true ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $arg"; usage; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo $0"
    exit 1
fi

# Work out which Linux family this is, since package and firewall tools differ.
# shellcheck disable=SC1091
. /etc/os-release
case " ${ID} ${ID_LIKE:-} " in
    *" ubuntu "*|*" debian "*) FAMILY=debian ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*) FAMILY=rhel ;;
    *) echo "Unsupported distribution: ${PRETTY_NAME:-unknown}"; exit 1 ;;
esac

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
info() { printf '    %s\n' "$1"; }
warn() { printf '    \033[33mWARNING:\033[0m %s\n' "$1"; }

echo "Hardening ${PRETTY_NAME} (${FAMILY} family)"

# ---------------------------------------------------------------------------
step "1/5  System updates"
# ---------------------------------------------------------------------------
if [[ $FAMILY == debian ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get upgrade -y -q
    apt-get install -y -q unattended-upgrades
    # Turn on daily automatic security updates.
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    info "Automatic security updates enabled (unattended-upgrades)."
else
    dnf upgrade -y -q
    dnf install -y -q dnf-automatic
    sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
    systemctl enable --now dnf-automatic.timer
    info "Automatic updates enabled (dnf-automatic)."
fi

# ---------------------------------------------------------------------------
step "2/5  SSH hardening"
# ---------------------------------------------------------------------------
# Settings go in a drop-in file instead of editing sshd_config directly, so they are
# easy to see and undo. OpenSSH uses the FIRST value it reads for each setting, so the
# file is named 00-... to load before other drop-ins (like cloud-init's 50-cloud-init.conf).
SSH_DROPIN=/etc/ssh/sshd_config.d/00-hardening.conf
mkdir -p /etc/ssh/sshd_config.d

if ! grep -qiE '^\s*Include\s+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then
    warn "sshd_config does not include sshd_config.d/. Adding the Include line at the top."
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
fi

# Safety check: never turn off password login unless the admin already has an SSH key.
if [[ $DISABLE_PASSWORD_AUTH == true ]]; then
    admin_user="${SUDO_USER:-root}"
    admin_home=$(getent passwd "$admin_user" | cut -d: -f6)
    if [[ ! -s "$admin_home/.ssh/authorized_keys" ]]; then
        warn "No SSH key found for $admin_user. Keeping password login on so you are not locked out."
        DISABLE_PASSWORD_AUTH=false
    fi
fi

{
    echo "# Managed by harden.sh"
    echo "PermitRootLogin no          # Log in as a normal user, then use sudo"
    echo "MaxAuthTries 3              # Slow down password guessing"
    echo "LoginGraceTime 30           # Drop connections that do not log in within 30 seconds"
    echo "PermitEmptyPasswords no"
    echo "X11Forwarding no            # Not needed on a server"
    echo "ClientAliveInterval 300     # Disconnect idle sessions after about 10 minutes"
    echo "ClientAliveCountMax 2"
    if [[ $DISABLE_PASSWORD_AUTH == true ]]; then
        echo "PasswordAuthentication no   # Require SSH keys"
    fi
} > "$SSH_DROPIN"

# Validate the config before restarting. A broken config could stop SSH from starting.
if sshd -t; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd
    info "SSH settings applied and service restarted."
else
    rm -f "$SSH_DROPIN"
    echo "SSH config test failed. Removed $SSH_DROPIN and left SSH unchanged."
    exit 1
fi

# ---------------------------------------------------------------------------
step "3/5  Firewall"
# ---------------------------------------------------------------------------
if [[ $FAMILY == debian ]]; then
    apt-get install -y -q ufw
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow OpenSSH          # Allow SSH BEFORE enabling, or remote sessions drop
    ufw --force enable
    info "UFW enabled: deny all incoming except SSH."
else
    dnf install -y -q firewalld
    systemctl enable --now firewalld
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --reload
    info "firewalld enabled with SSH allowed."
fi

# ---------------------------------------------------------------------------
step "4/5  Least privilege and accounts"
# ---------------------------------------------------------------------------
admin_group=sudo
[[ $FAMILY == rhel ]] && admin_group=wheel
admins=$(getent group "$admin_group" | cut -d: -f4)
info "Users with admin (sudo) rights: ${admins:-none}"
info "Review this list and remove anyone who does not need admin access:"
info "  sudo gpasswd -d <username> $admin_group"

empty=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
if [[ -n $empty ]]; then
    for u in $empty; do
        passwd -l "$u" >/dev/null
        warn "Locked account '$u' because it had no password."
    done
else
    info "No accounts with empty passwords."
fi

# Password aging for NEW accounts: change every 90 days, warn 7 days before expiry.
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/; s/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
info "Password aging set for new accounts (90-day maximum, 7-day warning)."

chmod 640 /etc/shadow 2>/dev/null || true
[[ $FAMILY == rhel ]] && chmod 000 /etc/shadow   # Red Hat's default permission

# ---------------------------------------------------------------------------
step "5/5  Mandatory access control"
# ---------------------------------------------------------------------------
if [[ $FAMILY == debian ]]; then
    apt-get install -y -q apparmor apparmor-utils
    systemctl enable --now apparmor
    profiles=$(aa-status --enforced 2>/dev/null || echo "?")
    info "AppArmor running with $profiles profiles in enforce mode."
else
    mode=$(getenforce)
    case $mode in
        Enforcing)
            info "SELinux is already enforcing." ;;
        Permissive)
            setenforce 1
            sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
            info "SELinux switched from permissive to enforcing." ;;
        Disabled)
            warn "SELinux is disabled. Turning it on needs a full file relabel and reboot."
            warn "Set SELINUX=enforcing in /etc/selinux/config, run 'touch /.autorelabel', then reboot." ;;
    esac
fi

printf '\n\033[1mDone.\033[0m Run ./audit.sh to verify. Keep this SSH session open and test a new login before closing it.\n'
