# Linux Hardening Checklist

A manual version of what `harden.sh` automates, with the reason behind each step. Use it to harden a system by hand or to double-check the script's work.

## 1. Updates and patching

- [ ] Install all pending updates (`apt upgrade` / `dnf upgrade`)
- [ ] Turn on automatic security updates (`unattended-upgrades` / `dnf-automatic`)

**Why:** Most attacks use known vulnerabilities that already have patches. Staying current closes those holes.

## 2. SSH hardening

- [ ] `PermitRootLogin no`
- [ ] `MaxAuthTries 3`
- [ ] `PermitEmptyPasswords no`
- [ ] Idle timeout with `ClientAliveInterval` and `ClientAliveCountMax`
- [ ] Key-only login with `PasswordAuthentication no` (after keys are set up)
- [ ] Validate with `sshd -t` before restarting SSH

**Why:** SSH is the most-attacked service on an internet-facing Linux server. Blocking root login means an attacker has to guess a username *and* a password, and key-only login stops password guessing entirely.

## 3. Firewall

- [ ] Default policy: deny incoming, allow outgoing
- [ ] Allow only the services the server needs (SSH at minimum)
- [ ] Allow SSH *before* enabling the firewall on a remote machine

**Why:** Every open port is something an attacker can probe. A default-deny firewall means a service has to be allowed on purpose.

## 4. Least privilege and user management

- [ ] Review who is in the `sudo` (Ubuntu) or `wheel` (Red Hat) group
- [ ] Remove admin rights from anyone who does not need them
- [ ] Lock accounts with empty passwords
- [ ] Make sure only `root` has UID 0
- [ ] Set password aging in `/etc/login.defs`

**Why:** If an account is compromised, the damage is limited to what that account can do. Fewer admins means fewer high-value targets.

## 5. Mandatory access control (MAC)

- [ ] Ubuntu: AppArmor enabled with profiles in enforce mode (`aa-status`)
- [ ] Red Hat: SELinux set to `Enforcing` (`getenforce`)

**Why:** Normal Linux permissions let a program do anything its user can do. MAC adds a second layer that limits each program to only what it needs, so a hacked web server cannot read files it has no business touching.

## Verify

- [ ] Run `sudo ./audit.sh` and confirm every check passes
- [ ] Open a *new* SSH session to confirm you can still log in before closing the old one
