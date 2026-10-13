# Linux Hardening

Two Bash scripts that secure a fresh Linux server and then check that it is secure. They work on both **Ubuntu** and **Red Hat-family** systems (RHEL, Rocky, AlmaLinux). I used this baseline to harden three Linux systems in my lab.

| File | What it does |
|---|---|
| `harden.sh` | Applies the security baseline (makes changes) |
| `audit.sh` | Checks the system against the baseline and prints PASS / WARN / FAIL (changes nothing) |
| `CHECKLIST.md` | The same steps done by hand, with the reason behind each one |

## What gets hardened

| Area | Ubuntu | Red Hat |
|---|---|---|
| **Updates** | Installs updates, turns on `unattended-upgrades` | Installs updates, turns on `dnf-automatic` |
| **SSH** | No root login, 3 login attempts max, idle timeout, optional key-only login | Same |
| **Firewall** | UFW: deny all incoming except SSH | firewalld: SSH allowed |
| **Least privilege** | Lists sudo users, locks empty-password accounts, sets password aging | Same, using the `wheel` group |
| **Mandatory access control** | AppArmor enabled and enforcing | SELinux set to enforcing |

## How to use

```bash
chmod +x harden.sh audit.sh

sudo ./audit.sh                 # 1. See where the system stands now
sudo ./harden.sh                # 2. Apply the baseline
sudo ./audit.sh                 # 3. Confirm everything passes
```

To also require SSH keys instead of passwords (only after your key is set up):

```bash
sudo ./harden.sh --disable-password-auth
```

## Example audit output

```
Security audit: lnx01 - Ubuntu 24.04 LTS - 2026-10-13 14:02

Updates
  PASS  No pending updates
  PASS  Automatic security updates are on

SSH
  PASS  Root login over SSH is disabled
  PASS  MaxAuthTries is 3
  PASS  Empty passwords are not accepted
  WARN  SSH password login is on (consider key-only login)

Firewall
  PASS  UFW firewall is active
  PASS  Incoming traffic is denied by default

Accounts and least privilege
  PASS  No accounts with empty passwords
  PASS  Only root has UID 0
  WARN  Review admin users in 'sudo': brandon
  PASS  Password maximum age is 90 days

Mandatory access control
  PASS  AppArmor is enabled (38 profiles enforcing)

Summary: 11 passed, 2 warnings, 0 failed
```

## Safety features

- **Tests SSH config before restarting.** If `sshd -t` fails, the script removes its changes and leaves SSH running as before.
- **Will not lock you out.** Key-only login is skipped if the admin user has no SSH key set up.
- **Allows SSH before turning on the firewall**, so remote sessions stay connected.
- **Does not force SELinux on from "disabled"**, because that requires a full relabel and reboot. It tells you the steps instead.
- **Audit is read-only** and returns the number of failures as its exit code, so it can run on a schedule.

> Test on a lab VM or take a snapshot first. Changing SSH and firewall settings on a remote server can lock you out if something goes wrong.

## What I learned

- How the same security goals are reached with different tools on Ubuntu and Red Hat
- How OpenSSH combines config files, and why the first value read wins
- The difference between normal Linux permissions and mandatory access control
- Writing Bash scripts that check their own work and fail safely
