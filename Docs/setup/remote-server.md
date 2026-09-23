# Remote Server Setup

[← Docs index](../README.md)

Set up a fresh **Ubuntu server** (a Hetzner cloud box, say) to run the website and services. You
drive it from your own computer: a few one-time scripts run on the server as root, then
`bootstrap.py -t remote_ubuntu` does the rest over SSH.

Rehearse this on a local VM first — see [Testing the Remote Server](../testing/remote-server.md).
It is the same steps against a throwaway machine.

## Before you start

- [ ] Your own computer is set up — [Local Computer Setup](local-computer.md).
- [ ] A fresh Ubuntu server you can reach as `root` with an SSH key.
- [ ] DNS for your domain, and every service subdomain you plan to run, pointing at the server.
      Let's Encrypt cannot issue a certificate for a name that does not resolve to it.
- [ ] Optional: a Hetzner Storage Box for media and backups, and its password to hand.

## Quick steps

**1. Describe the server in `~/JoyBox.ini`** on your computer:

```ini
[UserData.Servers]
domain_name = example.com
domain_contact = you@example.com
tls_mode = letsencrypt
server_0_host = 203.0.113.10
server_0_port = 22
server_0_user = you
server_0_key_filepath = /home/you/.ssh/id_ed25519
```

The app passwords and ports each service reads are in [Configuration](../reference/configuration.md);
keep the passwords in 1Password with [Secrets](../reference/secrets.md).

**2. Create your account on the server**, as root:

```bash
ssh root@203.0.113.10
adduser you
usermod -aG sudo you
install -d -m 700 -o you -g you /home/you/.ssh
install -m 600 -o you -g you ~/.ssh/authorized_keys /home/you/.ssh/authorized_keys
```

**3. Run the one-time scripts**, still as root on the server:

```bash
git clone https://github.com/NearlyTRex/JoyBox /root/JoyBox
cd /root/JoyBox/Bootstrap/scripts

./init_sudoers.sh --action setup --user you
./init_docker.sh --user you
./init_nginx.sh
./init_htpasswd.sh --action setup --user you
./init_storagebox.sh --user you --storage-user u123456 --storage-host u123456.your-storagebox.de
```

`init_htpasswd.sh` prompts for the password that guards the admin pages. `init_storagebox.sh`
asks for the Storage Box password once, to install a key; after that it mounts at
`/mnt/storage` on its own. Skip it if you have no Storage Box.

**4. Deploy**, from your computer:

```bash
cd ~/Repositories/JoyBox
python3 bootstrap.py -a setup -t remote_ubuntu -s 0 -p -v   # look first
python3 bootstrap.py -a setup -t remote_ubuntu -s 0
```

Or only some services — see [Services](../remote-server/services.md) for the list:

```bash
python3 bootstrap.py -a setup -t remote_ubuntu -s 0 --components nginx certbot cockpit wordpress
```

**5. Check it**, from your computer:

```bash
verify_server --server 0 --domain example.com
```

It exits with the number of failed checks, so `0` is a pass.

**6. Lock SSH to keys only**, once step 4 has connected with your key. Keep an SSH session open
while it runs, then on the server as root:

```bash
cd /root/JoyBox/Bootstrap/scripts
./init_sshd.sh --user you
```

From a second terminal confirm `ssh you@203.0.113.10` still works before closing the first.
Why this is a separate step is in [Hardening](../remote-server/hardening.md#ssh-is-key-only).

**7. Take the first backup:**

```bash
python3 bootstrap.py -a backup -t remote_ubuntu -s 0
```

## What each one-time script does

| Script | What it does |
|--------|--------------|
| `init_sudoers.sh` | Installs the root-owned manager scripts, and lets your account run them — and `apt-get` for the server's package list — without a password |
| `init_docker.sh` | Adds your account to the `docker` group and applies the daemon's security settings |
| `init_nginx.sh` | Firewall, fail2ban, unattended upgrades, and nginx's security headers, rate limiting, ModSecurity and stream module |
| `init_htpasswd.sh` | Adds or updates the login shared by the admin pages |
| `init_storagebox.sh` | Mounts the Storage Box over sshfs at `/mnt/storage`, and adds it to `/etc/fstab` |
| `init_sshd.sh` | Turns off password and root SSH login |

They need root, so they run on the server directly rather than as `bootstrap.py` components.

## Afterwards

- Update: re-run step 4. Anything already installed is skipped; add `-f` with `--components` to
  reinstall one service.
- Everyday commands: [Bootstrap commands](../reference/bootstrap-commands.md).
- Backups and restores: [Backup and Restore](../remote-server/backup-restore.md).
