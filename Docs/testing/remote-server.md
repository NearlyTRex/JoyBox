# Testing the Remote Server

[← Testing](README.md)

Rehearses the whole `remote_ubuntu` stack on a throwaway KVM virtual machine, so a
change can be proven before it touches a real server.

The VM is treated as **just another server entry**. There is no separate
environment type and no per-installer branching — the same installers run the same
way they would against Hetzner. That is the point: a pass here is evidence about
the real path, not about a parallel one. The steps mirror
[Remote Server Setup](../setup/remote-server.md).

## Quick steps

```bash
# Once: tooling and trust for locally signed certificates
python3 bootstrap.py -a setup -t local_ubuntu --components aptget
mkcert -install

# Make the VM and point joybox.test at it
testvm create --username "$USER"
testvm ip
testvm hosts

# Add it as server 1 in ~/JoyBox.ini (see step 3 below), then on the VM as root:
#   git clone https://github.com/NearlyTRex/JoyBox /root/JoyBox && cd /root/JoyBox/Bootstrap/scripts
#   ./init_sudoers.sh --action setup --user <you>
#   ./init_docker.sh --user <you>
#   ./init_nginx.sh
#   ./init_localstorage.sh --user <you>

# Deploy and verify, from your computer
testvm snapshot --snapshot pre-deploy
python3 bootstrap.py -a setup -t remote_ubuntu -s 1 --components nginx certbot cockpit wordpress navidrome oscar
verify_server --server 1 --domain joybox.test
```

Each step is explained below.

## Recovery first

One of the things this harness exists to rehearse is `init_sshd.sh`, which turns
off password SSH. Read this section before running anything else.

Two independent ways back into the VM, neither of which depends on sshd:

```bash
# Serial console - works even with sshd completely broken.
# cloud-init set a console password (default: joybox) for exactly this case.
testvm console

# Roll back to a snapshot - seconds, rather than a rebuild.
testvm snapshot --snapshot pre-sshd
testvm revert --snapshot pre-sshd
```

Take a snapshot before anything you would not want to repeat by hand.

## Prerequisites

The workstation tooling is declared in the `local_ubuntu` package lists, so:

```bash
python3 bootstrap.py -a setup -t local_ubuntu --components aptget
```

That installs `virtinst`, `qemu-system-x86`, `cloud-image-utils`, `mkcert`,
`libnss3-tools` (so `mkcert` can add its CA to Firefox and Chrome) and `age`.
One manual step remains, because it modifies your system trust store:

```bash
mkcert -install
```

You also need an SSH keypair. If `~/.ssh/id_ed25519` does not exist:

```bash
ssh-keygen -t ed25519
```

## Setup

### 1. Create the VM

```bash
testvm create --username "$USER"
```

Builds an Ubuntu Server guest on libvirt's default NAT network. It takes a
minute to get an address; `testvm ip` prints it once it
has one. Defaults to 2 vCPU / 4 GB / 20 GB, matching a CX22 closely enough for the
stack to behave the same way.

### 2. Point the test domain at it

```bash
testvm hosts
```

Writes a marker-bracketed block into `/etc/hosts` mapping `joybox.test` and its
subdomains to the VM. Re-run it after a snapshot revert if the address changed;
`--remove` takes the block out again.

### 3. Point JoyBox.ini at the VM

Add the VM as its own server entry next to the real one. Domain and TLS mode are
per server, so the real entry is untouched and nothing has to be switched back.
The VM mirrors the real layout everywhere else — `init_localstorage.sh` creates
the same `/mnt/storage` tree, so `navidrome_music_dir`, `audiobookshelf_audio_dir`
and `backup_root` are already correct:

```ini
[UserData.Servers]
server_1_host = <address from step 1>
server_1_port = 22
server_1_user = <you>
server_1_key_filepath = /home/<you>/.ssh/id_ed25519
server_1_domain_name = joybox.test
server_1_tls_mode = mkcert
```

The rest of this page uses `-s 1` and `--server 1` for it. The VM can also use
the real domain with `mkcert`: pass that domain to `testvm hosts --domain`, and
while the hosts block is in place this machine reaches the VM instead of the real
server.

### 4. Prepare the VM

These are the same one-time scripts a real server gets. Clone the repo on the VM
and run them as root from `Bootstrap/scripts` — `init_sudoers.sh` installs the
manager scripts from the `Bootstrap/managers` next to it:

```bash
git clone https://github.com/NearlyTRex/JoyBox ~/JoyBox && cd ~/JoyBox/Bootstrap/scripts
sudo ./init_sudoers.sh --action setup --user <you>
sudo ./init_docker.sh --user <you>
sudo ./init_nginx.sh
sudo ./init_localstorage.sh --user <you>
```

`init_localstorage.sh` stands in for the Storage Box — see
[Fidelity gaps](#fidelity-gaps).

### 5. Deploy

```bash
python3 bootstrap.py -a setup -t remote_ubuntu -s 1 \
    --components nginx certbot cockpit wordpress navidrome oscar
```

Those six are the smoke set, chosen for code-path diversity rather than count:
`cockpit` is not a Docker app, `wordpress` covers the apex-domain handoff and a
DB-backed stack, `navidrome` covers the storage path, and `oscar` is the control
that already bound to loopback correctly before any of this work. Add
`--components <name>` for anything else.

### 6. Verify

```bash
verify_server --server 1 --domain joybox.test
```

This runs from the workstation and reads the VM's state over the same SSH
connection `bootstrap.py` uses, so nothing has to be installed on the target.
It exits with the number of failed checks, so it works as a gate. Every check
tests the effect rather than the configuration — it bursts requests to confirm
rate limiting actually refuses, and reads live socket state to confirm nothing
is listening on `0.0.0.0`.

Each check is a function in `Shared/joybox/hardening.py` if you want to run
just one:

```python
from joybox import hardening
from joybox.connection import ConnectionLocal

connection = ConnectionLocal()
print(hardening.format_results(hardening.check_sshd(connection)))
```

## TLS

`server_N_tls_mode` under `[UserData.Servers]` decides how that server's certificate is obtained.
All three modes write to `/etc/letsencrypt/live/<domain>/`, so nothing downstream
changes — every app's nginx template points at that path regardless.

| Mode | Where it runs | Browser warning |
|------|---------------|-----------------|
| `letsencrypt` | certbot on the target | none — the only option for a public server |
| `mkcert` | mkcert on your workstation | none, once `mkcert -install` has run |
| `selfsigned` | openssl on the target | one warning, no local dependency |

`mkcert` runs on the workstation rather than the VM on purpose: it signs with the
local CA that `mkcert -install` added to *this machine's* trust store, and that
trust is what suppresses the warning. Only the leaf certificate is pushed to the VM.

## The SSH lockout drill

The riskiest change in the stack, so rehearse it here first.

```bash
# 1. Snapshot
testvm snapshot --snapshot pre-sshd

# 2. Confirm key auth already works - bootstrap.py must be on keys before
#    passwords are disabled, or the next deploy cannot connect
python3 bootstrap.py -t remote_ubuntu -s 1 --list-components

# 3. On the VM, as root
sudo ./init_sshd.sh --user <you>

# 4. Confirm: key login works, password login is refused
ssh <you>@<vm-ip>
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no <you>@<vm-ip>

# 5. If it went wrong
testvm revert --snapshot pre-sshd
```

`init_sshd.sh` refuses to run if the user has no `authorized_keys`, validates with
`sshd -t` before touching the daemon, and reloads rather than restarts so existing
sessions survive. The snapshot is the backstop for everything those miss.

## Backups

The encrypted backup path is worth exercising locally before it holds real data:

```bash
age-keygen -o ~/.joybox-age-test.key
```

Put the printed public key in `backup_age_recipient` and the file path in
`backup_age_identity`, then round-trip it:

```bash
python3 bootstrap.py -a backup  -t remote_ubuntu -s 1 --components wordpress
python3 bootstrap.py -a restore -t remote_ubuntu -s 1 --components wordpress --confirm restore
```

Archives land as `.age` files. During restore the private key is staged on
`/dev/shm` (RAM) and removed afterwards, so it never reaches the server's disk.

Use a throwaway key here, not the one guarding real backups.

## Fidelity gaps

Stated rather than papered over:

- **No sshfs.** `/mnt/storage` is a plain directory on the VM, not a Storage Box
  over FUSE. Mount flags, `idmap=user`, `_netdev` ordering and off-box durability
  are not exercised. Nothing under test depends on those semantics.
- **No real DNS or ACME.** `joybox.test` resolves through `/etc/hosts` only, and
  certificates are locally signed. Certbot's own issuance and renewal paths are
  not covered.
- **NAT, not a public address.** The VM is not reachable from the internet, so
  real-world scanning and abuse traffic are not part of the picture.

## Teardown

```bash
testvm hosts --remove
testvm destroy
```

Then remove the `server_1_*` entry from `JoyBox.ini`, or leave it for next time.
