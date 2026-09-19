# Local Testing

[← Docs index](README.md)

Rehearses the whole `remote_ubuntu` stack on a throwaway KVM virtual machine, so a
change can be proven before it touches a real server.

The VM is treated as **just another server entry**. There is no separate
environment type and no per-installer branching — the same installers run the same
way they would against Hetzner. That is the point: a pass here is evidence about
the real path, not about a parallel one.

## Recovery first

One of the things this harness exists to rehearse is `init_sshd.sh`, which turns
off password SSH. Read this section before running anything else.

Two independent ways back into the VM, neither of which depends on sshd:

```bash
# Serial console - works even with sshd completely broken.
# cloud-init set a console password (default: joybox) for exactly this case.
sudo Bootstrap/scripts/testvm.sh console

# Roll back to a snapshot - seconds, rather than a rebuild.
sudo Bootstrap/scripts/testvm.sh snapshot pre-sshd
sudo Bootstrap/scripts/testvm.sh revert pre-sshd
```

Take a snapshot before anything you would not want to repeat by hand.

## Prerequisites

The workstation tooling is declared in the `local_ubuntu` package lists, so:

```bash
python3 bootstrap.py -a setup -t local_ubuntu --components aptget
```

That installs `virtinst`, `qemu-system-x86`, `cloud-image-utils`, `mkcert` and
`age`. One manual step remains, because it modifies your system trust store:

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
sudo Bootstrap/scripts/testvm.sh create --user "$USER"
```

Builds an Ubuntu Server guest on libvirt's default NAT network and prints its
address. Defaults to 2 vCPU / 4 GB / 20 GB, matching a CX22 closely enough for the
stack to behave the same way.

### 2. Point the test domain at it

```bash
sudo Bootstrap/scripts/init_testhosts.sh
```

Writes a marker-bracketed block into `/etc/hosts` mapping `joybox.test` and its
subdomains to the VM. Re-run it after a snapshot revert if the address changed;
`--remove` takes the block out again.

### 3. Point JoyBox.ini at the VM

Only **two** settings actually have to change, because the VM mirrors the real
layout everywhere else — `init_localstorage.sh` creates the same `/mnt/storage`
tree, so `navidrome_music_dir`, `audiobookshelf_audio_dir` and `backup_root` are
already correct:

```ini
[UserData.Servers]
domain_name = joybox.test
tls_mode = mkcert

server_0_host = <address from step 1>
server_0_port = 22
server_0_user = <you>
server_0_key_filepath = /home/<you>/.ssh/id_ed25519
```

Switch `domain_name` and `tls_mode` back when you are done. Everything else —
app passwords, subdomains, ports — can stay as it is.

### 4. Prepare the VM

These are the same day-0 scripts a real server gets. Copy `Bootstrap/scripts`
over and run them as root on the VM:

```bash
sudo ./init_sudoers.sh --user <you>
sudo ./init_docker.sh --user <you>
sudo ./init_nginx.sh
sudo ./init_localstorage.sh --user <you>
```

`init_localstorage.sh` stands in for the Storage Box — see
[Fidelity gaps](#fidelity-gaps).

### 5. Deploy

```bash
python3 bootstrap.py -a setup -t remote_ubuntu -s 0 \
    --components nginx certbot cockpit wordpress navidrome oscar
```

Those six are the smoke set, chosen for code-path diversity rather than count:
`cockpit` is not a Docker app, `wordpress` covers the apex-domain handoff and a
DB-backed stack, `navidrome` covers the storage path, and `oscar` is the control
that already bound to loopback correctly before any of this work. Add
`--components <name>` for anything else.

### 6. Verify

```bash
sudo ./verify_hardening.sh --domain joybox.test
```

Exits with the number of failed checks, so it works as a gate. Every check tests
the effect rather than the configuration — it bursts requests to confirm rate
limiting actually refuses, and reads live socket state to confirm nothing is
listening on `0.0.0.0`.

Each check is also a `verify_*` function in `common.sh` if you want to run just
one:

```bash
source Bootstrap/scripts/common.sh
verify_sshd
verify_container_ports
```

## TLS

`tls_mode` under `[UserData.Servers]` decides how the certificate is obtained.
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
sudo Bootstrap/scripts/testvm.sh snapshot pre-sshd

# 2. Confirm key auth already works - bootstrap.py must be on keys before
#    passwords are disabled, or the next deploy cannot connect
python3 bootstrap.py -t remote_ubuntu -s 0 --list-components

# 3. On the VM, as root
sudo ./init_sshd.sh --user <you>

# 4. Confirm: key login works, password login is refused
ssh <you>@<vm-ip>
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no <you>@<vm-ip>

# 5. If it went wrong
sudo Bootstrap/scripts/testvm.sh revert pre-sshd
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
python3 bootstrap.py -a backup  -t remote_ubuntu -s 0 --components wordpress
python3 bootstrap.py -a restore -t remote_ubuntu -s 0 --components wordpress --confirm restore
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
sudo Bootstrap/scripts/init_testhosts.sh --remove
sudo Bootstrap/scripts/testvm.sh destroy
```

Then put `domain_name` and `tls_mode` back to their real values in `JoyBox.ini`.
