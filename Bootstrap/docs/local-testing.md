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
sudo Bootstrap/scripts/local/vm_snapshot.sh console

# Roll back to a snapshot - seconds, rather than a rebuild.
sudo Bootstrap/scripts/local/vm_snapshot.sh snapshot pre-sshd
sudo Bootstrap/scripts/local/vm_snapshot.sh revert pre-sshd
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
sudo Bootstrap/scripts/local/vm_create.sh --user "$USER"
```

Builds an Ubuntu Server guest on libvirt's default NAT network and prints its
address. Defaults to 2 vCPU / 4 GB / 20 GB, matching a CX22 closely enough for
the stack to behave the same way.

### 2. Point the test domain at it

```bash
sudo Bootstrap/scripts/local/hosts_sync.sh
```

Writes a marker-bracketed block into `/etc/hosts` mapping `joybox.test` and its
subdomains to the VM. Re-run it after a snapshot revert if the address changed;
`--remove` takes the block out again.

### 3. Write the config

```bash
cp Bootstrap/scripts/local/JoyBox.local.ini.example ~/JoyBox.local.ini
```

Fill in `server_0_host`, `server_0_user` and `server_0_key_filepath` from what
`vm_create.sh` printed.

A separate file is what isolates the rehearsal. `bootstrap.py -c` points the
settings module at it wholesale, so the VM gets its own domain, TLS mode and
credentials, and no local value can leak into a production run.

### 4. Prepare the VM

These are the same day-0 scripts a real server gets. Copy the `Bootstrap/scripts`
directory over and run them as root on the VM:

```bash
sudo ./init_sudoers.sh --user <you>
sudo ./init_docker.sh --user <you>
sudo ./init_nginx.sh
sudo ./local/init_local_storage.sh --user <you>
```

`init_local_storage.sh` stands in for the Storage Box — see
[Fidelity gaps](#fidelity-gaps).

### 5. Deploy

```bash
python3 bootstrap.py -a setup -t remote_ubuntu -s 0 -c ~/JoyBox.local.ini \
    --components nginx certbot cockpit wordpress navidrome oscar
```

Those six are the smoke set, chosen for code-path diversity rather than count:
`cockpit` is not a Docker app, `wordpress` covers the apex-domain handoff and a
DB-backed stack, `navidrome` covers the storage path, and `oscar` is the control
that already bound to loopback correctly before any of this work. Add
`--components <name>` for anything else.

### 6. Verify

```bash
sudo ./local/verify_hardening.sh
```

Exits with the number of failed checks, so it works as a gate. Every check tests
the effect rather than the configuration — it bursts requests to confirm rate
limiting actually refuses, and reads live socket state to confirm nothing is
listening on `0.0.0.0`.

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
sudo Bootstrap/scripts/local/vm_snapshot.sh snapshot pre-sshd

# 2. Confirm key auth already works - bootstrap.py must be on keys before
#    passwords are disabled, or the next deploy cannot connect
python3 bootstrap.py -t remote_ubuntu -s 0 -c ~/JoyBox.local.ini --list-components

# 3. On the VM, as root
sudo ./init_sshd.sh --user <you>

# 4. Confirm: key login works, password login is refused
ssh <you>@<vm-ip>
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no <you>@<vm-ip>

# 5. If it went wrong
sudo Bootstrap/scripts/local/vm_snapshot.sh revert pre-sshd
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
python3 bootstrap.py -a backup  -t remote_ubuntu -s 0 -c ~/JoyBox.local.ini --components wordpress
python3 bootstrap.py -a restore -t remote_ubuntu -s 0 -c ~/JoyBox.local.ini --components wordpress --confirm restore
```

Archives land as `.age` files. During restore the private key is staged on
`/dev/shm` (RAM) and removed afterwards, so it never reaches the server's disk.

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
sudo Bootstrap/scripts/local/hosts_sync.sh --remove
sudo Bootstrap/scripts/local/vm_snapshot.sh destroy
```
