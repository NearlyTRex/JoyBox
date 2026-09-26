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
# Once: tooling for the guest and for locally signed certificates
python3 bootstrap.py -a setup -t local_ubuntu --components aptget python wrappers

# Add the guest as server 1 in ~/JoyBox.ini (see below), then:
provision_server --server 1
```

That builds the guest, provisions it exactly as a real server is provisioned, and ends
with the hardening checks. Run it again after a change: finished stages confirm
themselves, so `--stages deploy verify` is the usual loop.

## The server entry

Add the guest as its own server entry next to the real one. Domain and TLS mode are per
server, so the real entry is untouched and nothing has to be switched back:

```ini
[UserData.Servers]
server_1_host = 192.168.122.10
server_1_port = 22
server_1_user = <you>
server_1_key_filepath = /home/<you>/.ssh/id_ed25519
server_1_domain_name = joybox.test
server_1_tls_mode = mkcert
server_1_vm = joybox-test
server_1_htpasswd_pass = op://Personal/JoyBox/UserData.Servers/server_1_htpasswd_pass
```

- `server_1_vm` is what makes this entry a test guest: the `vm` stage builds or starts
  `joybox-test` and points the domain at it in `/etc/hosts`.
- `192.168.122.10` is reserved for the guest's fixed MAC on libvirt's default network, so
  it survives rebuilds and reverts and the entry never needs editing.
- Leave the `storage` fields out: `init_localstorage.sh` creates the same `/mnt/storage`
  tree a Storage Box would, so `navidrome_music_dir`, `audiobookshelf_audio_dir` and
  `backup_root` are already right.
- The guest can use the real domain instead of `joybox.test`. While the hosts block is in
  place this machine reaches the guest rather than the real server; the hardening checks'
  rate-limit burst stays on the guest either way.

## What the guest starts as

`testvm create`, which the `vm` stage runs, makes the guest look like a freshly ordered
server: root reachable with your key and no account of your own. Provisioning then
creates your account with only the sudo a real server grants it, so a deploy that
needs more fails here rather than on the real host.

It is 2 vCPU / 4 GB / 20 GB, close enough to a CX22 for the stack to behave the same way.

## Recovery

The `sshd` stage turns off root and password SSH. It proves your key login before and
after, and snapshots the guest as `pre-sshd` first, reverting to it if your key login
is lost. Two more ways back in, neither of which depends on sshd:

```bash
# Serial console - works even with sshd completely broken.
# Log in as root with the console password, joybox.
testvm console

# Roll back to a snapshot - seconds, rather than a rebuild.
testvm snapshots
testvm revert --snapshot provision-fresh
```

`provision-fresh` is the guest just after first boot, before anything was provisioned.

## Prerequisites

The workstation tooling is declared in the `local_ubuntu` package lists:

```bash
python3 bootstrap.py -a setup -t local_ubuntu --components aptget python wrappers
```

That installs `virtinst`, `qemu-system-x86`, `cloud-image-utils`, `mkcert`,
`libnss3-tools` (so `mkcert` can add its CA to Firefox and Chrome) and `age`, the
`paramiko` SSH library, and the `provision_server` and `testvm` commands. The first
`mkcert` deploy runs `mkcert -install`, which adds a local certificate authority to this
machine's trust store and asks for your password.

`testvm` runs as you and asks sudo only for its root-only steps: writing guest
images under `/var/lib/libvirt/images` and editing `/etc/hosts`. It talks to the
system libvirt directly, which needs membership of the `libvirt` group (`groups`
lists yours). If it is missing, add it and log in again:

```bash
sudo usermod -aG libvirt "$USER"
```

You also need an SSH keypair. If `~/.ssh/id_ed25519` does not exist:

```bash
ssh-keygen -t ed25519
```

## Smaller loops

`--components` limits the deploy, the same as for `bootstrap.py`:

```bash
provision_server -s 1 --stages deploy verify \
    --components nginx certbot cockpit wordpress navidrome oscar
```

Those six are the smoke set, chosen for code-path diversity rather than count:
`cockpit` is not a Docker app, `wordpress` covers the apex-domain handoff and a
DB-backed stack, `navidrome` covers the storage path, and `oscar` is the control
that already bound to loopback correctly before any of this work.

`verify_server --server 1 --domain joybox.test` runs the checks on their own. It exits
with the number of failed checks, and every check tests the effect rather than the
configuration: it bursts requests to confirm rate limiting actually refuses, and reads
live socket state to confirm nothing is listening on `0.0.0.0`. Each check is a function
in `Shared/joybox/hardening.py`.

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
- **Root's first key comes from cloud-init**, not the provider's control panel. The
  `login` stage that follows is the same.

## Teardown

```bash
testvm hosts --remove
testvm destroy
```

Then remove the `server_1_*` entry from `JoyBox.ini`, or leave it for next time; the
next `provision_server --server 1` builds a fresh guest at the same address.
