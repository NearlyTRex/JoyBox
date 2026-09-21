# Autoinstall Images

[← Docs index](README.md)

Build an Ubuntu Server image that installs itself. You write it to a USB stick, boot the target
machine from it, and walk away — the installer answers its own questions from a cloud-init seed
baked into the image.

## Configure the machine once

Everything the installer would have asked lives in `~/JoyBox.ini`. Nothing is hardcoded, so a
fresh checkout builds nothing until this is filled in.

```ini
[UserData.Autoinstall]
autoinstall_version = 24.04
autoinstall_username = operator
autoinstall_realname = Operator
autoinstall_hostname = ubuntu
autoinstall_ssh_keys = ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... you@example.com
autoinstall_password_hash =
autoinstall_locale = en_US.UTF-8
autoinstall_keyboard = us
autoinstall_timezone = Etc/UTC
autoinstall_packages = qemu-guest-agent
autoinstall_serial_console = false
autoinstall_overlay_file =
```

A build is refused unless there is a **username**, a **hostname**, and at least one of a password
hash or an SSH key — an installed machine with none of those is one nobody can log into, and
nobody is at the keyboard to notice.

Generate a password hash with `mkpasswd --method=SHA-512 --rounds=656000`. Password logins over
SSH are disabled in the seed either way, so the hash is only for the console.

## Build

```bash
# Latest point release of the configured version, into the current directory
build_autoinstall_iso

# Somewhere else, with a name and a hostname for this machine
build_autoinstall_iso -o ~/Images -n homelab.iso -t homelab

# From an ISO you already have, skipping the download
build_autoinstall_iso -s ~/Downloads/ubuntu-24.04.1-live-server-amd64.iso
```

The downloaded image is checked against the **SHA256SUMS published beside it**, and that listing
is itself checked against **the signature Ubuntu publishes over it**, before anything is built. A
mismatch deletes the download rather than leaving it to be picked up as "already here" by the
next run.

| Flag | Default | Meaning |
|------|---------|---------|
| `-o`, `--output_path` | current directory | Directory to write the image into |
| `-n`, `--output_name` | `ubuntu-autoinstall.iso` | Name of the image |
| `-s`, `--source_iso` | — | Stock image to start from, instead of downloading |
| `-r`, `--release` | from settings | Ubuntu release to build from |
| `-t`, `--hostname` | from settings | Hostname for the installed machine |
| `-y`, `--overlay` | from settings | YAML merged into the generated config |
| `-d`, `--user_data` | — | Use this seed verbatim instead of generating one |
| `-l`, `--serial_console` | off | Also send installer output to `ttyS0` |
| `-k`, `--skip_verify` | off | Do not check the download against its published checksum |
| `-g`, `--skip_signature` | off | Do not check who signed the published checksums |

Write it to a stick with:

```bash
sudo dd if=ubuntu-autoinstall.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

## Who signed the checksums

A checksum fetched over the same connection as the image proves only that the two agree — anyone
able to serve you a different image can serve a matching checksum with it. Ubuntu signs the
listing, so the build checks that signature against a key obtained some other way:

```ini
[UserData.Autoinstall]
autoinstall_signing_keyring = /usr/share/keyrings/ubuntu-archive-keyring.gpg
autoinstall_signing_fingerprint = 843938DF228D22F7B3742BC0D94AA3F0EFE21092
```

That fingerprint is the **Ubuntu CD Image Automatic Signing Key (2012)**, which still signs
current releases. The keyring is the one the `ubuntu-keyring` package installs, so the key comes
from the distribution rather than from the same server as the image.

A keyring holds every key its distribution trusts, so a valid signature alone is not enough — the
build also checks that the key which signed the listing is the one named above. Point both
settings elsewhere for a release signed by a different key, or a machine that keeps its keyrings
somewhere else.

If gpg or the keyring is missing the build stops rather than carrying on unverified. Use
`--skip_signature` to build anyway, or `--skip_verify` to skip both checks.

## Load the machine with software

The generated seed covers what the *installer* must have: a disk layout, an account, a way in.
Anything the machine is actually **for** goes in an overlay — a YAML file merged into the
generated config.

```ini
[UserData.Autoinstall]
autoinstall_overlay_file = ~/JoyBox/Autoinstall/homelab.yaml
```

```yaml
# ~/JoyBox/Autoinstall/homelab.yaml
autoinstall:
  packages:
    - docker.io
    - build-essential
  snaps:
    - name: ollama
  late-commands:
    - curtin in-target --target=/target -- systemctl enable docker
    - curtin in-target --target=/target -- usermod -aG docker operator
  user-data:
    write_files:
      - path: /etc/docker/daemon.json
        content: |
          { "log-driver": "json-file", "log-opts": { "max-size": "10m" } }
        permissions: '0644'
```

Merging is additive where it matters: **lists under `packages`, `snaps`, `late-commands`,
`users` and `write_files` are appended to**, not replaced, so an overlay cannot accidentally drop
the account or the disk layout the generated document established. Dictionaries merge key by
key, and a plain value overrides.

Late commands run inside the installed system with the network already up, which is why anything
that downloads belongs there rather than in `early-commands`. What they do **not** have is a
running systemd — the installer has the target mounted, not booted — so an installer that starts
or restarts a service belongs in `user-data`, whose `runcmd` runs on the first real boot.

## A GPU LLM server

There is one of these in the tree, ready to build from:

```bash
build_autoinstall_iso -y Scripts/autoinstall/homelab_llm.yaml -t llm -n llm.iso
```

It asks subiquity to install the third-party drivers it detects, which on an NVIDIA machine is
the signed `-server` driver, and adds the tools worth having on a box whose job is to feed a
card: `nvtop`, `btop`, build tooling and a Python environment. On a machine with no card it
recognises, nothing driver-shaped is installed and the rest still applies.

ollama itself goes in on first boot, from its own installer, because that installer wants a
systemd to talk to. A drop-in written beforehand settles how it runs:

```
OLLAMA_HOST=0.0.0.0:11434     listen on the network, not just on localhost
OLLAMA_MODELS=/var/lib/ollama/models
OLLAMA_KEEP_ALIVE=30m         hold a model in vram between questions
OLLAMA_NUM_PARALLEL=2
OLLAMA_MAX_LOADED_MODELS=2
```

The machine comes up with `llama3.1:8b` already pulled, `ufw` allowing only SSH and the API port,
and a `gpu-status` command that prints what the card is doing. Change the model on the last line
of the overlay, or drop the line to choose later.

**The API has no authentication.** Anything that can reach port 11434 can use the models and read
what is asked of them, so this belongs on a network you control — not on a machine with a public
address and not behind a router forwarding the port. Put it behind something that authenticates
if it needs to be reachable from elsewhere.

**Secure Boot** and NVIDIA need a word. The drivers from Ubuntu's archive are signed by Canonical
and load with Secure Boot on; drivers built by DKMS from NVIDIA's own installer are not, and
enrolling a key for them is a blue screen at the console asking for a password — on a machine
nobody is sitting at. The overlay stays on the archive drivers for that reason.

Everything in the file is ordinary overlay syntax, so it is also a worked example of the merge:
it adds `drivers`, extends `packages`, and reaches into `user-data` for `write_files` and
`runcmd` without disturbing the account, the disk layout or the SSH hardening underneath.

## Write the whole seed yourself

When the overlay is not enough, hand over a complete cloud-init file and it is used exactly as it
is — nothing is generated and the profile is not consulted:

```bash
build_autoinstall_iso --user_data ~/JoyBox/Autoinstall/user-data
```

## What the build does to the image

1. Downloads the newest point release of the configured version (or reuses one you supply).
2. Verifies it against the published `SHA256SUMS`, having first checked the signature over that
   listing against Ubuntu's CD signing key.
3. Unpacks it, including the EFI boot image that lives in the El Torito catalogue rather than the
   filesystem — rebuilding without it produces an image no UEFI machine will boot.
4. Writes `user-data` and `meta-data` into a `/nocloud` directory.
5. Points every boot configuration at that seed (`autoinstall ds=nocloud;s=/cdrom/nocloud/`) and
   drops the menu timeout to 2 seconds, leaving a moment to interrupt.
6. Repacks it as a hybrid BIOS + UEFI image that boots from a USB stick.

The arguments are inserted **before** the `---` separator on the kernel line. Anything after that
separator is passed to the installed system rather than the installer, so an image built the
other way boots normally and quietly does not autoinstall at all.
