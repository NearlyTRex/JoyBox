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

The downloaded image is checked against the **SHA256SUMS published beside it** before anything is
built from it. A mismatch deletes the download rather than leaving it to be picked up as "already
here" by the next run. `--skip_verify` turns that off.

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

Write it to a stick with:

```bash
sudo dd if=ubuntu-autoinstall.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

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

To install something that is not packaged — ollama's own installer, for instance — fetch and run
it in a late command:

```yaml
autoinstall:
  late-commands:
    - curtin in-target --target=/target -- sh -c "curl -fsSL https://ollama.com/install.sh | sh"
    - curtin in-target --target=/target -- systemctl enable ollama
```

Late commands run inside the installed system with the network already up, which is why anything
that downloads belongs there rather than in `early-commands`.

## Write the whole seed yourself

When the overlay is not enough, hand over a complete cloud-init file and it is used exactly as it
is — nothing is generated and the profile is not consulted:

```bash
build_autoinstall_iso --user_data ~/JoyBox/Autoinstall/user-data
```

## What the build does to the image

1. Downloads the newest point release of the configured version (or reuses one you supply).
2. Verifies it against the published `SHA256SUMS`.
3. Unpacks it, including the EFI boot image that lives in the El Torito catalogue rather than the
   filesystem — rebuilding without it produces an image no UEFI machine will boot.
4. Writes `user-data` and `meta-data` into a `/nocloud` directory.
5. Points every boot configuration at that seed (`autoinstall ds=nocloud;s=/cdrom/nocloud/`) and
   drops the menu timeout to 2 seconds, leaving a moment to interrupt.
6. Repacks it as a hybrid BIOS + UEFI image that boots from a USB stick.

The arguments are inserted **before** the `---` separator on the kernel line. Anything after that
separator is passed to the installed system rather than the installer, so an image built the
other way boots normally and quietly does not autoinstall at all.
