# Autoinstall Images

[← Docs index](../README.md)

Reference for building an Ubuntu Server image that installs itself. The step-by-step version is
[Homelab Server Setup](../setup/homelab-server.md); the GPU server image is
[The LLM Server Image](llm-overlay.md).

You write the image to a USB stick, boot the target
machine from it, and walk away — the installer answers its own questions from a cloud-init seed
baked into the image.

## Configure the machine once

Everything the installer would have asked lives in `~/JoyBox.ini`. Nothing is hardcoded, so a
fresh checkout builds nothing until this is filled in.

```ini
[UserData.Autoinstall]
autoinstall_version = 24.04
autoinstall_username = homelab
autoinstall_realname = Homelab
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

The username is checked against the list the installer itself refuses, which includes ordinary
looking names like `operator` and `admin` — they are group names Ubuntu already uses. The
installer only refuses one after it has booted on the target machine, where it stops and waits
at a shell, so the build refuses it here instead.

Generate the key with `ssh-keygen -t ed25519 -C joybox-autoinstall -f ~/.ssh/joybox_autoinstall`
and put the contents of the **`.pub`** file in `autoinstall_ssh_keys`. Several keys go on one
line separated by commas.

A password hash is optional and only matters at the console, since password logins over SSH are
disabled in the seed. Make one with `mkpasswd --method=SHA-512 --rounds=656000` (from the
`whois` package) or `openssl passwd -6`. Leave it empty and the account is **locked** rather than
left with an empty password — an empty password field is a console login that takes no password,
which is not the same thing as no login at all.

## Check it before building

The seed is what the installer obeys, so look at it before spending a download on it:

```bash
build_autoinstall_iso --show_seed
build_autoinstall_iso --show_seed -y Scripts/autoinstall/homelab_llm.yaml
```

That renders exactly what would be written into the image, from the configuration and overlay as
they stand, and says what is still missing. Nothing is fetched and nothing is written.

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

Every flag is on the [`build_autoinstall_iso`](../reference/man/build_autoinstall_iso.md) page.

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
current releases — the test suite keeps a real signed listing for each release it claims to cover
and checks the shipped fingerprint against every one of them, so a key rotation shows up as a
failing test rather than as a build that stops working. The keyring is the one the `ubuntu-keyring` package installs, so the key comes
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
    - curtin in-target --target=/target -- usermod -aG docker homelab
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

## Try it in a machine first

Write the image to a stick only after it has installed something in a VM — see
[Testing the Homelab Server](../testing/homelab-server.md).

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
3. Unpacks it, including the two pieces that are not files in the filesystem: the EFI boot image,
   which lives in the El Torito catalogue, and the boot code in the system area at the front of
   the image. Both are read straight out of the image by offset, so no particular version of
   xorriso is needed.
4. Writes `user-data` and `meta-data` into a `/nocloud` directory.
5. Points every boot configuration at that seed (`autoinstall ds=nocloud;s=/cdrom/nocloud/`) and
   drops the menu timeout to 2 seconds, leaving a moment to interrupt.
6. Repacks it as a hybrid BIOS + UEFI image: the boot code goes back into the system area, and
   the EFI image is appended as a real EFI system partition under a GPT, with the El Torito entry
   pointing at that same partition.

That last step is what makes `dd` to a USB stick work. An image carrying only an El Torito
catalogue boots from a disc; firmware booting a stick looks for a partition table instead, and
finding none, boots nothing. The built image ends up with the same partition layout as the stock
one, and the EFI partition is byte for byte the one Ubuntu shipped.

The arguments are inserted **before** the `---` separator on the kernel line. Anything after that
separator is passed to the installed system rather than the installer, so an image built the
other way boots normally and quietly does not autoinstall at all.
