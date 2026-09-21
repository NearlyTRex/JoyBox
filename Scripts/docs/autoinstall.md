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

| Flag | Default | Meaning |
|------|---------|---------|
| `-o`, `--output_path` | current directory | Directory to write the image into |
| `-n`, `--output_name` | `ubuntu-autoinstall.iso` | Name of the image |
| `-s`, `--source_iso` | — | Stock image to start from, instead of downloading |
| `-r`, `--release` | from settings | Ubuntu release to build from |
| `-t`, `--hostname` | from settings | Hostname for the installed machine |
| `-y`, `--overlay` | from settings | YAML merged into the generated config |
| `-w`, `--show_seed` | off | Print the seed this configuration produces and stop |
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

## Try it in a machine first

Write the image to a stick only after it has installed something. `boot_vm_image` runs it in a
throwaway machine set up the way the target is — UEFI firmware, a blank disk, the image in the
drive:

```bash
# Install from the image onto a fresh disk
boot_vm_image -n llm -i ~/Images/llm.iso

# Boot what it installed, afterwards
boot_vm_image -n llm
```

A window opens and you watch it. Qemu exits when the installer reboots, which is how you know
it finished — the image is still in the drive, so a machine that carried on would boot it again
and start the install over.

The disk and the machine's own copy of the firmware variables are kept in `vm_dir`, named after
`-n`, so several images can be tried side by side without touching each other:

```ini
[UserData.VM]
vm_dir = $HOME/VirtualMachines
vm_memory = 6144
vm_vcpus = 4
vm_disk_size = 60
vm_ssh_port = 2222
```

| Flag | Meaning |
|------|---------|
| `-n`, `--name` | Machine name, which names its disk and firmware variables |
| `-i`, `--iso` | Image to install from; leave it out to boot what was installed |
| `-m`, `--memory` | Memory in MB — the server image unpacks into RAM, so 4096 is tight |
| `-c`, `--vcpus` | Processor count |
| `-z`, `--disk_size` | Disk size in GB, used when the disk is made |
| `-t`, `--ssh_port` | Local port forwarded to the machine's SSH; `0` for no network at all |
| `-e`, `--headless` | Open no window and put the console on this terminal |
| `-l`, `--serial_file` | With `--headless`, write the console to a file |
| `-r`, `--reset` | Throw the disk away and start from nothing |

Reach the installed machine with `ssh -p 2222 <user>@localhost`.

`--headless` is only worth using on an image built with `--serial_console`; without it the kernel
logs to the screen and the terminal shows nothing after the boot menu.

**What a machine cannot tell you**: there is no GPU passed through, so `drivers: install: true`
finds nothing and ollama runs on the processor. That half is only exercised on real hardware.
Everything else — the disk layout, the account, the key, the firewall, the services the overlay
adds — behaves here exactly as it will there.

Without `/dev/kvm` the machine still runs, slowly enough that an install is a wait rather than a
test; the command says so when it starts.

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
