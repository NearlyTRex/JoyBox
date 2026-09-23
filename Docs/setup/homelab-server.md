# Homelab Server Setup

[← Docs index](../README.md)

Set up a machine on your home network from a USB stick that installs Ubuntu Server by itself.
You build the image on your own computer, boot the machine from it, and come back to a server you
can SSH into. The image in the tree makes a GPU LLM server running ollama; the same steps work
with any overlay.

Try the image in a VM before writing it to a stick — see
[Testing the Homelab Server](../testing/homelab-server.md).

## Before you start

- [ ] Your own computer is set up — [Local Computer Setup](local-computer.md).
- [ ] The ISO tool installed: `setup_tools -k XorrISO`.
- [ ] Signed in to the 1Password CLI (`op signin`) if `~/JoyBox.ini` references secrets — see
      [Secrets](../reference/secrets.md).
- [ ] A USB stick of 4 GB or more whose contents you don't need.
- [ ] The target machine plugged into the network by cable. The installer downloads packages.
- [ ] **Nothing on the target's disks you want to keep.** The install erases the machine's
      largest disk without asking. Unplug any other drive you care about.

## Quick steps

**1. Describe the machine in `~/JoyBox.ini`:**

```ini
[UserData.Autoinstall]
autoinstall_version = 26.04
autoinstall_username = you
autoinstall_realname = You
autoinstall_hostname = llm
autoinstall_ssh_keys = ssh-ed25519 AAAA... you@example.com
autoinstall_timezone = America/Los_Angeles
autoinstall_overlay_file = $HOME/Repositories/JoyBox/Scripts/autoinstall/homelab_llm.yaml
```

No key yet? `ssh-keygen -t ed25519 -f ~/.ssh/joybox_autoinstall` and use the `.pub` file's
contents.

**2. Look at what the installer will be told:**

```bash
build_autoinstall_iso --show_seed
```

It prints the seed and names anything still missing. Nothing is downloaded or written.

**3. Build the image:**

```bash
build_autoinstall_iso -o ~/Images -n llm.iso
```

This downloads Ubuntu, checks its checksum and Ubuntu's signature over it, and writes
`~/Images/llm.iso`. Already downloaded Ubuntu? Add `-s ~/Images/ubuntu-server-26.04.iso`.

**4. Try it in a VM** — [Testing the Homelab Server](../testing/homelab-server.md). It catches a
bad seed before it costs you a trip to the machine.

**5. Write it to the stick.** Find the stick's device name — check the size, because the wrong
device here is a disk erased:

```bash
lsblk -d -o NAME,SIZE,MODEL,TRAN
sudo dd if=~/Images/llm.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

**6. Install.** Boot the target from the stick (the firmware's boot menu key is usually F11, F12
or Esc). The menu waits two seconds, then the install runs on its own. When the machine
reboots, **pull the stick out** so it boots the installed system instead of the installer.

**7. Log in:**

```bash
ssh you@192.168.1.50     # the address your router gave it
```

On the LLM image, give it a few minutes after the first boot for ollama to install and pull its
first model, then:

```bash
gpu-status                                  # on the server
curl http://192.168.1.50:11434/api/tags     # from your computer
```

## Where to go next

- [Autoinstall Images](../homelab-server/autoinstall.md) — every setting, overlays, and what the
  build does to the image.
- [The LLM server image](../homelab-server/llm-overlay.md) — what the overlay installs, and the
  API's lack of authentication.
- [`build_autoinstall_iso`](../reference/man/build_autoinstall_iso.md) — all flags.
