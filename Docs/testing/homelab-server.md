# Testing the Homelab Server

[← Testing](README.md)

Run the installer image in a throwaway VM set up the way the real machine is — UEFI firmware, a
blank disk, the image in the drive — and check the result before writing it to a USB stick.

## Before you start

- [ ] The image is built — steps 1–3 of [Homelab Server Setup](../setup/homelab-server.md).
- [ ] QEMU and UEFI firmware installed — see [Testing](README.md).

## Quick steps

**1. Install from the image onto a fresh disk:**

```bash
boot_vm_image -n llm -i ~/Images/llm.iso
```

A window opens and you watch the install. QEMU exits when the installer reboots — that is how
you know it finished. The image would otherwise boot again and start the install over.

**2. Boot what it installed:**

```bash
boot_vm_image -n llm
```

**3. Log in**, from another terminal:

```bash
ssh -i ~/.ssh/joybox_autoinstall -p 2222 you@localhost
```

**4. Check it came out right**, on the VM:

```bash
hostname                           # the hostname you configured
sudo ufw status                    # only OpenSSH and 11434 allowed
systemctl status ollama            # active, once first boot has finished
ollama list                        # the first model, once the pull has finished
gpu-status                         # "No NVIDIA GPU visible" is expected here
```

And from your computer, that a password is refused:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -p 2222 you@localhost
```

**5. Try the API.** Only SSH is forwarded to the VM, so tunnel the port through it:

```bash
ssh -i ~/.ssh/joybox_autoinstall -p 2222 -L 11434:localhost:11434 you@localhost
curl http://localhost:11434/api/tags     # in another terminal
```

**6. Start over** after changing the overlay or settings: rebuild the image, then throw the disk
away:

```bash
boot_vm_image -n llm -i ~/Images/llm.iso -r
```

## Settings

The VM's size and where its disk is kept come from `~/JoyBox.ini`, and each has a flag to
override it for one run:

```ini
[UserData.VM]
vm_dir = $HOME/VirtualMachines
vm_memory = 6144
vm_vcpus = 4
vm_disk_size = 60
vm_ssh_port = 2222
```

Each `-n` name gets its own disk and firmware variables in `vm_dir`, so several images can be
tried side by side. Give the server image at least 4 GB of memory: the installer unpacks into
RAM. All flags are on the [`boot_vm_image`](../reference/man/boot_vm_image.md) page.

## Without a window

`--headless` puts the console on your terminal instead. It is only useful for an image built
with `--serial_console`; otherwise the kernel logs to the screen and the terminal shows nothing
after the boot menu.

```bash
build_autoinstall_iso -o ~/Images -n llm.iso --serial_console
boot_vm_image -n llm -i ~/Images/llm.iso --headless
```

## What a VM cannot tell you

- **The GPU.** None is passed through, so `drivers: install: true` finds nothing and ollama runs
  on the processor. Driver installation is only exercised on real hardware.
- **The real disk.** The install takes the largest disk it finds; in the VM that is the only one.

Everything else — the disk layout, the account, the key, the firewall, the services the overlay
adds — behaves here as it will on the machine.

Without `/dev/kvm` the VM still runs, slowly enough that an install is a wait rather than a
test; `boot_vm_image` says so when it starts.
