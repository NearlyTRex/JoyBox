# Testing

[← Docs index](../README.md)

Both servers can be rehearsed on a throwaway VM on your own computer before touching real
hardware. They use different tools, because they test different things.

| | [Remote server](remote-server.md) | [Homelab server](homelab-server.md) |
|---|---|---|
| What it proves | `provision_server` builds, deploys, hardens and verifies a server, and `bootstrap.py` backs it up | The USB image installs itself and comes up usable |
| Tool | `provision_server` and `testvm` (libvirt; `sudo` only for images and `/etc/hosts`) | `boot_vm_image` (plain QEMU, no root) |
| Starts from | Ubuntu's cloud image, with root reachable by your key | Your built installer ISO on a blank UEFI disk |
| Reached at | A fixed address on libvirt's NAT network, `192.168.122.10`, as its server entry's domain | `localhost:2222` |
| Kept in | `/var/lib/libvirt/images` | `vm_dir`, `~/VirtualMachines` by default |
| Undo | Snapshots: `testvm snapshot` / `testvm revert` | `boot_vm_image -r` starts from a blank disk |

Your computer needs the virtualization packages, which the `aptget` component installs:

```bash
python3 bootstrap.py -a setup -t local_ubuntu --components aptget
ls -l /dev/kvm     # present and usable by you, or the VMs crawl
```
