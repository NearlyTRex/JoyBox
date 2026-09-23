# Testing

[← Docs index](../README.md)

Both servers can be rehearsed on a throwaway VM on your own computer before touching real
hardware. They use different tools, because they test different things.

| | [Remote server](remote-server.md) | [Homelab server](homelab-server.md) |
|---|---|---|
| What it proves | `bootstrap.py -t remote_ubuntu` deploys, hardens and backs up a server | The USB image installs itself and comes up usable |
| Tool | `testvm` (libvirt, needs `sudo`) | `boot_vm_image` (plain QEMU, no root) |
| Starts from | Ubuntu's cloud image, ready to SSH into | Your built installer ISO on a blank UEFI disk |
| Reached at | Its own address on libvirt's NAT network, as `joybox.test` | `localhost:2222` |
| Kept in | `/var/lib/libvirt/images` | `vm_dir`, `~/VirtualMachines` by default |
| Undo | Snapshots: `testvm snapshot` / `testvm revert` | `boot_vm_image -r` starts from a blank disk |

Your computer needs the virtualization packages, which the `aptget` component installs:

```bash
python3 bootstrap.py -a setup -t local_ubuntu --components aptget
ls -l /dev/kvm     # present and usable by you, or the VMs crawl
```
