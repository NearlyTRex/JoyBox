# Local imports
from joybox import iso


def bootable_command(**kwargs):
    defaults = dict(
        iso_tool = "/tools/xorriso",
        iso_file = "/out.iso",
        source_dir = "/tree",
        volume_name = "A Volume",
        bios_boot_image = "boot/grub/i386-pc/eltorito.img",
        efi_boot_image = "/work/efi.img",
        mbr_image = "/work/mbr.img")
    defaults.update(kwargs)
    return iso.get_bootable_iso_command(**defaults)


# As xorriso prints it, including the colon in its own label
BOOT_REPORT = """Drive current: -indev '/images/ubuntu.iso'
Volume id    : 'Ubuntu-Server 26.04.1 LTS amd64'
El Torito catalog  : 798  1
El Torito cat path : /boot.catalog
El Torito images   :   N  Pltf  B   Emul  Ld_seg  Hdpt  Ldsiz         LBA
El Torito boot img :   1  BIOS  y   none  0x0000  0x00      4         799
El Torito boot img :   2  UEFI  y   none  0x0000  0x00  10296     1426880
El Torito img path :   1  /boot/grub/i386-pc/eltorito.img
El Torito img opts :   1  boot-info-table grub2-boot-info
El Torito img blks :   2  2574
"""
