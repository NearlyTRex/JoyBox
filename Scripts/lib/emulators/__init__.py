# Imports
from . import a7800
from . import ares
from . import atari800
from . import basiliskii
from . import bgb
from . import bigpemu
from . import blastem
from . import bsnes
from . import cemu
from . import citra
from . import computer
from . import cxbxreloaded
from . import demul
from . import dolphin
from . import duckstation
from . import eka2l1
from . import flycast
from . import fsuae
from . import kegafusion
from . import mame
from . import mednafen
from . import melonds
from . import mgba
from . import nestopia
from . import pcem
from . import pcsx2
from . import phoenix
from . import ppsspp
from . import retroarch
from . import rpcs3
from . import ryujinx
from . import vicec64
from . import vita3k
from . import xemu
from . import xenia
from . import yuzu

# Emulator instances
instances = [
    a7800.A7800(),
    ares.Ares(),
    atari800.Atari800(),
    basiliskii.BasiliskII(),
    bgb.BGB(),
    bigpemu.BigPEmu(),
    blastem.BlastEm(),
    bsnes.BSnes(),
    cemu.Cemu(),
    citra.Citra(),
    computer.Computer(),
    cxbxreloaded.CxBxReloaded(),
    demul.Demul(),
    dolphin.Dolphin(),
    duckstation.DuckStation(),
    eka2l1.EKA2L1(),
    flycast.Flycast(),
    fsuae.FSUAE(),
    kegafusion.KegaFusion(),
    mame.Mame(),
    mednafen.Mednafen(),
    melonds.MelonDS(),
    mgba.MGBA(),
    nestopia.Nestopia(),
    pcem.PCEm(),
    pcsx2.PCSX2(),
    phoenix.Phoenix(),
    ppsspp.PPSSPP(),
    retroarch.RetroArch(),
    rpcs3.RPCS3(),
    ryujinx.Ryujinx(),
    vicec64.ViceC64(),
    vita3k.Vita3K(),
    xemu.Xemu(),
    xenia.Xenia(),
    yuzu.Yuzu()
]

# Get emulators
def GetEmulators():
    return instances
