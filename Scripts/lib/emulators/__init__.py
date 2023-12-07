# Imports
from . import ares
from . import atari800
from . import basiliskii
from . import bigpemu
from . import cemu
from . import citra
from . import computer
from . import dolphin
from . import duckstation
from . import eka2l1
from . import flycast
from . import fsuae
from . import mame
from . import mednafen
from . import melonds
from . import mgba
from . import pcsx2
from . import ppsspp
from . import retroarch
from . import rpcs3
from . import vicec64
from . import vita3k
from . import xemu
from . import xenia
from . import yuzu

# Emulator instances
instances = [
    ares.Ares(),
    atari800.Atari800(),
    basiliskii.BasiliskII(),
    bigpemu.BigPEmu(),
    cemu.Cemu(),
    citra.Citra(),
    computer.Computer(),
    dolphin.Dolphin(),
    duckstation.DuckStation(),
    eka2l1.EKA2L1(),
    flycast.Flycast(),
    fsuae.FSUAE(),
    mame.Mame(),
    mednafen.Mednafen(),
    melonds.MelonDS(),
    mgba.MGBA(),
    pcsx2.PCSX2(),
    ppsspp.PPSSPP(),
    retroarch.RetroArch(),
    rpcs3.RPCS3(),
    vicec64.ViceC64(),
    vita3k.Vita3K(),
    xemu.Xemu(),
    xenia.Xenia(),
    yuzu.Yuzu()
]

# Get emulators
def GetEmulators():
    return instances
