# Imports
import ares
import atari800
import basiliskii
import bigpemu
import cemu
import citra
import computer
import dolphin
import duckstation
import eka2l1
import flycast
import fsuae
import mame
import mednafen
import melonds
import mgba
import pcsx2
import ppsspp
import retroarch
import rpcs3
import vicec64
import vita3k
import xemu
import xenia
import yuzu

# Get emulators
def GetEmulators():
    return [
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
