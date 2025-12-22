# Imports
from .a7800 import A7800
from .ares import Ares
from .atari800 import Atari800
from .basiliskii import BasiliskII
from .bgb import BGB
from .bigpemu import BigPEmu
from .blastem import BlastEm
from .bsnes import BSnes
from .cemu import Cemu
from .citra import Citra
from .computer import Computer
from .cxbxreloaded import CxBxReloaded
from .demul import Demul
from .dolphin import Dolphin
from .duckstation import DuckStation
from .eka2l1 import EKA2L1
from .flycast import Flycast
from .fsuae import FSUAE
from .kegafusion import KegaFusion
from .mame import Mame
from .mednafen import Mednafen
from .melonds import MelonDS
from .mesen import Mesen
from .mgba import MGBA
from .nestopia import Nestopia
from .pcem import PCEm
from .pcsx2 import PCSX2
from .phoenix import Phoenix
from .ppsspp import PPSSPP
from .retroarch import RetroArch
from .rpcs3 import RPCS3
# from .ryujinx import Ryujinx
from .sameboy import SameBoy
from .sheepshaver import SheepShaver
from .snes9x import Snes9x
from .stella import Stella
from .vicec64 import ViceC64
from .vita3k import Vita3K
from .winuae import WinUAE
from .xemu import Xemu
from .xenia import Xenia
from .yuzu import Yuzu

# Get emulator map
def get_emulator_map():
    instances = {}
    def AddInstance(class_name):
        instance = class_name()
        instances[instance.GetName()] = instance
    AddInstance(A7800)
    AddInstance(Ares)
    AddInstance(Atari800)
    AddInstance(BasiliskII)
    AddInstance(BGB)
    AddInstance(BigPEmu)
    AddInstance(BlastEm)
    AddInstance(BSnes)
    AddInstance(Cemu)
    AddInstance(Citra)
    AddInstance(Computer)
    AddInstance(CxBxReloaded)
    AddInstance(Demul)
    AddInstance(Dolphin)
    AddInstance(DuckStation)
    AddInstance(EKA2L1)
    AddInstance(Flycast)
    AddInstance(FSUAE)
    AddInstance(KegaFusion)
    AddInstance(Mame)
    AddInstance(Mesen)
    AddInstance(Mednafen)
    AddInstance(MelonDS)
    AddInstance(MGBA)
    AddInstance(Nestopia)
    AddInstance(PCEm)
    AddInstance(PCSX2)
    AddInstance(Phoenix)
    AddInstance(PPSSPP)
    AddInstance(RetroArch)
    AddInstance(RPCS3)
    # AddInstance(Ryujinx)
    AddInstance(SameBoy)
    AddInstance(SheepShaver)
    AddInstance(Snes9x)
    AddInstance(Stella)
    AddInstance(ViceC64)
    AddInstance(Vita3K)
    AddInstance(WinUAE)
    AddInstance(Xemu)
    AddInstance(Xenia)
    AddInstance(Yuzu)
    return instances

# Get emulator list
def get_emulator_list():
    return get_emulator_map().values()

# Get emulator by name
def get_emulator_by_name(tool_name):
    for instance in get_emulator_list():
        if instance.GetName() == tool_name:
            return instance
    return None
