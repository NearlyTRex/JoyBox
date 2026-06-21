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
    def add_instance(class_name):
        instance = class_name()
        instances[instance.get_name()] = instance
    add_instance(A7800)
    add_instance(Ares)
    add_instance(Atari800)
    add_instance(BasiliskII)
    add_instance(BGB)
    add_instance(BigPEmu)
    add_instance(BlastEm)
    add_instance(BSnes)
    add_instance(Cemu)
    add_instance(Citra)
    add_instance(Computer)
    add_instance(CxBxReloaded)
    add_instance(Demul)
    add_instance(Dolphin)
    add_instance(DuckStation)
    add_instance(EKA2L1)
    add_instance(Flycast)
    add_instance(FSUAE)
    add_instance(KegaFusion)
    add_instance(Mame)
    add_instance(Mesen)
    add_instance(Mednafen)
    add_instance(MelonDS)
    add_instance(MGBA)
    add_instance(Nestopia)
    add_instance(PCEm)
    add_instance(PCSX2)
    add_instance(Phoenix)
    add_instance(PPSSPP)
    add_instance(RetroArch)
    add_instance(RPCS3)
    # add_instance(Ryujinx)
    add_instance(SameBoy)
    add_instance(SheepShaver)
    add_instance(Snes9x)
    add_instance(Stella)
    add_instance(ViceC64)
    add_instance(Vita3K)
    add_instance(WinUAE)
    add_instance(Xemu)
    add_instance(Xenia)
    add_instance(Yuzu)
    return instances

# Get emulator list
def get_emulator_list():
    return get_emulator_map().values()

# Get emulator by name
def get_emulator_by_name(tool_name):
    for instance in get_emulator_list():
        if instance.get_name() == tool_name:
            return instance
    return None
