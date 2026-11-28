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

# Every emulator class, in registration order
EMULATOR_CLASSES = (
    A7800,
    Ares,
    Atari800,
    BasiliskII,
    BGB,
    BigPEmu,
    BlastEm,
    BSnes,
    Cemu,
    Citra,
    Computer,
    CxBxReloaded,
    Demul,
    Dolphin,
    DuckStation,
    EKA2L1,
    Flycast,
    FSUAE,
    KegaFusion,
    Mame,
    Mesen,
    Mednafen,
    MelonDS,
    MGBA,
    Nestopia,
    PCEm,
    PCSX2,
    Phoenix,
    PPSSPP,
    RetroArch,
    RPCS3,
    SameBoy,
    SheepShaver,
    Snes9x,
    Stella,
    ViceC64,
    Vita3K,
    WinUAE,
    Xemu,
    Xenia,
    Yuzu,
)

# One instance of every emulator class, keyed by its registered name
def get_emulator_map():
    instances = {}
    for class_name in EMULATOR_CLASSES:
        instance = class_name()
        instances[instance.get_name()] = instance
    return instances

# Every emulator instance, in registration order
def get_emulator_list():
    return get_emulator_map().values()

# Get the emulator that runs a platform
def get_emulator_by_platform(emulator_platform):
    for instance in get_emulator_list():
        if emulator_platform in instance.get_platforms():
            return instance
    return None

# The emulator registered under a name; None when none matches
def get_emulator_by_name(emulator_name):
    for instance in get_emulator_list():
        if instance.get_name() == emulator_name:
            return instance
    return None
