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
from .computer import GetDosLaunchCommand as GetComputerDosLaunchCommand
from .computer import ResolveJsonPath as ResolveComputerJsonPath
from .computer import ResolveJsonPaths as ResolveComputerJsonPaths
from .computer import BuildDiscTokenMap as BuildComputerDiscTokenMap
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
from .ryujinx import Ryujinx
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
def GetEmulatorMap():
    instances = {}
    instances["A7800"] = A7800()
    instances["Ares"] = Ares()
    instances["Atari800"] = Atari800()
    instances["BasiliskII"] = BasiliskII()
    instances["BGB"] = BGB()
    instances["BigPEmu"] = BigPEmu()
    instances["BlastEm"] = BlastEm()
    instances["BSnes"] = BSnes()
    instances["Cemu"] = Cemu()
    instances["Citra"] = Citra()
    instances["Computer"] = Computer()
    instances["CxBxReloaded"] = CxBxReloaded()
    instances["Demul"] = Demul()
    instances["Dolphin"] = Dolphin()
    instances["DuckStation"] = DuckStation()
    instances["EKA2L1"] = EKA2L1()
    instances["Flycast"] = Flycast()
    instances["FSUAE"] = FSUAE()
    instances["KegaFusion"] = KegaFusion()
    instances["Mame"] = Mame()
    instances["Mesen"] = Mesen()
    instances["Mednafen"] = Mednafen()
    instances["MelonDS"] = MelonDS()
    instances["MGBA"] = MGBA()
    instances["Nestopia"] = Nestopia()
    instances["PCEm"] = PCEm()
    instances["PCSX2"] = PCSX2()
    instances["Phoenix"] = Phoenix()
    instances["PPSSPP"] = PPSSPP()
    instances["RetroArch"] = RetroArch()
    instances["RPCS3"] = RPCS3()
    instances["Ryujinx"] = Ryujinx()
    instances["SameBoy"] = SameBoy()
    instances["SheepShaver"] = SheepShaver()
    instances["Snes9x"] = Snes9x()
    instances["Stella"] = Stella()
    instances["ViceC64"] = ViceC64()
    instances["Vita3K"] = Vita3K()
    instances["WinUAE"] = WinUAE()
    instances["Xemu"] = Xemu()
    instances["Xenia"] = Xenia()
    instances["Yuzu"] = Yuzu()
    return instances

# Get emulator list
def GetEmulatorList():
    return GetEmulatorMap().values()

# Get emulator by name
def GetEmulatorByName(tool_name):
    for instance in GetEmulatorMap().values():
        if instance.GetName() == tool_name:
            return instance
    return None
