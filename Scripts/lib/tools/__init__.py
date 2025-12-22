# Imports
from .appimagetool import AppImageTool
from .balenaetcher import BalenaEtcher
from .brave import Brave
from .cdecrypt import CDecrypt
from .chrome import Chrome
from .chromedriver import ChromeDriver
from .curl import Curl
from .dxvk import DXVK
from .dxvk import get_libs32 as get_dxvk_libs32
from .dxvk import get_libs64 as get_dxvk_libs64
from .exiftool import ExifTool
from .extractxiso import ExtractXIso
from .ffmpeg import FFMpeg
from .firefox import Firefox
from .fuseiso import FuseISO
from .geckodriver import GeckoDriver
from .ghidra import Ghidra
from .git import Git
from .goldbergemu import GoldbergEmu
from .gpg import Gpg
from .hactool import HacTool
from .heirloom import Heirloom
from .heroicgogdl import HeroicGogDL
from .humblebundlemanager import HumbleBundleManager
from .itchdl import ItchDL
from .jdupes import JDupes
from .mkpl import Mkpl
from .legendary import Legendary
from .lgogdownloader import LGOGDownloader
from .ludusavi import Ludusavi
from .ludusavimanifest import LudusaviManifest
from .mametools import MameTools
from .moonlight import Moonlight
from .mutagen import Mutagen
from .ndecrypt import NDecrypt
from .nile import Nile
from .nircmd import NirCmd
from .pegasus import Pegasus
from .perl import Perl
from .projectctr import ProjectCTR
from .ps3dec import PS3Dec
from .psngetpkginfo import PSNGetPkgInfo
from .psvstrip import PSVStrip
from .psvtools import PSVTools
from .pylnk import PyLnk
from .pysimplegui import PySimpleGUI
from .pysteamgriddb import PySteamGridDB
from .python import Python
from .rclone import RClone
from .sandboxie import Sandboxie
from .sevenzip import SevenZip
from .sigtop import Sigtop
from .steam import Steam
from .steamappidlist import SteamAppIDList
from .steamcmd import SteamCMD
from .steamdepotdownloader import SteamDepotDownloader
from .steamless import Steamless
from .sunshine import Sunshine
from .tar import Tar
from .threedsromtool import ThreeDSRomTool
from .vkd3d import VKD3D
from .vkd3d import get_libs32 as get_vkd3d_libs32
from .vkd3d import get_libs64 as get_vkd3d_libs64
from .wad2bin import Wad2Bin
from .wine import Wine
from .xcitrimmer import XCITrimmer
from .xorriso import XorrISO
from .ytdlp import YtDlp
from .zoomplatformsh import ZoomPlatformSH

# Get tool map
def get_tool_map():
    instances = {}
    def add_instance(class_name):
        instance = class_name()
        instances[instance.GetName()] = instance
    add_instance(AppImageTool)
    add_instance(BalenaEtcher)
    add_instance(Brave)
    add_instance(CDecrypt)
    add_instance(Chrome)
    add_instance(ChromeDriver)
    add_instance(Curl)
    add_instance(DXVK)
    add_instance(ExifTool)
    add_instance(ExtractXIso)
    add_instance(FFMpeg)
    add_instance(Firefox)
    add_instance(FuseISO)
    add_instance(GeckoDriver)
    add_instance(Ghidra)
    add_instance(Git)
    add_instance(GoldbergEmu)
    add_instance(Gpg)
    add_instance(HacTool)
    add_instance(Heirloom)
    add_instance(HeroicGogDL)
    add_instance(HumbleBundleManager)
    add_instance(ItchDL)
    add_instance(JDupes)
    add_instance(Mkpl)
    add_instance(Legendary)
    add_instance(LGOGDownloader)
    add_instance(Ludusavi)
    add_instance(LudusaviManifest)
    add_instance(MameTools)
    add_instance(Moonlight)
    add_instance(Mutagen)
    add_instance(NDecrypt)
    add_instance(NirCmd)
    add_instance(Nile)
    add_instance(Pegasus)
    add_instance(Perl)
    add_instance(ProjectCTR)
    add_instance(PS3Dec)
    add_instance(PSNGetPkgInfo)
    add_instance(PSVStrip)
    add_instance(PSVTools)
    add_instance(PyLnk)
    add_instance(PySimpleGUI)
    add_instance(PySteamGridDB)
    add_instance(Python)
    add_instance(RClone)
    add_instance(Sandboxie)
    add_instance(SevenZip)
    add_instance(Sigtop)
    add_instance(Steam)
    add_instance(SteamAppIDList)
    add_instance(SteamCMD)
    add_instance(SteamDepotDownloader)
    add_instance(Steamless)
    add_instance(Sunshine)
    add_instance(Tar)
    add_instance(ThreeDSRomTool)
    add_instance(VKD3D)
    add_instance(Wad2Bin)
    add_instance(Wine)
    add_instance(XCITrimmer)
    add_instance(XorrISO)
    add_instance(YtDlp)
    add_instance(ZoomPlatformSH)
    return instances

# Get tool list
def get_tool_list():
    return get_tool_map().values()

# Get tool by name
def get_tool_by_name(tool_name):
    for instance in get_tool_list():
        if instance.GetName() == tool_name:
            return instance
    return None
