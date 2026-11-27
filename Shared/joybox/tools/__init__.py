# Imports
from .appimagetool import AppImageTool
from .balenaetcher import BalenaEtcher
from .bchunk import Bchunk
from .brave import Brave
from .cdecrypt import CDecrypt
from .chrome import Chrome
from .chromedriver import ChromeDriver
from .cmake import Cmake
from .curl import Curl
from .dxvk import DXVK
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
from .unar import Unar
from .unrar import Unrar
from .unzip import Unzip
from .vkd3d import VKD3D
from .wad2bin import Wad2Bin
from .wine import Wine
from .xcitrimmer import XCITrimmer
from .xorriso import XorrISO
from .ytdlp import YtDlp
from .zoomplatformsh import ZoomPlatformSH

# Every tool class, in registration order
TOOL_CLASSES = (
    AppImageTool,
    BalenaEtcher,
    Bchunk,
    Brave,
    CDecrypt,
    Chrome,
    ChromeDriver,
    Cmake,
    Curl,
    DXVK,
    ExifTool,
    ExtractXIso,
    FFMpeg,
    Firefox,
    FuseISO,
    GeckoDriver,
    Ghidra,
    Git,
    GoldbergEmu,
    Gpg,
    HacTool,
    Heirloom,
    HeroicGogDL,
    HumbleBundleManager,
    ItchDL,
    JDupes,
    Mkpl,
    Legendary,
    LGOGDownloader,
    Ludusavi,
    LudusaviManifest,
    MameTools,
    Moonlight,
    Mutagen,
    NDecrypt,
    NirCmd,
    Nile,
    Pegasus,
    Perl,
    ProjectCTR,
    PS3Dec,
    PSNGetPkgInfo,
    PSVStrip,
    PSVTools,
    PyLnk,
    PySimpleGUI,
    PySteamGridDB,
    Python,
    RClone,
    Sandboxie,
    SevenZip,
    Sigtop,
    Steam,
    SteamAppIDList,
    SteamCMD,
    SteamDepotDownloader,
    Steamless,
    Sunshine,
    Tar,
    ThreeDSRomTool,
    Unar,
    Unrar,
    Unzip,
    VKD3D,
    Wad2Bin,
    Wine,
    XCITrimmer,
    XorrISO,
    YtDlp,
    ZoomPlatformSH,
)

# One instance of every tool class, keyed by its registered name
def get_tool_map():
    instances = {}
    for class_name in TOOL_CLASSES:
        instance = class_name()
        instances[instance.get_name()] = instance
    return instances

# Every tool instance, in registration order
def get_tool_list():
    return get_tool_map().values()

# The tool registered under a name; None when none matches
def get_tool_by_name(tool_name):
    for instance in get_tool_list():
        if instance.get_name() == tool_name:
            return instance
    return None
