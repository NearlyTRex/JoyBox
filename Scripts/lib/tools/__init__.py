# Imports
from .appimagetool import AppImageTool
from .balenaetcher import BalenaEtcher
from .brave import Brave
from .cdecrypt import CDecrypt
from .chrome import Chrome
from .chromedriver import ChromeDriver
from .curl import Curl
from .dxvk import DXVK
from .dxvk import GetLibs32 as GetDXVKLibs32
from .dxvk import GetLibs64 as GetDXVKLibs64
from .exiftool import ExifTool
from .extractxiso import ExtractXIso
from .ffmpeg import FFMpeg
from .firefox import Firefox
from .geckodriver import GeckoDriver
from .git import Git
from .goldbergemu import GoldbergEmu
from .gpg import Gpg
from .hactool import HacTool
from .heirloom import Heirloom
from .itchdl import ItchDL
from .jdupes import JDupes
from .mkpl import Mkpl
from .legendary import Legendary
from .lgogdownloader import LGOGDownloader
from .ludusavi import Ludusavi
from .ludusavimanifest import LudusaviManifest
from .ludusavimanifest import GetManifest
from .mametools import MameTools
from .moonlight import Moonlight
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
from .steamcmd import SteamCMD
from .steamdepotdownloader import SteamDepotDownloader
from .steamless import Steamless
from .sunshine import Sunshine
from .tar import Tar
from .threedsromtool import ThreeDSRomTool
from .vkd3d import VKD3D
from .vkd3d import GetLibs32 as GetVKD3DLibs32
from .vkd3d import GetLibs64 as GetVKD3DLibs64
from .wad2bin import Wad2Bin
from .wine import Wine
from .xcitrimmer import XCITrimmer
from .xorriso import XorrISO
from .ytdlp import YtDlp

# Get tool map
def GetToolMap():
    instances = {}
    def AddInstance(class_name):
        instance = class_name()
        instances[instance.GetName()] = instance
    AddInstance(AppImageTool)
    AddInstance(BalenaEtcher)
    AddInstance(Brave)
    AddInstance(CDecrypt)
    AddInstance(Chrome)
    AddInstance(ChromeDriver)
    AddInstance(Curl)
    AddInstance(DXVK)
    AddInstance(ExifTool)
    AddInstance(ExtractXIso)
    AddInstance(FFMpeg)
    AddInstance(Firefox)
    AddInstance(GeckoDriver)
    AddInstance(Git)
    AddInstance(GoldbergEmu)
    AddInstance(Gpg)
    AddInstance(HacTool)
    AddInstance(Heirloom)
    AddInstance(ItchDL)
    AddInstance(JDupes)
    AddInstance(Mkpl)
    AddInstance(Legendary)
    AddInstance(LGOGDownloader)
    AddInstance(Ludusavi)
    AddInstance(LudusaviManifest)
    AddInstance(MameTools)
    AddInstance(Moonlight)
    AddInstance(NDecrypt)
    AddInstance(NirCmd)
    AddInstance(Nile)
    AddInstance(Pegasus)
    AddInstance(Perl)
    AddInstance(ProjectCTR)
    AddInstance(PS3Dec)
    AddInstance(PSNGetPkgInfo)
    AddInstance(PSVStrip)
    AddInstance(PSVTools)
    AddInstance(PyLnk)
    AddInstance(PySimpleGUI)
    AddInstance(PySteamGridDB)
    AddInstance(Python)
    AddInstance(RClone)
    AddInstance(Sandboxie)
    AddInstance(SevenZip)
    AddInstance(Sigtop)
    AddInstance(Steam)
    AddInstance(SteamCMD)
    AddInstance(SteamDepotDownloader)
    AddInstance(Steamless)
    AddInstance(Sunshine)
    AddInstance(Tar)
    AddInstance(ThreeDSRomTool)
    AddInstance(VKD3D)
    AddInstance(Wad2Bin)
    AddInstance(Wine)
    AddInstance(XCITrimmer)
    AddInstance(XorrISO)
    AddInstance(YtDlp)
    return instances

# Get tool list
def GetToolList():
    return GetToolMap().values()

# Get tool by name
def GetToolByName(tool_name):
    for instance in GetToolList():
        if instance.GetName() == tool_name:
            return instance
    return None
