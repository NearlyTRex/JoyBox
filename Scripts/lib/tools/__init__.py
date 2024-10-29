# Imports
from .appimagetool import AppImageTool
from .balenaetcher import BalenaEtcher
from .cdecrypt import CDecrypt
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
    instances["AppImageTool"] = AppImageTool()
    instances["BalenaEtcher"] = BalenaEtcher()
    instances["CDecrypt"] = CDecrypt()
    instances["ChromeDriver"] = ChromeDriver()
    instances["Curl"] = Curl()
    instances["DXVK"] = DXVK()
    instances["ExifTool"] = ExifTool()
    instances["ExtractXIso"] = ExtractXIso()
    instances["FFMpeg"] = FFMpeg()
    instances["Firefox"] = Firefox()
    instances["GeckoDriver"] = GeckoDriver()
    instances["Git"] = Git()
    instances["GoldbergEmu"] = GoldbergEmu()
    instances["Gpg"] = Gpg()
    instances["HacTool"] = HacTool()
    instances["ItchDL"] = ItchDL()
    instances["JDupes"] = JDupes()
    instances["Mkpl"] = Mkpl()
    instances["Legendary"] = Legendary()
    instances["LGOGDownloader"] = LGOGDownloader()
    instances["Ludusavi"] = Ludusavi()
    instances["LudusaviManifest"] = LudusaviManifest()
    instances["MameTools"] = MameTools()
    instances["Moonlight"] = Moonlight()
    instances["NDecrypt"] = NDecrypt()
    instances["NirCmd"] = NirCmd()
    instances["Nile"] = Nile()
    instances["Pegasus"] = Pegasus()
    instances["Perl"] = Perl()
    instances["ProjectCTR"] = ProjectCTR()
    instances["PS3Dec"] = PS3Dec()
    instances["PSNGetPkgInfo"] = PSNGetPkgInfo()
    instances["PSVStrip"] = PSVStrip()
    instances["PSVTools"] = PSVTools()
    instances["PyLnk"] = PyLnk()
    instances["PySimpleGUI"] = PySimpleGUI()
    instances["Python"] = Python()
    instances["RClone"] = RClone()
    instances["Sandboxie"] = Sandboxie()
    instances["SevenZip"] = SevenZip()
    instances["Sigtop"] = Sigtop()
    instances["Steam"] = Steam()
    instances["SteamCMD"] = SteamCMD()
    instances["SteamDepotDownloader"] = SteamDepotDownloader()
    instances["Steamless"] = Steamless()
    instances["Sunshine"] = Sunshine()
    instances["Tar"] = Tar()
    instances["ThreeDSRomTool"] = ThreeDSRomTool()
    instances["VKD3D"] = VKD3D()
    instances["Wad2Bin"] = Wad2Bin()
    instances["Wine"] = Wine()
    instances["XCITrimmer"] = XCITrimmer()
    instances["XorrISO"] = XorrISO()
    instances["YtDlp"] = YtDlp()
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
