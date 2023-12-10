# Imports
from . import appimagetool
from . import cdecrypt
from . import dxvk
from . import exiftool
from . import extractxiso
from . import ffmpeg
from . import geckodriver
from . import hactool
from . import ludusavi
from . import mametools
from . import ndecrypt
from . import nircmd
from . import pegasus
from . import projectctr
from . import ps3dec
from . import psngetpkginfo
from . import psvstrip
from . import psvtools
from . import pylnk
from . import rclone
from . import sunshine
from . import threedsromtool
from . import vkd3d
from . import wad2bin
from . import xcitrimmer

# Tool instances
instances = [
    appimagetool.AppImageTool(),
    cdecrypt.CDecrypt(),
    dxvk.DXVK(),
    exiftool.ExifTool(),
    extractxiso.ExtractXIso(),
    ffmpeg.FFMpeg(),
    geckodriver.GeckoDriver(),
    hactool.HacTool(),
    ludusavi.Ludusavi(),
    mametools.MameTools(),
    ndecrypt.NDecrypt(),
    nircmd.NirCmd(),
    pegasus.Pegasus(),
    projectctr.ProjectCTR(),
    ps3dec.PS3Dec(),
    psngetpkginfo.PSNGetPkgInfo(),
    psvstrip.PSVStrip(),
    psvtools.PSVTools(),
    pylnk.PyLnk(),
    rclone.RClone(),
    sunshine.Sunshine(),
    threedsromtool.ThreeDSRomTool(),
    vkd3d.VKD3D(),
    wad2bin.Wad2Bin(),
    xcitrimmer.XCITrimmer()
]

# Get tools
def GetTools():
    return instances
