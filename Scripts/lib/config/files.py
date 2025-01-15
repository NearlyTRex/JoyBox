# Imports
import os
import sys

# Local imports
from . import types

# Disc image file type
class DiscImageFileType(types.EnumType):
    ISO                     = ("ISO", ".iso")
    CUE                     = ("CUE", ".cue")
    GDI                     = ("GDI", ".gdi")
    CHD                     = ("CHD", ".chd")

# Image types
class ImageFileType(types.EnumType):
    JPEG                    = ("JPEG", ".jpg")
    PNG                     = ("PNG", ".png")

# Encrypted file types
class EncryptedFileType(types.EnumType):
    ENC                     = ("ENC", ".enc")
    MENC                    = ("MENC", ".menc")

# Archive types
class ArchiveFileType(types.EnumType):

    # Zip
    ZIP                     = ("ZIP", ".zip")
    INSTALL                 = ("INSTALL", ".install")

    # 7z
    SEVENZIP                = ("7Z", ".7z")

    # Rar
    RAR                     = ("RAR", ".rar")

    # BZip2
    TAR_BZ2                 = ("TAR_BZ2", ".tar.bz2")
    TB2                     = ("TB2", ".tb2")
    TBZ                     = ("TBZ", ".tbz")
    TBZ2                    = ("TBZ2", ".tbz2")
    TZ2                     = ("TZ2", ".tz2")

    # GZip
    TAR_GZ                  = ("TAR_GZ", ".tar.gz")
    TAZ_GZ                  = ("TAZ_GZ", ".taz")
    TGZ                     = ("TGZ", ".tgz")

    # LZip
    TAR_LZ                  = ("TAR_LZ", ".tar.lz")

    # LZMA
    TAR_LZMA                = ("TAR_LZMA", ".tar.lzma")
    TLZ                     = ("TLZ", ".tlz")

    # LZop
    TAR_LZO                 = ("TAR_LZO", ".tar.lzo")

    # XZ
    TAR_XZ                  = ("TAR_XZ", ".tar.xz")
    TXZ                     = ("TXZ", ".txz")

    # Compress
    TAR_Z                   = ("TAR_Z", ".tar.Z")
    TZ                      = ("TZ", ".tZ")
    TAZ                     = ("TAZ", ".taZ")

    # ZStd
    TAR_ZST                 = ("TAR_ZST", ".tar.zst")
    TZST                    = ("TZST", ".tzst")

    # Executable
    EXE                     = ("EXE", ".exe")

    # AppImage
    APPIMAGE                = ("APPIMAGE", ".AppImage")

# Archive zip file types
class ArchiveZipFileType(types.EnumType):
    ZIP                     = (ArchiveFileType.ZIP.val(), ArchiveFileType.ZIP.cval())
    INSTALL                 = (ArchiveFileType.INSTALL.val(), ArchiveFileType.INSTALL.cval())

# Archive 7z file types
class Archive7zFileType(types.EnumType):
    SEVENZIP                = (ArchiveFileType.SEVENZIP.val(), ArchiveFileType.SEVENZIP.cval())

# Archive rar file types
class ArchiveRarFileType(types.EnumType):
    RAR                     = (ArchiveFileType.RAR.val(), ArchiveFileType.RAR.cval())

# Archive tarball file types
class ArchiveTarballFileType(types.EnumType):

    # BZip2
    TAR_BZ2                 = (ArchiveFileType.TAR_BZ2.val(), ArchiveFileType.TAR_BZ2.cval())
    TB2                     = (ArchiveFileType.TB2.val(), ArchiveFileType.TB2.cval())
    TBZ                     = (ArchiveFileType.TBZ.val(), ArchiveFileType.TBZ.cval())
    TBZ2                    = (ArchiveFileType.TBZ2.val(), ArchiveFileType.TBZ2.cval())
    TZ2                     = (ArchiveFileType.TZ2.val(), ArchiveFileType.TZ2.cval())

    # GZip
    TAR_GZ                  = (ArchiveFileType.TAR_GZ.val(), ArchiveFileType.TAR_GZ.cval())
    TAZ_GZ                  = (ArchiveFileType.TAZ_GZ.val(), ArchiveFileType.TAZ_GZ.cval())
    TGZ                     = (ArchiveFileType.TGZ.val(), ArchiveFileType.TGZ.cval())

    # LZip
    TAR_LZ                  = (ArchiveFileType.TAR_LZ.val(), ArchiveFileType.TAR_LZ.cval())

    # LZMA
    TAR_LZMA                = (ArchiveFileType.TAR_LZMA.val(), ArchiveFileType.TAR_LZMA.cval())
    TLZ                     = (ArchiveFileType.TLZ.val(), ArchiveFileType.TLZ.cval())

    # LZop
    TAR_LZO                 = (ArchiveFileType.TAR_LZO.val(), ArchiveFileType.TAR_LZO.cval())

    # XZ
    TAR_XZ                  = (ArchiveFileType.TAR_XZ.val(), ArchiveFileType.TAR_XZ.cval())
    TXZ                     = (ArchiveFileType.TXZ.val(), ArchiveFileType.TXZ.cval())

    # Compress
    TAR_Z                   = (ArchiveFileType.TAR_Z.val(), ArchiveFileType.TAR_Z.cval())
    TZ                      = (ArchiveFileType.TZ.val(), ArchiveFileType.TZ.cval())
    TAZ                     = (ArchiveFileType.TAZ.val(), ArchiveFileType.TAZ.cval())

    # ZStd
    TAR_ZST                 = (ArchiveFileType.TAR_ZST.val(), ArchiveFileType.TAR_ZST.cval())
    TZST                    = (ArchiveFileType.TZST.val(), ArchiveFileType.TZST.cval())

# Windows program file types
class WindowsProgramFileType(types.EnumType):
    EXE                     = ("EXE", ".exe")
    LNK                     = ("LNK", ".lnk")
    BAT                     = ("BAT", ".bat")

# Linux program file types
class LinuxProgramFileType(types.EnumType):
    APPIMAGE                = ("APPIMAGE", ".AppImage")

# Nintendo WiiU file types
class NintendoWiiUFileType(types.EnumType):
    APP                     = ("APP", ".app")
    H3                      = ("H3", ".h3")
    TIK                     = ("TIK", ".tik")
    TMD                     = ("TMD", ".tmd")
    CERT                    = ("CERT", ".cert")
