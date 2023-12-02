# Imports
import os
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import environment
import sandbox

# Get base directory
def GetBaseDirectory():
    return environment.GetScriptsExtDir()

# Get prefix name
def GetPrefixName():
    return config.prefix_name_tool

# Get prefix dir
def GetPrefixDir():
    return sandbox.GetPrefix(
        name = config.prefix_name_tool,
        is_wine_prefix = environment.IsWinePlatform(),
        is_sandboxie_prefix = environment.IsSandboxiePlatform())

# Config
def GetConfig():
    return {

        # 3DSRomTool
        "3DSRomTool": {
            "program": {
                "windows": "3DSRomTool/windows/rom_tool.exe",
                "linux": "3DSRomTool/windows/3DSRomTool.AppImage"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # 7-Zip
        "7-Zip": {
            "program": {
                "windows": "7-Zip/windows/7z.exe",
                "linux": "7-Zip/windows/7z.exe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # 7-Zip-Standalone
        "7-Zip-Standalone": {
            "program": {
                "windows": "7-Zip/windows/7za.exe",
                "linux": "7-Zip/windows/7za.exe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # AppImageTool
        "AppImageTool": {
            "program": {
                "windows": None,
                "linux": "AppImageTool/linux/AppImageTool.AppImage"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # CDecrypt
        "CDecrypt": {
            "program": {
                "windows": "CDecrypt/windows/cdecrypt.exe",
                "linux": "CDecrypt/windows/CDecrypt.AppImage"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # CtrTool
        "CtrTool": {
            "program": {
                "windows": "CtrTool/windows/ctrtool.exe",
                "linux": "CtrTool/windows/ctrtool.exe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # CtrToolMakeRom
        "CtrToolMakeRom": {
            "program": {
                "windows": "CtrTool/windows/makerom.exe",
                "linux": "CtrTool/windows/makerom.exe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # ExifTool
        "ExifTool": {
            "program": {
                "windows": "ExifTool/windows/exiftool.exe",
                "linux": "ExifTool/linux/exiftool"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # ExtractXIso
        "ExtractXIso": {
            "program": {
                "windows": "ExtractXIso/windows/extract-xiso.exe",
                "linux": "ExtractXIso/windows/extract-xiso.exe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # FFMpeg
        "FFMpeg": {
            "program": {
                "windows": "FFMpeg/windows/ffmpeg.exe",
                "linux": "FFMpeg/linux/ffmpeg"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # GeckoDriver
        "GeckoDriver": {
            "program": {
                "windows": "GeckoDriver/windows/geckodriver.exe",
                "linux": "GeckoDriver/linux/geckodriver"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # HacTool
        "HacTool": {
            "program": {
                "windows": "HacTool/windows/hactool.exe",
                "linux": "HacTool/linux/HacTool.AppImage"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Ludusavi
        "Ludusavi": {
            "program": {
                "windows": "Ludusavi/windows/ludusavi.exe",
                "linux": "Ludusavi/linux/ludusavi"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # MameToolsChdman
        "MameToolsChdman": {
            "program": {
                "windows": "MameTools/windows/chdman.exe",
                "linux": "MameTools/windows/chdman.exe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # NDecrypt
        "NDecrypt": {
            "program": {
                "windows": "NDecrypt/windows/NDecrypt.exe",
                "linux": "NDecrypt/linux/NDecrypt"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # NirCmd
        "NirCmd": {
            "program": {
                "windows": "NirCmd/windows/nircmdc.exe",
                "linux": "NirCmd/windows/nircmdc.exe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # Pegasus
        "Pegasus": {
            "program": {
                "windows": "Pegasus/windows/pegasus-fe.exe",
                "linux": "Pegasus/linux/pegasus-fe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Pkg2AppImage
        "Pkg2AppImage": {
            "program": {
                "windows": None,
                "linux": "Pkg2AppImage/linux/Pkg2AppImage.AppImage"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # PS3Dec
        "PS3Dec": {
            "program": {
                "windows": "PS3Dec/windows/PS3Dec.exe",
                "linux": "PS3Dec/windows/PS3Dec.exe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # PSVStrip
        "PSVStrip": {
            "program": {
                "windows": "PSVStrip/windows/psvstrip.exe",
                "linux": "PSVStrip/windows/psvstrip.exe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # RClone
        "RClone": {
            "program": {
                "windows": "RClone/windows/rclone.exe",
                "linux": "RClone/linux/rclone"
            },
            "config_file": {
                "windows": "RClone/windows/rclone.conf",
                "linux": "RClone/linux/rclone.conf"
            },
            "cache_dir": {
                "windows": "RClone/windows/cache",
                "linux": "RClone/linux/cache"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Sunshine
        "Sunshine": {
            "program": {
                "windows": "Sunshine/windows/sunshine.exe",
                "linux": "Sunshine/linux/Sunshine.AppImage"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Wad2Bin
        "Wad2Bin": {
            "program": {
                "windows": "Wad2Bin/windows/wad2bin.exe",
                "linux": "Wad2Bin/windows/wad2bin.exe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # XCICutter
        "XCICutter": {
            "program": {
                "windows": "XCICutter/windows/XCI-Cutter.exe",
                "linux": "XCICutter/windows/XCI-Cutter.exe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # XexTool
        "XexTool": {
            "program": {
                "windows": "XexTool/windows/xextool.exe",
                "linux": "XexTool/windows/xextool.exe"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        }
    }
