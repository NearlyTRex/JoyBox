# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import environment
import sandbox

# Get base directory
def GetBaseDirectory():
    return environment.GetEmulatorsRootDir()

# Get prefix name
def GetPrefixName():
    return config.prefix_name_emulator

# Get prefix dir
def GetPrefixDir():
    return sandbox.GetPrefix(
        name = config.prefix_name_emulator,
        is_wine_prefix = environment.IsWinePlatform(),
        is_sandboxie_prefix = environment.IsSandboxiePlatform())

# Config
def GetConfig():
    return {

        # Ares
        "Ares": {
            "program": {
                "windows": "Ares/windows/ares.exe",
                "linux": "Ares/linux/Ares.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "save_base_dir": {
                "windows": "Ares/windows/Saves",
                "linux": "Ares/linux/Ares.AppImage.home/.local/share/ares/Saves"
            },
            "save_sub_dirs": {

                # Microsoft
                "Microsoft MSX": "MSX",

                # Nintendo
                "Nintendo 64": "Nintendo 64",
                "Nintendo Famicom": "Famicom",
                "Nintendo NES": "Famicom",
                "Nintendo SNES": "Super Famicom",
                "Nintendo Super Famicom": "Super Famicom",

                # Other
                "Atari 2600": "Atari 2600",
                "Bandai WonderSwan": "WonderSwan",
                "Bandai WonderSwan Color": "WonderSwan Color",
                "Coleco ColecoVision": "ColecoVision",
                "NEC SuperGrafx": "SuperGrafx",
                "NEC TurboGrafx CD & PC-Engine CD": "PC Engine CD",
                "NEC TurboGrafx-16 & PC-Engine": "PC Engine",
                "Sega 32X": "Mega 32X",
                "Sega CD": "Mega CD",
                "Sega CD 32X": "Mega CD 32X",
                "Sega Game Gear": "Game Gear",
                "Sega Genesis": "Mega Drive",
                "Sega Master System": "Master System",
                "Sinclair ZX Spectrum": "ZX Spectrum",
                "SNK Neo Geo Pocket Color": "Neo Geo Pocket Color"
            },
            "setup_dir": {
                "windows": "Ares/windows",
                "linux": "Ares/linux/Ares.AppImage.home/.local/share/ares"
            },
            "config_file": {
                "windows": "Ares/windows/settings.bml",
                "linux": "Ares/linux/Ares.AppImage.home/.local/share/ares/settings.bml"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Atari800
        "Atari800": {
            "program": {
                "windows": "Atari800/windows/atari800.exe",
                "linux": "Atari800/linux/Atari800.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "config_file": {
                "windows": None,
                "linux": None
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # BasiliskII
        "BasiliskII": {
            "program": {
                "windows": "BasiliskII/windows/BasiliskII.exe",
                "linux": "BasiliskII/linux/BasiliskII.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "setup_dir": {
                "windows": "BasiliskII/windows",
                "linux": "BasiliskII/linux/BasiliskII.AppImage.home/.config/BasiliskII"
            },
            "config_file": {
                "windows": None,
                "linux": "BasiliskII/linux/BasiliskII.AppImage.home/.config/BasiliskII/prefs"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # BigPEmu
        "BigPEmu": {
            "program": {
                "windows": "BigPEmu/windows/BigPEmu.exe",
                "linux": "BigPEmu/windows/BigPEmu.exe"
            },
            "save_dir": {
                "windows": "BigPEmu/windows/UserData",
                "linux": "BigPEmu/windows/UserData"
            },
            "config_file": {
                "windows": None,
                "linux": None
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # Cemu
        "Cemu": {
            "program": {
                "windows": "Cemu/windows/Cemu.exe",
                "linux": "Cemu/linux/Cemu.AppImage"
            },
            "save_dir": {
                "windows": "Cemu/windows/mlc01/usr/save/00050000",
                "linux": "Cemu/linux/Cemu.AppImage.home/.local/share/Cemu/mlc01/usr/save/00050000"
            },
            "setup_dir": {
                "windows": "Cemu/windows",
                "linux": "Cemu/linux/Cemu.AppImage.home/.local/share/Cemu"
            },
            "config_file": {
                "windows": None,
                "linux": None
            },
            "keys_file": {
                "windows": "Cemu/windows/keys.txt",
                "linux": "Cemu/linux/Cemu.AppImage.home/.local/share/Cemu/keys.txt"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Citra
        "Citra": {
            "program": {
                "windows": "Citra/windows/citra-qt.exe",
                "linux": "Citra/linux/citra-qt.AppImage"
            },
            "save_dir": {
                "windows": "Citra/windows/user/sdmc/Nintendo 3DS/00000000000000000000000000000000/00000000000000000000000000000000/title/00040000",
                "linux": "Citra/linux/citra-qt.AppImage.home/.local/share/citra-emu/sdmc/Nintendo 3DS/00000000000000000000000000000000/00000000000000000000000000000000/title/00040000"
            },
            "setup_dir": {
                "windows": "Citra/windows/user",
                "linux": "Citra/linux/citra-qt.AppImage.home/.local/share/citra-emu"
            },
            "config_file": {
                "windows": "Citra/windows/user/config/qt-config.ini",
                "linux": "Citra/linux/citra-qt.AppImage.home/.config/citra-emu/qt-config.ini"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Dolphin
        "Dolphin": {
            "program": {
                "windows": "Dolphin/windows/Dolphin.exe",
                "linux": "Dolphin/linux/Dolphin.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "save_base_dir": {
                "windows": "Dolphin/windows/User",
                "linux": "Dolphin/linux/Dolphin.AppImage.home/.local/share/dolphin-emu"
            },
            "save_sub_dirs": {

                # Nintendo
                "Nintendo Gamecube": "GC",
                "Nintendo Wii": "Wii/title/00010000"
            },
            "setup_dir": {
                "windows": "Dolphin/windows/User",
                "linux": "Dolphin/linux/Dolphin.AppImage.home/.local/share/dolphin-emu"
            },
            "config_file": {
                "windows": None,
                "linux": None
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # DosBoxX
        "DosBoxX": {
            "program": {
                "windows": "DosBoxX/windows/dosbox-x.exe",
                "linux": "DosBoxX/linux/DosBoxX.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "config_file": {
                "windows": "DosBoxX/windows/dosbox-x.conf",
                "linux": "DosBoxX/linux/DosBoxX.AppImage.home/.config/dosbox-x/dosbox-x.conf"
            },
            "config_file_win31": {
                "windows": "DosBoxX/windows/dosbox-x.win31.conf",
                "linux": "DosBoxX/linux/DosBoxX.AppImage.home/.config/dosbox-x/dosbox-x.win31.conf"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # DuckStation
        "DuckStation": {
            "program": {
                "windows": "DuckStation/windows/duckstation-qt-x64-ReleaseLTCG.exe",
                "linux": "DuckStation/linux/DuckStation.AppImage"
            },
            "save_dir": {
                "windows": "DuckStation/windows/memcards",
                "linux": "DuckStation/linux/DuckStation.AppImage.home/.config/duckstation/memcards"
            },
            "setup_dir": {
                "windows": "DuckStation/windows",
                "linux": "DuckStation/linux/DuckStation.AppImage.home/.config/duckstation"
            },
            "config_file": {
                "windows": "DuckStation/windows/settings.ini",
                "linux": "DuckStation/linux/DuckStation.AppImage.home/.config/duckstation/settings.ini"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # EKA2L1
        "EKA2L1": {
            "program": {
                "windows": "EKA2L1/windows/eka2l1_qt.exe",
                "linux": "EKA2L1/linux/EKA2L1.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "config_file": {
                "windows": None,
                "linux": None
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Flycast
        "Flycast": {
            "program": {
                "windows": "Flycast/windows/flycast.exe",
                "linux": "Flycast/linux/Flycast.AppImage"
            },
            "save_dir": {
                "windows": "Flycast/windows/data",
                "linux": "Flycast/linux/Flycast.AppImage.home/.local/share/flycast"
            },
            "config_file": {
                "windows": "Flycast/windows/emu.cfg",
                "linux": "Flycast/linux/Flycast.AppImage.home/.config/flycast/emu.cfg"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # FS-UAE
        "FS-UAE": {
            "program": {
                "windows": "FS-UAE/windows/Windows/x86-64/fs-uae.exe",
                "linux": "FS-UAE/linux/FS-UAE.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "setup_dir": {
                "windows": "FS-UAE/windows",
                "linux": "FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE"
            },
            "config_file": {
                "windows": None,
                "linux": None
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Mame
        "Mame": {
            "program": {
                "windows": "Mame/windows/mame.exe",
                "linux": "Mame/linux/Mame.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "setup_dir": {
                "windows": "Mame/windows",
                "linux": "Mame/linux/Mame.AppImage.home/.mame"
            },
            "config_dir": {
                "windows": "Mame/windows",
                "linux": "Mame/linux/Mame.AppImage.home/.mame"
            },
            "config_file": {
                "windows": "Mame/windows/mame.ini",
                "linux": "Mame/linux/Mame.AppImage.home/.mame/mame.ini"
            },
            "roms_dir": {
                "windows": "Mame/windows/roms",
                "linux": "Mame/linux/Mame.AppImage.home/.mame/roms"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Mednafen
        "Mednafen": {
            "program": {
                "windows": "Mednafen/windows/mednafen.exe",
                "linux": "Mednafen/linux/Mednafen.AppImage"
            },
            "save_dir": {
                "windows": "Mednafen/windows/sav",
                "linux": "Mednafen/linux/Mednafen.AppImage.home/.mednafen/sav"
            },
            "setup_dir": {
                "windows": "Mednafen/windows",
                "linux": "Mednafen/linux/Mednafen.AppImage.home/.mednafen"
            },
            "config_file": {
                "windows": "Mednafen/windows/mednafen.cfg",
                "linux": "Mednafen/linux/Mednafen.AppImage.home/.mednafen/mednafen.cfg"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # melonDS
        "melonDS": {
            "program": {
                "windows": "melonDS/windows/melonDS.exe",
                "linux": "melonDS/linux/melonDS.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "setup_dir": {
                "windows": "melonDS/windows",
                "linux": "melonDS/linux/melonDS.AppImage.home/.config/melonDS"
            },
            "config_file": {
                "windows": "melonDS/windows/melonDS.ini",
                "linux": "melonDS/linux/melonDS.AppImage.home/.config/melonDS/melonDS.ini"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # mGBA
        "mGBA": {
            "program": {
                "windows": "mGBA/windows/mGBA.exe",
                "linux": "mGBA/linux/mGBA.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "setup_dir": {
                "windows": "mGBA/windows",
                "linux": "mGBA/linux/mGBA.AppImage.home/.config/mgba"
            },
            "config_file": {
                "windows": "mGBA/windows/config.ini",
                "linux": "mGBA/linux/mGBA.AppImage.home/.config/mgba/config.ini"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # PCSX2
        "PCSX2": {
            "program": {
                "windows": "PCSX2/windows/pcsx2-qt.exe",
                "linux": "PCSX2/linux/PCSX2.AppImage"
            },
            "save_dir": {
                "windows": "PCSX2/windows/memcards",
                "linux": "PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/memcards"
            },
            "setup_dir": {
                "windows": "PCSX2/windows",
                "linux": "PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2"
            },
            "config_file": {
                "windows": "PCSX2/windows/inis/PCSX2.ini",
                "linux": "PCSX2/linux/PCSX2.AppImage.home/.config/PCSX2/inis/PCSX2.ini"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # PPSSPP
        "PPSSPP": {
            "program": {
                "windows": "PPSSPP/windows/PPSSPPWindows64.exe",
                "linux": "PPSSPP/linux/PPSSPP.AppImage"
            },
            "save_dir": {
                "windows": "PPSSPP/windows/memstick/PSP/SAVEDATA",
                "linux": "PPSSPP/linux/PPSSPP.AppImage.home/.config/ppsspp/PSP/SAVEDATA"
            },
            "config_file": {
                "windows": None,
                "linux": None
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # RetroArch
        "RetroArch": {
            "program": {
                "windows": "RetroArch/windows/retroarch.exe",
                "linux": "RetroArch/linux/RetroArch-Linux-x86_64.AppImage"
            },
            "save_dir": {
                "windows": "RetroArch/windows/saves",
                "linux": "RetroArch/linux/RetroArch-Linux-x86_64.AppImage.home/.config/retroarch/saves"
            },
            "save_base_dir": {
                "windows": "RetroArch/windows/saves",
                "linux": "RetroArch/linux/RetroArch-Linux-x86_64.AppImage.home/.config/retroarch/saves"
            },
            "save_sub_dirs": {

                # Other
                "Panasonic 3DO": "opera/per_game"
            },
            "setup_dir": {
                "windows": "RetroArch/windows",
                "linux": "RetroArch/linux/RetroArch-Linux-x86_64.AppImage.home/.config/retroarch"
            },
            "cores_dir": {
                "windows": "RetroArch/windows/cores",
                "linux": "RetroArch/linux/RetroArch-Linux-x86_64.AppImage.home/.config/retroarch/cores"
            },
            "cores_ext": {
                "windows": ".dll",
                "linux": ".so"
            },
            "cores_mapping": {

                # Other
                "Panasonic 3DO": "opera_libretro",
                "Sega Saturn": "mednafen_saturn_libretro"
            },
            "config_file": {
                "windows": None,
                "linux": None
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # RPCS3
        "RPCS3": {
            "program": {
                "windows": "RPCS3/windows/rpcs3.exe",
                "linux": "RPCS3/linux/RPCS3.AppImage"
            },
            "save_dir": {
                "windows": "RPCS3/windows/dev_hdd0/home/00000001",
                "linux": "RPCS3/linux/RPCS3.AppImage.home/.config/rpcs3/dev_hdd0/home/00000001"
            },
            "setup_dir": {
                "windows": "RPCS3/windows",
                "linux": "RPCS3/linux/RPCS3.AppImage.home/.config/rpcs3"
            },
            "config_file": {
                "windows": None,
                "linux": None
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # ScummVM
        "ScummVM": {
            "program": {
                "windows": "ScummVM/windows/scummvm.exe",
                "linux": "ScummVM/linux/ScummVM.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "config_file": {
                "windows": None,
                "linux": None
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # VICE-C64
        "VICE-C64": {
            "program": {
                "windows": "VICE-C64/windows/x64sc.exe",
                "linux": "VICE-C64/linux/VICE-C64.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "config_file": {
                "windows": "VICE-C64/windows/sdl-vice.ini",
                "linux": "VICE-C64/linux/VICE-C64.AppImage.home/.config/vice/vicerc"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Vita3K
        "Vita3K": {
            "program": {
                "windows": "Vita3K/windows/Vita3K.exe",
                "linux": "Vita3K/linux/Vita3K.AppImage"
            },
            "save_dir": {
                "windows": "Vita3K/windows/data/ux0/user",
                "linux": "Vita3K/linux/Vita3K.AppImage.home/.local/share/Vita3K/Vita3K/ux0/user"
            },
            "app_dir": {
                "windows": "Vita3K/windows/data/ux0/app",
                "linux": "Vita3K/linux/Vita3K.AppImage.home/.local/share/Vita3K/Vita3K/ux0/app"
            },
            "setup_dir": {
                "windows": "Vita3K/windows/data",
                "linux": "Vita3K/linux/Vita3K.AppImage.home/.local/share/Vita3K/Vita3K"
            },
            "config_file": {
                "windows": "Vita3K/windows/config.yml",
                "linux": "Vita3K/linux/Vita3K.AppImage.home/.config/Vita3K/config.yml"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Xemu
        "Xemu": {
            "program": {
                "windows": "Xemu/windows/xemu.exe",
                "linux": "Xemu/linux/Xemu.AppImage"
            },
            "save_dir": {
                "windows": None,
                "linux": None
            },
            "setup_dir": {
                "windows": "Xemu/windows",
                "linux": "Xemu/linux/Xemu.AppImage.home/.local/share/xemu/xemu"
            },
            "config_file": {
                "windows": "Xemu/windows/xemu.toml",
                "linux": "Xemu/linux/Xemu.AppImage.home/.local/share/xemu/xemu/xemu.toml"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        },

        # Xenia
        "Xenia": {
            "program": {
                "windows": "Xenia/windows/xenia.exe",
                "linux": "Xenia/windows/xenia.exe"
            },
            "save_dir": {
                "windows": "Xenia/windows/content",
                "linux": "Xenia/windows/content"
            },
            "config_file": {
                "windows": "Xenia/windows/xenia.config.toml",
                "linux": "Xenia/windows/xenia.config.toml"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": True
            }
        },

        # Yuzu
        "Yuzu": {
            "program": {
                "windows": "Yuzu/windows/yuzu.exe",
                "linux": "Yuzu/linux/Yuzu.AppImage"
            },
            "save_dir": {
                "windows": "Yuzu/windows/user/nand/user/save/0000000000000000/F6F389D41D6BC0BDD6BD928C526AE556",
                "linux": "Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu/nand/user/save/0000000000000000/F6F389D41D6BC0BDD6BD928C526AE556"
            },
            "setup_dir": {
                "windows": "Yuzu/windows/user",
                "linux": "Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu"
            },
            "config_file": {
                "windows": "Yuzu/windows/user/config/qt-config.ini",
                "linux": "Yuzu/linux/Yuzu.AppImage.home/.config/yuzu/qt-config.ini"
            },
            "run_sandboxed": {
                "windows": False,
                "linux": False
            }
        }
    }
