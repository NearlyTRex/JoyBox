# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import command
import system
import gui
import environment
import metadata
import programs
import tools
import emulators
import saves
from launchers import ares
from launchers import atari800
from launchers import basiliskii
from launchers import bigpemu
from launchers import cemu
from launchers import citra
from launchers import dolphin
from launchers import duckstation
from launchers import eka2l1
from launchers import flycast
from launchers import fsuae
from launchers import mame
from launchers import mednafen
from launchers import melonds
from launchers import mgba
from launchers import pcsx2
from launchers import ppsspp
from launchers import retroarch
from launchers import rpcs3
from launchers import vicec64
from launchers import vita3k
from launchers import xemu
from launchers import xenia
from launchers import yuzu
from launchers import computer

# Get emulator launcher
def GetEmulatorLauncher(game_platform):

    # Ares
    if game_platform in config.ares_platforms:
        return ares.LaunchViaAres

    # Atari800
    if game_platform in config.atari800_platforms:
        return ares.LaunchViaAtari800

    # BasiliskII
    elif game_platform in config.basiliskii_platforms:
        return basiliskii.LaunchViaBasiliskII

    # BigPEmu
    elif game_platform in config.bigpemu_platforms:
        return bigpemu.LaunchViaBigPEmu

    # Cemu
    elif game_platform in config.cemu_platforms:
        return cemu.LaunchViaCemu

    # Citra
    elif game_platform in config.citra_platforms:
        return citra.LaunchViaCitra

    # Dolphin
    elif game_platform in config.dolphin_platforms:
        return dolphin.LaunchViaDolphin

    # Dolphin
    elif game_platform in config.duckstation_platforms:
        return duckstation.LaunchViaDuckStation

    # EKA2L1
    elif game_platform in config.eka2l1_platforms:
        return flycast.LaunchViaEKA2L1

    # Flycast
    elif game_platform in config.flycast_platforms:
        return flycast.LaunchViaFlycast

    # FS-UAE
    elif game_platform in config.fsuae_platforms:
        return fsuae.LaunchViaFSUAE

    # Mame
    elif game_platform in config.mame_platforms:
        return mame.LaunchViaMame

    # Mednafen
    elif game_platform in config.mednafen_platforms:
        return mednafen.LaunchViaMednafen

    # melonDS
    elif game_platform in config.melonds_platforms:
        return melonds.LaunchViaMelonDS

    # mGBA
    elif game_platform in config.mgba_platforms:
        return mgba.LaunchViaMGBA

    # PCSX2
    elif game_platform in config.pcsx2_platforms:
        return pcsx2.LaunchViaPCSX2

    # PPSSPP
    elif game_platform in config.ppsspp_platforms:
        return ppsspp.LaunchViaPPSSPP

    # RetroArch
    elif game_platform in config.retroarch_platforms:
        return retroarch.LaunchViaRetroArch

    # RPCS3
    elif game_platform in config.rpcs3_platforms:
        return rpcs3.LaunchViaRPCS3

    # VICE-C64
    elif game_platform in config.vicec64_platforms:
        return vicec64.LaunchViaViceC64

    # Vita3K
    elif game_platform in config.vita3k_platforms:
        return vita3k.LaunchViaVita3K

    # Xemu
    elif game_platform in config.xemu_platforms:
        return xemu.LaunchViaXemu

    # Xenia
    elif game_platform in config.xenia_platforms:
        return xenia.LaunchViaXenia

    # Yuzu
    elif game_platform in config.yuzu_platforms:
        return yuzu.LaunchViaYuzu

    # Computer
    elif game_platform in config.computer_platforms:
        return computer.LaunchViaComputer
    return None

# Get emulator info
def GetEmulatorInfo(game_platform):
    emulator_info = {}

    # Ares
    if game_platform in config.ares_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("Ares", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("Ares")

    # Atari800
    elif game_platform in config.atari800_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("Atari800", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("Atari800")

    # BasiliskII
    elif game_platform in config.basiliskii_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("BasiliskII", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("BasiliskII")

    # BigPEmu
    elif game_platform in config.bigpemu_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("BigPEmu", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("BigPEmu")

    # Cemu
    elif game_platform in config.cemu_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("Cemu", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("Cemu")

    # Citra
    elif game_platform in config.citra_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("Citra", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("Citra")

    # Dolphin
    elif game_platform in config.dolphin_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("Dolphin", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("Dolphin")

    # DuckStation
    elif game_platform in config.duckstation_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("DuckStation", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("DuckStation")

    # EKA2L1
    elif game_platform in config.eka2l1_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("EKA2L1", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("EKA2L1")

    # Flycast
    elif game_platform in config.flycast_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("Flycast", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("Flycast")

    # FS-UAE
    elif game_platform in config.fsuae_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("FS-UAE", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("FS-UAE")

    # Mame
    elif game_platform in config.mame_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("Mame", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("Mame")

    # Mednafen
    elif game_platform in config.mednafen_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("Mednafen", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("Mednafen")

    # melonDS
    elif game_platform in config.melonds_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("melonDS", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("melonDS")

    # mGBA
    elif game_platform in config.mgba_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("mGBA", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("mGBA")

    # PCSX2
    elif game_platform in config.pcsx2_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("PCSX2", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("PCSX2")

    # PPSSPP
    elif game_platform in config.ppsspp_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("PPSSPP", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("PPSSPP")

    # RetroArch
    elif game_platform in config.retroarch_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("RetroArch", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("RetroArch")

    # RPCS3
    elif game_platform in config.rpcs3_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("RPCS3", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("RPCS3")

    # VICE-C64
    elif game_platform in config.vicec64_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("VICE-C64", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("VICE-C64")

    # Vita3K
    elif game_platform in config.vita3k_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("Vita3K", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("Vita3K")

    # Xemu
    elif game_platform in config.xemu_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("Xemu", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("Xemu")

    # Xenia
    elif game_platform in config.xenia_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("Xenia", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("Xenia")

    # Yuzu
    elif game_platform in config.yuzu_platforms:
        emulator_info["saves_dir"] = programs.GetEmulatorSaveDir("Yuzu", environment.GetCurrentPlatform(), game_platform)
        emulator_info["config_file"] = programs.GetEmulatorConfigFile("Yuzu")

    # Computer
    elif game_platform in config.computer_platforms:
        emulator_info["saves_dir"] = None
        emulator_info["config_file"] = None
        if environment.IsWindowsPlatform():
            emulator_info["format"] = config.save_format_sandboxie
        else:
            emulator_info["format"] = config.save_format_wine
    return emulator_info

# Launch via unknown platform
def LaunchUnknown(launch_platform, file_path):
    print("Unknown platform '%s'" % launch_platform)

# Launch via disabled platform
def LaunchDisabled(launch_platform, file_path):
    print("Launcher for platform '%s' is currently disabled" % launch_platform)

# Launch game
def LaunchGame(launch_platform, file_path, capture_type = None, verbose = False, exit_on_failure = False):

    # Get real file path
    real_file_path = system.ResolveVirtualRomPath(file_path)
    if system.IsVirtualRomPath(real_file_path) or not system.IsPathValid(real_file_path):
        gui.DisplayErrorPopup(
            title_text = "Unable to resolve game file",
            message_text = "Game file '%s' could not be resolved" % file_path)

    # Get launch name
    launch_name = os.path.basename(os.path.dirname(real_file_path))

    # Get game info
    game_supercategory, game_category, game_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(launch_platform)
    game_launcher = GetEmulatorLauncher(launch_platform)
    game_launcher_info = GetEmulatorInfo(launch_platform)

    # Get launch artwork
    launch_artwork = environment.GetSyncedGameAssetFile(
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = launch_name,
        asset_type = config.asset_type_boxfront)

    # Check game launcher
    if not game_launcher or not game_launcher_info:
        gui.DisplayErrorPopup(
            title_text = "Launcher not found",
            message_text = "Launcher for game '%s' in platform '%s' could not be found" % (system.GetFilenameFile(real_file_path), launch_platform))

    # Get launcher info
    launcher_config_file = game_launcher_info["config_file"]
    launcher_saves_dir = game_launcher_info["saves_dir"]
    launcher_saves_format = game_launcher_info["format"] if ("format" in game_launcher_info) else None

    # Get save directories
    save_dir_emulator = launcher_saves_dir
    save_dir_real = environment.GetCachedSaveDir(game_category, game_subcategory, launch_name, launcher_saves_format)
    save_dir_general = environment.GetCachedSaveDir(game_category, game_subcategory, launch_name, config.save_format_general)

    # Unpack save if possible
    if saves.CanSaveBeUnpacked(game_category, game_subcategory, launch_name):
        saves.UnpackSave(game_category, game_subcategory, launch_name, verbose = verbose, exit_on_failure = exit_on_failure)

    # Make sure save directory exists
    system.MakeDirectory(save_dir_real, verbose = verbose, exit_on_failure = exit_on_failure)

    # Setup emulator save directory
    if save_dir_emulator:

        # Make parent folder
        system.MakeDirectory(system.GetFilenameDirectory(save_dir_emulator), verbose = verbose, exit_on_failure = exit_on_failure)

        # Removing existing folder/symlink
        system.RemoveObject(save_dir_emulator, verbose = verbose, exit_on_failure = exit_on_failure)

        # Create save symlink
        system.CreateSymlink(save_dir_real, save_dir_emulator, verbose = verbose, exit_on_failure = exit_on_failure)

    # Get config file version of save dir
    config_file_save_dir = save_dir_real

    # Replace tokens in config file
    system.ReplaceStringsInFile(launcher_config_file, [
        {"from": config.token_arcade_rom_root, "to": environment.GetRomRootDir()},
        {"from": config.token_arcade_tool_root, "to": tools.GetBaseDirectory()},
        {"from": config.token_arcade_emulator_root, "to": emulators.GetBaseDirectory()},
        {"from": config.token_game_save_dir, "to": config_file_save_dir}
    ])

    # Launch game
    game_launcher(
        launch_name = launch_name,
        launch_platform = launch_platform,
        launch_file = real_file_path,
        launch_artwork = launch_artwork,
        launch_save_dir = save_dir_real,
        launch_general_save_dir = save_dir_general,
        launch_capture_type = capture_type)

    # Revert to tokens in config file
    system.ReplaceStringsInFile(launcher_config_file, [
        {"from": environment.GetRomRootDir(), "to": config.token_arcade_rom_root},
        {"from": tools.GetBaseDirectory(), "to": config.token_arcade_tool_root},
        {"from": emulators.GetBaseDirectory(), "to": config.token_arcade_emulator_root},
        {"from": config_file_save_dir, "to": config.token_game_save_dir}
    ])

    # Clean emulator save directory
    if save_dir_emulator:

        # Removing existing symlink
        system.RemoveObject(save_dir_emulator, verbose = verbose, exit_on_failure = exit_on_failure)

        # Create save folder
        system.MakeDirectory(save_dir_emulator, verbose = verbose, exit_on_failure = exit_on_failure)

    # Pack save
    saves.PackSave(game_category, game_subcategory, launch_name, verbose = verbose, exit_on_failure = exit_on_failure)
