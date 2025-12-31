# Imports
import os, os.path
import sys
import time

# Local imports
import config
import fileops
import system
import gameinfo
import platforms
import ini
import paths
import lockerinfo

###########################################################
# System capabilities
###########################################################

# Determine if windows platform
def is_windows_platform():
    return sys.platform.startswith("win32")

# Determine if linux platform
def is_linux_platform():
    return sys.platform.startswith("linux")

# Determine if mac platform
def is_mac_platform():
    return sys.platform.startswith("darwin")

# Determine if unix platform
def is_unix_platform():
    return is_mac_platform() or is_linux_platform()

# Determine if wine platform
def is_wine_platform():
    return is_linux_platform()

# Determine if sandboxie platform
def is_sandboxie_platform():
    return is_windows_platform()

# Get current platform
def get_current_platform():
    if is_windows_platform():
        return "windows"
    elif is_linux_platform():
        return "linux"
    elif is_mac_platform():
        return "macos"
    return None

# Get current timestamp
def get_current_timestamp():
    return int(time.time())

# Get home directory
def get_home_directory():
    return os.path.expanduser("~")

# Get cookie directory
def get_cookie_directory():
    return paths.join_paths(get_home_directory(), "Cookies")

# Get log directory
def get_log_directory():
    return paths.join_paths(get_home_directory(), "Logs")

# Get editor command
def get_editor():

    # First check ini config
    editor = ini.get_ini_value("Tools.System", "editor")
    if editor:
        return editor

    # Fall back to environment variables
    editor = os.environ.get('EDITOR')
    if editor:
        return editor
    editor = os.environ.get('VISUAL')
    if editor:
        return editor

    # Final fallback
    if is_windows_platform():
        return "notepad.exe"
    return "nano"

# Determine if symlinks are supported
def are_symlinks_supported():
    if is_unix_platform():
        return True
    else:
        test_file_src = paths.join_paths(os.path.expanduser("~"), ".symsrc")
        test_file_dest = paths.join_paths(os.path.expanduser("~"), ".symdest")
        if os.path.islink(test_file_dest):
            return True
        fileops.touch_file(test_file_src)
        fileops.create_symlink(test_file_src, test_file_dest)
        return os.path.islink(test_file_dest)
    return False

###########################################################
# Tools
###########################################################

# Get tools root dir
def get_tools_root_dir():
    return ini.get_ini_path_value("UserData.Dirs", "tools_dir")

###########################################################
# Emulators
###########################################################

# Get emulators root dir
def get_emulators_root_dir():
    return ini.get_ini_path_value("UserData.Dirs", "emulators_dir")

###########################################################
# Locker
###########################################################

# Get locker root dir
def get_locker_root_dir(locker_type = None):
    if locker_type is None:
        locker_type = config.LockerType.LOCAL
    locker_info = lockerinfo.LockerInfo(locker_type)
    if locker_info.is_local_only():
        return locker_info.get_local_path()
    mount_path = locker_info.get_remote_mount_path()
    if mount_path:
        return mount_path
    return locker_info.get_local_path()

###########################################################
# Locker - Development
###########################################################

# Get locker development root dir
def get_locker_development_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_root_dir(locker_type),
        config.LockerFolderType.DEVELOPMENT)

# Get locker development archives root dir
def get_locker_development_archives_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_development_root_dir(locker_type),
        "Archive")

###########################################################
# Locker - Gaming
###########################################################

# Get locker gaming root dir
def get_locker_gaming_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_root_dir(locker_type),
        config.LockerFolderType.GAMING)

# Get locker gaming roms root dir
def get_locker_gaming_roms_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.ROMS)

# Get locker gaming dlc root dir
def get_locker_gaming_dlc_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.DLC)

# Get locker gaming update root dir
def get_locker_gaming_update_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.UPDATES)

# Get locker gaming tags root dir
def get_locker_gaming_tags_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.TAGS)

###########################################################
# Locker - Gaming - Files
###########################################################

# Get locker gaming files offset
def get_locker_gaming_files_offset(game_supercategory, game_category, game_subcategory, game_name):
    game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)
    game_name_path = gameinfo.derive_game_name_path_from_name(game_name, game_platform)
    return paths.join_paths(
        game_supercategory,
        game_category,
        game_subcategory,
        game_name_path)

# Get locker gaming files dir
def get_locker_gaming_files_dir(game_supercategory, game_category, game_subcategory, game_name, locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        get_locker_gaming_files_offset(game_supercategory, game_category, game_subcategory, game_name))

###########################################################
# Locker - Gaming - Saves
###########################################################

# Get locker gaming saves root dir
def get_locker_gaming_saves_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.SAVES)

# Get locker gaming save dir
def get_locker_gaming_save_dir(game_supercategory, game_category, game_subcategory, game_name, locker_type = None):
    game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)
    game_name_path = gameinfo.derive_game_name_path_from_name(game_name, game_platform)
    return paths.join_paths(
        get_locker_gaming_saves_root_dir(locker_type),
        game_category,
        game_subcategory,
        game_name_path)

###########################################################
# Locker - Gaming - Assets
###########################################################

# Get locker gaming assets root dir
def get_locker_gaming_assets_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.ASSETS)

# Get locker gaming asset dir
def get_locker_gaming_asset_dir(game_category, game_subcategory, asset_type, locker_type = None):
    return paths.join_paths(
        get_locker_gaming_assets_root_dir(locker_type),
        game_category,
        game_subcategory,
        asset_type)

# Get locker gaming asset file
def get_locker_gaming_asset_file(game_category, game_subcategory, game_name, asset_type, locker_type = None):
    asset_file = "%s%s" % (game_name, asset_type.cval())
    return paths.join_paths(
        get_locker_gaming_assets_root_dir(locker_type),
        game_category,
        game_subcategory,
        asset_type,
        asset_file)

###########################################################
# Locker - Gaming - Emulators
###########################################################

# Get locker gaming emulators root dir
def get_locker_gaming_emulators_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.EMULATORS)

# Get locker gaming emulator binaries dir
def get_locker_gaming_emulator_binaries_dir(emu_name, emu_platform, locker_type = None):
    return paths.join_paths(
        get_locker_gaming_emulators_root_dir(locker_type),
        emu_name,
        "Binaries",
        emu_platform)

# Get locker gaming emulator setup dir
def get_locker_gaming_emulator_setup_dir(emu_name, locker_type = None):
    return paths.join_paths(
        get_locker_gaming_emulators_root_dir(locker_type),
        emu_name,
        "Setup")

###########################################################
# Locker - Music
###########################################################

# Get locker music root dir
def get_locker_music_root_dir(locker_type = None, genre_type = None):
    if genre_type:
        return paths.join_paths(get_locker_root_dir(locker_type), config.LockerFolderType.MUSIC, genre_type)
    return paths.join_paths(get_locker_root_dir(locker_type), config.LockerFolderType.MUSIC)

# Get locker music dir with genre type handling
def get_locker_music_dir(genre_type = None):
    if genre_type:
        return get_locker_music_root_dir(genre_type = genre_type)
    else:
        return get_locker_music_root_dir()

# Get locker music album dir
def get_locker_music_album_dir(album_name, artist_name = None, locker_type = None, genre_type = None):
    if artist_name:
        return paths.join_paths(get_locker_music_root_dir(locker_type, genre_type), artist_name, album_name)
    return paths.join_paths(get_locker_music_root_dir(locker_type, genre_type), album_name)

###########################################################
# Locker - Photos
###########################################################

# Get locker photos root dir
def get_locker_photos_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_root_dir(locker_type),
        config.LockerFolderType.PHOTOS)

###########################################################
# Locker - Programs
###########################################################

# Get locker programs root dir
def get_locker_programs_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_root_dir(locker_type),
        config.LockerFolderType.PROGRAMS)

# Get locker programs tools root dir
def get_locker_programs_tools_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_programs_root_dir(locker_type),
        "Tools")

# Get locker program tool dir
def get_locker_program_tool_dir(tool_name, tool_platform = None, locker_type = None):
    if tool_platform:
        return paths.join_paths(
            get_locker_programs_tools_root_dir(locker_type),
            tool_name,
            tool_platform)
    else:
        return paths.join_paths(
            get_locker_programs_tools_root_dir(locker_type),
            tool_name)

###########################################################
# Metadata - Games
###########################################################

# Get game metadata root dir
def get_game_metadata_root_dir():
    return ini.get_ini_path_value("UserData.Dirs", "game_metadata_dir")

# Get pegasus metadata root dir
def get_game_pegasus_metadata_root_dir():
    return paths.join_paths(get_game_metadata_root_dir(), "Pegasus")

# Get pegasus metadata file
def get_game_pegasus_metadata_file(game_category, game_subcategory):
    return paths.join_paths(
        get_game_pegasus_metadata_root_dir(),
        config.Supercategory.ROMS,
        game_category,
        game_subcategory,
        "metadata.pegasus.txt")

# Get pegasus metadata asset dir
def get_game_pegasus_metadata_asset_dir(game_category, game_subcategory, asset_type):
    return paths.join_paths(
        get_game_pegasus_metadata_root_dir(),
        config.Supercategory.ROMS,
        game_category,
        game_subcategory,
        asset_type)

# Get metadata file
def get_game_metadata_file(game_category, game_subcategory, metadata_format = config.MetadataFormatType.PEGASUS):
    if metadata_format == config.MetadataFormatType.PEGASUS:
        return get_game_pegasus_metadata_file(game_category, game_subcategory)
    return None

# Check if file is a metadata file
def is_game_metadata_file(metadata_file):
    return metadata_file.endswith("metadata.pegasus.txt")

# Get published metadata root dir
def get_game_published_metadata_root_dir():
    return paths.join_paths(get_game_metadata_root_dir(), "Published")

# Get misc metadata root dir
def get_game_misc_metadata_root_dir():
    return paths.join_paths(get_game_metadata_root_dir(), "Misc")

# Get hashes metadata root dir
def get_game_hashes_metadata_root_dir():
    return paths.join_paths(get_game_metadata_root_dir(), "Hashes")

# Get hashes metadata file
def get_game_hashes_metadata_file(game_supercategory, game_category, game_subcategory):
    return paths.join_paths(
        get_game_hashes_metadata_root_dir(),
        game_supercategory,
        game_category,
        game_subcategory + ".json")

# Get json metadata root dir
def get_game_json_metadata_root_dir():
    return paths.join_paths(get_game_metadata_root_dir(), "Json")

# Get json rom metadata dir
def get_json_metadata_dir(game_supercategory, game_category, game_subcategory):
    return paths.join_paths(
        get_game_json_metadata_root_dir(),
        game_supercategory,
        game_category,
        game_subcategory)

# Get json metadata file
def get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name):
    game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)
    game_name_path = gameinfo.derive_game_name_path_from_name(game_name, game_platform)
    return paths.join_paths(
        get_json_metadata_dir(game_supercategory, game_category, game_subcategory),
        game_name_path,
        game_name + ".json")

# Get json metadata ignore file
def get_game_json_metadata_ignore_file(game_supercategory, game_category, game_subcategory):
    return paths.join_paths(
        get_json_metadata_dir(game_supercategory, game_category, game_subcategory),
        "ignores.json")

###########################################################
# Metadata - Files
###########################################################

# Get file metadata root dir
def get_file_metadata_root_dir():
    return ini.get_ini_path_value("UserData.Dirs", "file_metadata_dir")

# Get audio metadata root dir
def get_file_audio_metadata_root_dir(metadata_type, genre_type):
    return paths.join_paths(get_file_metadata_root_dir(), "Audio", metadata_type, genre_type)

# Get audio metadata dir (with optional artist support)
def get_file_audio_metadata_dir(metadata_type, genre_type, artist_name = None):
    if artist_name:
        return paths.join_paths(get_file_metadata_root_dir(), "Audio", metadata_type, genre_type, artist_name)
    return paths.join_paths(get_file_metadata_root_dir(), "Audio", metadata_type, genre_type)

# Get audio metadata archive file
def get_file_audio_metadata_archive_file(genre_type, album_name):
    return paths.join_paths(get_file_audio_metadata_root_dir(config.AudioMetadataType.ARCHIVE, genre_type), album_name + ".txt")

# Get audio metadata album dir
def get_file_audio_metadata_album_dir(metadata_type, genre_type, album_name, artist_name = None):
    if genre_type:
        output_dir = get_file_audio_metadata_dir(metadata_type, genre_type, artist_name)
        return paths.join_paths(output_dir, album_name)
    else:
        return paths.join_paths(get_file_metadata_root_dir(), album_name)

# Get audio metadata file
def get_file_audio_metadata_file(metadata_type, genre_type, album_name, artist_name = None):
    if genre_type:
        output_dir = get_file_audio_metadata_dir(metadata_type, genre_type, artist_name)
    else:
        output_dir = get_file_metadata_root_dir()
    return paths.join_paths(output_dir, f"{album_name}.json")

# Get file locker hashes root dir
def get_file_locker_hashes_root_dir():
    return paths.join_paths(get_file_metadata_root_dir(), "Locker", "Hashes")

# Get file locker hashes file for a base path
def get_file_locker_hashes_file(base_path, depth = 4):
    parts = base_path.split(os.sep)
    if len(parts) >= depth:
        group_key = paths.join_paths(*parts[:depth])
    elif len(parts) > 1:
        group_key = paths.join_paths(*parts[:-1])
    else:
        group_key = "root"
    return paths.join_paths(get_file_locker_hashes_root_dir(), group_key + ".csv")

###########################################################
# Scripts
###########################################################

# Get scripts root dir
def get_scripts_root_dir():
    return ini.get_ini_path_value("UserData.Dirs", "scripts_dir")

# Get scripts bin dir
def get_scripts_bin_dir():
    return paths.join_paths(get_scripts_root_dir(), "bin")

# Get scripts icons dir
def get_scripts_icons_dir():
    return paths.join_paths(get_scripts_root_dir(), "icons")

# Get scripts lib dir
def get_scripts_lib_dir():
    return paths.join_paths(get_scripts_root_dir(), "lib")

# Get scripts command extension
def get_scripts_command_extension():
    if is_windows_platform():
        return ".bat"
    else:
        return ""

# Get scripts executable extension
def get_scripts_executable_extension():
    if is_windows_platform():
        return ".exe"
    else:
        return ""

###########################################################
# Repositories
###########################################################

# Get repositories root dir
def get_repositories_root_dir():
    return ini.get_ini_path_value("UserData.Dirs", "repositories_dir")

###########################################################
# Cache
###########################################################

# Get cache root dir
def get_cache_root_dir():
    return ini.get_ini_path_value("UserData.Dirs", "cache_dir")

# Get cache gaming root dir
def get_cache_gaming_root_dir():
    return paths.join_paths(
        get_cache_root_dir(),
        config.LockerFolderType.GAMING)

# Get cache gaming roms root dir
def get_cache_gaming_roms_root_dir():
    return paths.join_paths(
        get_cache_gaming_root_dir(),
        config.Supercategory.ROMS)

# Get cache gaming rom dir
def get_cache_gaming_rom_dir(game_category, game_subcategory, game_name):
    return paths.join_paths(
        get_cache_gaming_roms_root_dir(),
        game_category,
        game_subcategory,
        game_name)

# Get cache gaming install root dir
def get_cache_gaming_installs_root_dir():
    return paths.join_paths(
        get_cache_gaming_root_dir(),
        config.Supercategory.INSTALLS)

# Get cache gaming install dir
def get_cache_gaming_install_dir(game_category, game_subcategory, game_name):
    game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)
    game_name_path = gameinfo.derive_game_name_path_from_name(game_name, game_platform)
    return paths.join_paths(
        get_cache_gaming_installs_root_dir(),
        game_category,
        game_subcategory,
        game_name_path)

# Get cache gaming saves root dir
def get_cache_gaming_saves_root_dir():
    return paths.join_paths(
        get_cache_gaming_root_dir(),
        config.Supercategory.SAVES)

# Get cache gaming save dir
def get_cache_gaming_save_dir(game_category, game_subcategory, game_name, save_type = None):
    if save_type:
        return paths.join_paths(
            get_cache_gaming_saves_root_dir(),
            game_category,
            game_subcategory,
            game_name,
            save_type)
    else:
        return paths.join_paths(
            get_cache_gaming_saves_root_dir(),
            game_category,
            game_subcategory,
            game_name)

# Get cache gaming setup root dir
def get_cache_gaming_setup_root_dir():
    return paths.join_paths(
        get_cache_gaming_root_dir(),
        config.Supercategory.SETUP)

# Get cache gaming setup dir
def get_cache_gaming_setup_dir(game_category, game_subcategory, game_name):
    return paths.join_paths(
        get_cache_gaming_setup_root_dir(),
        game_category,
        game_subcategory,
        game_name)
