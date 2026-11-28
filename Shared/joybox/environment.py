# Imports
import os
import os.path
import re

# Local imports
from joybox import platform_info
from joybox import config
from joybox import gamenaming
from joybox import settings
from joybox import paths
from joybox import lockerinfo

###########################################################
# System capabilities
###########################################################

# Get editor command
def get_editor():

    # First check ini config
    editor = settings.get_value("Tools.System", "editor")
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
    if platform_info.is_windows_platform():
        return "notepad.exe"
    return "nano"

###########################################################
# Tools
###########################################################

# Where tool programs install, from the UserData.Dirs tools_dir setting
def get_tools_root_dir():
    return settings.get_path_value("UserData.Dirs", "tools_dir")

###########################################################
# Emulators
###########################################################

# Where emulators install, from the UserData.Dirs emulators_dir setting
def get_emulators_root_dir():
    return settings.get_path_value("UserData.Dirs", "emulators_dir")

###########################################################
# Locker
###########################################################

# Mount path of the given locker, the local one by default
def get_locker_root_dir(locker_type = None):
    if locker_type is None:
        locker_type = config.LockerType.LOCAL
    locker_info = lockerinfo.LockerInfo(locker_type)
    return locker_info.get_mount_path()

###########################################################
# Locker - Development
###########################################################

# The locker's Development folder
def get_locker_development_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_root_dir(locker_type),
        config.LockerFolderType.DEVELOPMENT)

# The Archive folder under the locker's Development folder
def get_locker_development_archives_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_development_root_dir(locker_type),
        "Archive")

###########################################################
# Locker - Gaming
###########################################################

# The locker's Gaming folder, parent of the ROM, DLC, save and asset trees
def get_locker_gaming_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_root_dir(locker_type),
        config.LockerFolderType.GAMING)

# The ROMs supercategory folder under the locker's Gaming folder
def get_locker_gaming_roms_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.ROMS)

# The DLC supercategory folder under the locker's Gaming folder
def get_locker_gaming_dlc_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.DLC)

# The Updates supercategory folder under the locker's Gaming folder
def get_locker_gaming_update_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.UPDATES)

# The Tags supercategory folder under the locker's Gaming folder
def get_locker_gaming_tags_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.TAGS)

###########################################################
# Locker - Gaming - Files
###########################################################

# Relative path supercategory/category/subcategory/name of a game's files, with a
# first-letter folder before the name on letter platforms
def get_locker_gaming_files_offset(game_supercategory, game_category, game_subcategory, game_name):
    game_platform = gamenaming.derive_game_platform_from_categories(game_subcategory)
    game_name_path = gamenaming.derive_game_name_path_from_name(game_name, game_platform)
    return paths.join_paths(
        game_supercategory,
        game_category,
        game_subcategory,
        game_name_path)

# Absolute folder of a game's files: its relative offset under the locker's Gaming folder
def get_locker_gaming_files_dir(game_supercategory, game_category, game_subcategory, game_name, locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        get_locker_gaming_files_offset(game_supercategory, game_category, game_subcategory, game_name))

###########################################################
# Locker - Gaming - Saves
###########################################################

# The Saves supercategory folder under the locker's Gaming folder
def get_locker_gaming_saves_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.SAVES)

# Locker folder for one game's saves, by category, subcategory and name path
def get_locker_gaming_save_dir(game_category, game_subcategory, game_name, locker_type = None):
    game_platform = gamenaming.derive_game_platform_from_categories(game_subcategory)
    game_name_path = gamenaming.derive_game_name_path_from_name(game_name, game_platform)
    return paths.join_paths(
        get_locker_gaming_saves_root_dir(locker_type),
        game_category,
        game_subcategory,
        game_name_path)

###########################################################
# Locker - Gaming - Assets
###########################################################

# The Assets supercategory folder under the locker's Gaming folder
def get_locker_gaming_assets_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.ASSETS)

# Locker folder holding one asset type for a category and subcategory
def get_locker_gaming_asset_dir(game_category, game_subcategory, asset_type, locker_type = None):
    return paths.join_paths(
        get_locker_gaming_assets_root_dir(locker_type),
        game_category,
        game_subcategory,
        asset_type)

# Locker path of a game's asset: the game name plus the asset type's extension, in its asset folder
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

# The Emulators supercategory folder under the locker's Gaming folder
def get_locker_gaming_emulators_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_gaming_root_dir(locker_type),
        config.Supercategory.EMULATORS)

# Locker folder of an emulator's stored release for one platform, under its Binaries folder
def get_locker_gaming_emulator_binaries_dir(emu_name, emu_platform, locker_type = None):
    return paths.join_paths(
        get_locker_gaming_emulators_root_dir(locker_type),
        emu_name,
        "Binaries",
        emu_platform)

# Locker folder of an emulator's Setup files, such as BIOS images
def get_locker_gaming_emulator_setup_dir(emu_name, locker_type = None):
    return paths.join_paths(
        get_locker_gaming_emulators_root_dir(locker_type),
        emu_name,
        "Setup")

###########################################################
# Locker - Music
###########################################################

# The locker's Music folder, or the genre's folder inside it when given one
def get_locker_music_root_dir(locker_type = None, genre_type = None):
    if genre_type:
        return paths.join_paths(get_locker_root_dir(locker_type), config.LockerFolderType.MUSIC, genre_type)
    return paths.join_paths(get_locker_root_dir(locker_type), config.LockerFolderType.MUSIC)

# Get locker music dir with genre type handling
def get_locker_music_dir(genre_type = None):
    if genre_type:
        return get_locker_music_root_dir(genre_type = genre_type)
    return get_locker_music_root_dir()

# Locker folder of an album, under its artist folder when given one
def get_locker_music_album_dir(album_name, artist_name = None, locker_type = None, genre_type = None):
    if artist_name:
        return paths.join_paths(get_locker_music_root_dir(locker_type, genre_type), artist_name, album_name)
    return paths.join_paths(get_locker_music_root_dir(locker_type, genre_type), album_name)

###########################################################
# Locker - Photos
###########################################################

# The locker's Photos folder
def get_locker_photos_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_root_dir(locker_type),
        config.LockerFolderType.PHOTOS)

###########################################################
# Locker - Programs
###########################################################

# The locker's Programs folder
def get_locker_programs_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_root_dir(locker_type),
        config.LockerFolderType.PROGRAMS)

# The Tools folder under the locker's Programs folder
def get_locker_programs_tools_root_dir(locker_type = None):
    return paths.join_paths(
        get_locker_programs_root_dir(locker_type),
        "Tools")

# Locker folder of a stored tool, under a per-platform folder when given one
def get_locker_program_tool_dir(tool_name, tool_platform = None, locker_type = None):
    if tool_platform:
        return paths.join_paths(
            get_locker_programs_tools_root_dir(locker_type),
            tool_name,
            tool_platform)
    return paths.join_paths(
        get_locker_programs_tools_root_dir(locker_type),
        tool_name)

###########################################################
# Metadata - Games
###########################################################

# Root of game metadata, from the UserData.Dirs game_metadata_dir setting
def get_game_metadata_root_dir():
    return settings.get_path_value("UserData.Dirs", "game_metadata_dir")

# The Pegasus folder under the game metadata root
def get_game_pegasus_metadata_root_dir():
    return paths.join_paths(get_game_metadata_root_dir(), "Pegasus")

# The metadata.pegasus.txt listing the ROMs of a category and subcategory
def get_game_pegasus_metadata_file(game_category, game_subcategory):
    return paths.join_paths(
        get_game_pegasus_metadata_root_dir(),
        config.Supercategory.ROMS,
        game_category,
        game_subcategory,
        "metadata.pegasus.txt")

# Folder of one asset type for a category and subcategory in the Pegasus metadata tree
def get_game_pegasus_metadata_asset_dir(game_category, game_subcategory, asset_type):
    return paths.join_paths(
        get_game_pegasus_metadata_root_dir(),
        config.Supercategory.ROMS,
        game_category,
        game_subcategory,
        asset_type)

# The metadata file for a category and subcategory in the given format; None for formats other than Pegasus
def get_game_metadata_file(game_category, game_subcategory, metadata_format = config.MetadataFormatType.PEGASUS):
    if metadata_format == config.MetadataFormatType.PEGASUS:
        return get_game_pegasus_metadata_file(game_category, game_subcategory)
    return None

# Check if file is a metadata file
def is_game_metadata_file(metadata_file):
    return metadata_file.endswith("metadata.pegasus.txt")

# The Published folder under the game metadata root
def get_game_published_metadata_root_dir():
    return paths.join_paths(get_game_metadata_root_dir(), "Published")

# The Misc folder under the game metadata root
def get_game_misc_metadata_root_dir():
    return paths.join_paths(get_game_metadata_root_dir(), "Misc")

# The Hashes folder under the game metadata root
def get_game_hashes_metadata_root_dir():
    return paths.join_paths(get_game_metadata_root_dir(), "Hashes")

# The <subcategory>.json holding file hashes for a supercategory and category
def get_game_hashes_metadata_file(game_supercategory, game_category, game_subcategory):
    return paths.join_paths(
        get_game_hashes_metadata_root_dir(),
        game_supercategory,
        game_category,
        game_subcategory + ".json")

# The Json folder under the game metadata root
def get_game_json_metadata_root_dir():
    return paths.join_paths(get_game_metadata_root_dir(), "Json")

# Get json rom metadata dir
def get_json_metadata_dir(game_supercategory, game_category, game_subcategory):
    return paths.join_paths(
        get_game_json_metadata_root_dir(),
        game_supercategory,
        game_category,
        game_subcategory)

# The <name>.json describing one game, in its name path folder of the Json metadata tree
def get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name):
    game_platform = gamenaming.derive_game_platform_from_categories(game_subcategory)
    game_name_path = gamenaming.derive_game_name_path_from_name(game_name, game_platform)
    return paths.join_paths(
        get_json_metadata_dir(game_supercategory, game_category, game_subcategory),
        game_name_path,
        game_name + ".json")

# The ignores.json beside a subcategory's game JSON files
def get_game_json_metadata_ignore_file(game_supercategory, game_category, game_subcategory):
    return paths.join_paths(
        get_json_metadata_dir(game_supercategory, game_category, game_subcategory),
        "ignores.json")

###########################################################
# Metadata - Files
###########################################################

# Root of non-game file metadata, from the UserData.Dirs file_metadata_dir setting
def get_file_metadata_root_dir():
    return settings.get_path_value("UserData.Dirs", "file_metadata_dir")

# Audio/<metadata type>/<genre> under the file metadata root
def get_file_audio_metadata_root_dir(metadata_type, genre_type):
    return paths.join_paths(get_file_metadata_root_dir(), "Audio", metadata_type, genre_type)

# Get audio metadata dir (with optional artist support)
def get_file_audio_metadata_dir(metadata_type, genre_type, artist_name = None):
    if artist_name:
        return paths.join_paths(get_file_metadata_root_dir(), "Audio", metadata_type, genre_type, artist_name)
    return paths.join_paths(get_file_metadata_root_dir(), "Audio", metadata_type, genre_type)

# The <album>.txt archive listing for an album in a genre
def get_file_audio_metadata_archive_file(genre_type, album_name):
    return paths.join_paths(get_file_audio_metadata_root_dir(config.AudioMetadataType.ARCHIVE, genre_type), album_name + ".txt")

# Folder of an album's audio metadata, under its genre and artist when given; directly
# under the file metadata root without a genre
def get_file_audio_metadata_album_dir(metadata_type, genre_type, album_name, artist_name = None):
    if genre_type:
        output_dir = get_file_audio_metadata_dir(metadata_type, genre_type, artist_name)
        return paths.join_paths(output_dir, album_name)
    return paths.join_paths(get_file_metadata_root_dir(), album_name)

# The <album>.json of an album's audio metadata, under its genre and artist when given;
# directly under the file metadata root without a genre
def get_file_audio_metadata_file(metadata_type, genre_type, album_name, artist_name = None):
    if genre_type:
        output_dir = get_file_audio_metadata_dir(metadata_type, genre_type, artist_name)
    else:
        output_dir = get_file_metadata_root_dir()
    return paths.join_paths(output_dir, f"{album_name}.json")

# The Locker/Hashes folder under the file metadata root
def get_file_locker_hashes_root_dir():
    return paths.join_paths(get_file_metadata_root_dir(), "Locker", "Hashes")

# Get file locker hashes file for a file, named by its first depth folders
def get_file_locker_hashes_file(file_path, depth = 4):
    folders = file_path.split(os.sep)[:-1][:depth]
    group_key = paths.join_paths(*folders) if folders else "root"
    return paths.join_paths(get_file_locker_hashes_root_dir(), group_key + ".csv")

###########################################################
# Scripts
###########################################################

# Get repo root dir (the parent of the Scripts directory)
def get_repo_root(expand = False):
    scripts_dir = settings.get_value("UserData.Dirs", "scripts_dir")
    root = re.sub(r"[\\/]Scripts[\\/]*$", "", scripts_dir) if scripts_dir else "$HOME/Repositories/JoyBox"
    return os.path.expandvars(root) if expand else root

# The JoyBox Scripts folder, from the UserData.Dirs scripts_dir setting
def get_scripts_root_dir():
    return settings.get_path_value("UserData.Dirs", "scripts_dir")

# The icons folder under the Scripts folder
def get_scripts_icons_dir():
    return paths.join_paths(get_scripts_root_dir(), "icons")

# Get the directory pip installs the JoyBox commands into, the venv's own
def get_commands_dir():
    venv_dir = settings.get_path_value("Tools.Python", "python_venv_dir")
    if platform_info.is_windows_platform():
        return paths.join_paths(venv_dir, "Scripts")
    return paths.join_paths(venv_dir, "bin")

# Get an installed JoyBox command
def get_command_path(command_name):
    extension = ".exe" if platform_info.is_windows_platform() else ""
    return paths.join_paths(get_commands_dir(), command_name + extension)

###########################################################
# Repositories
###########################################################

# Folder holding cloned repositories, from the UserData.Dirs repositories_dir setting
def get_repositories_root_dir():
    return settings.get_path_value("UserData.Dirs", "repositories_dir")

###########################################################
# Cache
###########################################################

# Root of the local cache, from the UserData.Dirs cache_dir setting
def get_cache_root_dir():
    return settings.get_path_value("UserData.Dirs", "cache_dir")

# The Sync folder under the cache root
def get_cache_sync_dir():
    return paths.join_paths(
        get_cache_root_dir(),
        "Sync")

# The Purchases folder under the cache root
def get_cache_purchases_dir():
    return paths.join_paths(
        get_cache_root_dir(),
        "Purchases")

# The Gaming folder under the cache root
def get_cache_gaming_root_dir():
    return paths.join_paths(
        get_cache_root_dir(),
        config.LockerFolderType.GAMING)

# Cache folder for one game under a supercategory, by category, subcategory and name path
def get_cache_gaming_game_dir(game_supercategory, game_category, game_subcategory, game_name):
    game_platform = gamenaming.derive_game_platform_from_categories(game_subcategory)
    game_name_path = gamenaming.derive_game_name_path_from_name(game_name, game_platform)
    return paths.join_paths(
        get_cache_gaming_root_dir(),
        game_supercategory,
        game_category,
        game_subcategory,
        game_name_path)

# The ROMs supercategory folder under the cache's Gaming folder
def get_cache_gaming_roms_root_dir():
    return paths.join_paths(
        get_cache_gaming_root_dir(),
        config.Supercategory.ROMS)

# Cache folder for one game's ROM files, by category, subcategory and name path
def get_cache_gaming_rom_dir(game_category, game_subcategory, game_name):
    return get_cache_gaming_game_dir(config.Supercategory.ROMS, game_category, game_subcategory, game_name)

# The Installs supercategory folder under the cache's Gaming folder
def get_cache_gaming_installs_root_dir():
    return paths.join_paths(
        get_cache_gaming_root_dir(),
        config.Supercategory.INSTALLS)

# Cache folder one game installs into, by category, subcategory and name path
def get_cache_gaming_install_dir(game_category, game_subcategory, game_name):
    return get_cache_gaming_game_dir(config.Supercategory.INSTALLS, game_category, game_subcategory, game_name)

# The Saves supercategory folder under the cache's Gaming folder
def get_cache_gaming_saves_root_dir():
    return paths.join_paths(
        get_cache_gaming_root_dir(),
        config.Supercategory.SAVES)

# Cache folder for one game's saves, narrowed to a save type folder when given one
def get_cache_gaming_save_dir(game_category, game_subcategory, game_name, save_type = None):
    save_dir = get_cache_gaming_game_dir(config.Supercategory.SAVES, game_category, game_subcategory, game_name)
    if save_type:
        return paths.join_paths(save_dir, save_type)
    return save_dir

# The Setup supercategory folder under the cache's Gaming folder
def get_cache_gaming_setup_root_dir():
    return paths.join_paths(
        get_cache_gaming_root_dir(),
        config.Supercategory.SETUP)

# Cache folder for one game's setup files, by category, subcategory and name path
def get_cache_gaming_setup_dir(game_category, game_subcategory, game_name):
    return get_cache_gaming_game_dir(config.Supercategory.SETUP, game_category, game_subcategory, game_name)
