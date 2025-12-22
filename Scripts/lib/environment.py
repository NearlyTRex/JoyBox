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

###########################################################
# System capabilities
###########################################################

# Determine if windows platform
def IsWindowsPlatform():
    return sys.platform.startswith("win32")

# Determine if linux platform
def IsLinuxPlatform():
    return sys.platform.startswith("linux")

# Determine if mac platform
def IsMacPlatform():
    return sys.platform.startswith("darwin")

# Determine if unix platform
def IsUnixPlatform():
    return IsMacPlatform() or IsLinuxPlatform()

# Determine if wine platform
def IsWinePlatform():
    return IsLinuxPlatform()

# Determine if sandboxie platform
def IsSandboxiePlatform():
    return IsWindowsPlatform()

# Get current platform
def GetCurrentPlatform():
    if IsWindowsPlatform():
        return "windows"
    elif IsLinuxPlatform():
        return "linux"
    elif IsMacPlatform():
        return "macos"
    return None

# Get current timestamp
def GetCurrentTimestamp():
    return int(time.time())

# Get home directory
def GetHomeDirectory():
    return os.path.expanduser("~")

# Get cookie directory
def GetCookieDirectory():
    return paths.join_paths(GetHomeDirectory(), "Cookies")

# Get log directory
def GetLogDirectory():
    return paths.join_paths(GetHomeDirectory(), "Logs")

# Determine if symlinks are supported
def AreSymlinksSupported():
    if IsUnixPlatform():
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
def GetToolsRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "tools_dir")

###########################################################
# Emulators
###########################################################

# Get emulators root dir
def GetEmulatorsRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "emulators_dir")

###########################################################
# Locker
###########################################################

# Get local locker root dir
def GetLocalLockerRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "local_locker_dir")

# Get remote locker root dir
def GetRemoteLockerRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "remote_locker_dir")

# Get locker root dir
def GetLockerRootDir(source_type = None):
    if source_type == config.SourceType.REMOTE:
        return GetRemoteLockerRootDir()
    else:
        return GetLocalLockerRootDir()

###########################################################
# Locker - Development
###########################################################

# Get locker development root dir
def GetLockerDevelopmentRootDir(source_type = None):
    return paths.join_paths(
        GetLockerRootDir(source_type),
        config.LockerFolderType.DEVELOPMENT)

# Get locker development archives root dir
def GetLockerDevelopmentArchivesRootDir(source_type = None):
    return paths.join_paths(
        GetLockerDevelopmentRootDir(source_type),
        "Archive")

###########################################################
# Locker - Gaming
###########################################################

# Get locker gaming root dir
def GetLockerGamingRootDir(source_type = None):
    return paths.join_paths(
        GetLockerRootDir(source_type),
        config.LockerFolderType.GAMING)

# Get locker gaming roms root dir
def GetLockerGamingRomsRootDir(source_type = None):
    return paths.join_paths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.ROMS)

# Get locker gaming dlc root dir
def GetLockerGamingDLCRootDir(source_type = None):
    return paths.join_paths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.DLC)

# Get locker gaming update root dir
def GetLockerGamingUpdateRootDir(source_type = None):
    return paths.join_paths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.UPDATES)

# Get locker gaming tags root dir
def GetLockerGamingTagsRootDir(source_type = None):
    return paths.join_paths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.TAGS)

###########################################################
# Locker - Gaming - Files
###########################################################

# Get locker gaming files offset
def GetLockerGamingFilesOffset(game_supercategory, game_category, game_subcategory, game_name):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return paths.join_paths(
        game_supercategory,
        game_category,
        game_subcategory,
        game_name_path)

# Get locker gaming files dir
def GetLockerGamingFilesDir(game_supercategory, game_category, game_subcategory, game_name, source_type = None):
    return paths.join_paths(
        GetLockerGamingRootDir(source_type),
        GetLockerGamingFilesOffset(game_supercategory, game_category, game_subcategory, game_name))

###########################################################
# Locker - Gaming - Saves
###########################################################

# Get locker gaming saves root dir
def GetLockerGamingSavesRootDir(source_type = None):
    return paths.join_paths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.SAVES)

# Get locker gaming save dir
def GetLockerGamingSaveDir(game_supercategory, game_category, game_subcategory, game_name, source_type = None):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return paths.join_paths(
        GetLockerGamingSavesRootDir(source_type),
        game_category,
        game_subcategory,
        game_name_path)

###########################################################
# Locker - Gaming - Assets
###########################################################

# Get locker gaming assets root dir
def GetLockerGamingAssetsRootDir(source_type = None):
    return paths.join_paths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.ASSETS)

# Get locker gaming asset dir
def GetLockerGamingAssetDir(game_category, game_subcategory, asset_type, source_type = None):
    return paths.join_paths(
        GetLockerGamingAssetsRootDir(source_type),
        game_category,
        game_subcategory,
        asset_type)

# Get locker gaming asset file
def GetLockerGamingAssetFile(game_category, game_subcategory, game_name, asset_type, source_type = None):
    asset_file = "%s%s" % (game_name, asset_type.cval())
    return paths.join_paths(
        GetLockerGamingAssetsRootDir(source_type),
        game_category,
        game_subcategory,
        asset_type,
        asset_file)

###########################################################
# Locker - Gaming - Emulators
###########################################################

# Get locker gaming emulators root dir
def GetLockerGamingEmulatorsRootDir(source_type = None):
    return paths.join_paths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.EMULATORS)

# Get locker gaming emulator binaries dir
def GetLockerGamingEmulatorBinariesDir(emu_name, emu_platform, source_type = None):
    return paths.join_paths(
        GetLockerGamingEmulatorsRootDir(source_type),
        emu_name,
        "Binaries",
        emu_platform)

# Get locker gaming emulator setup dir
def GetLockerGamingEmulatorSetupDir(emu_name, source_type = None):
    return paths.join_paths(
        GetLockerGamingEmulatorsRootDir(source_type),
        emu_name,
        "Setup")

###########################################################
# Locker - Music
###########################################################

# Get locker music root dir
def GetLockerMusicRootDir(source_type = None, genre_type = None):
    if genre_type:
        return paths.join_paths(GetLockerRootDir(source_type), config.LockerFolderType.MUSIC, genre_type)
    return paths.join_paths(GetLockerRootDir(source_type), config.LockerFolderType.MUSIC)

# Get locker music dir with genre type handling
def GetLockerMusicDir(genre_type = None):
    if genre_type:
        return GetLockerMusicRootDir(genre_type = genre_type)
    else:
        return GetLockerMusicRootDir()

# Get locker music album dir
def GetLockerMusicAlbumDir(album_name, artist_name = None, source_type = None, genre_type = None):
    if artist_name:
        return paths.join_paths(GetLockerMusicRootDir(source_type, genre_type), artist_name, album_name)
    return paths.join_paths(GetLockerMusicRootDir(source_type, genre_type), album_name)

###########################################################
# Locker - Photos
###########################################################

# Get locker photos root dir
def GetLockerPhotosRootDir(source_type = None):
    return paths.join_paths(
        GetLockerRootDir(source_type),
        config.LockerFolderType.PHOTOS)

###########################################################
# Locker - Programs
###########################################################

# Get locker programs root dir
def GetLockerProgramsRootDir(source_type = None):
    return paths.join_paths(
        GetLockerRootDir(source_type),
        config.LockerFolderType.PROGRAMS)

# Get locker programs tools root dir
def GetLockerProgramsToolsRootDir(source_type = None):
    return paths.join_paths(
        GetLockerProgramsRootDir(source_type),
        "Tools")

# Get locker program tool dir
def GetLockerProgramToolDir(tool_name, tool_platform = None, source_type = None):
    if tool_platform:
        return paths.join_paths(
            GetLockerProgramsToolsRootDir(source_type),
            tool_name,
            tool_platform)
    else:
        return paths.join_paths(
            GetLockerProgramsToolsRootDir(source_type),
            tool_name)

###########################################################
# Metadata - Games
###########################################################

# Get game metadata root dir
def GetGameMetadataRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "game_metadata_dir")

# Get pegasus metadata root dir
def GetGamePegasusMetadataRootDir():
    return paths.join_paths(GetGameMetadataRootDir(), "Pegasus")

# Get pegasus metadata file
def GetGamePegasusMetadataFile(game_category, game_subcategory):
    return paths.join_paths(
        GetGamePegasusMetadataRootDir(),
        config.Supercategory.ROMS,
        game_category,
        game_subcategory,
        "metadata.pegasus.txt")

# Get pegasus metadata asset dir
def GetGamePegasusMetadataAssetDir(game_category, game_subcategory, asset_type):
    return paths.join_paths(
        GetGamePegasusMetadataRootDir(),
        config.Supercategory.ROMS,
        game_category,
        game_subcategory,
        asset_type)

# Get metadata file
def GetGameMetadataFile(game_category, game_subcategory, metadata_format = config.MetadataFormatType.PEGASUS):
    if metadata_format == config.MetadataFormatType.PEGASUS:
        return GetGamePegasusMetadataFile(game_category, game_subcategory)
    return None

# Check if file is a metadata file
def IsGameMetadataFile(metadata_file):
    return metadata_file.endswith("metadata.pegasus.txt")

# Get published metadata root dir
def GetGamePublishedMetadataRootDir():
    return paths.join_paths(GetGameMetadataRootDir(), "Published")

# Get misc metadata root dir
def GetGameMiscMetadataRootDir():
    return paths.join_paths(GetGameMetadataRootDir(), "Misc")

# Get hashes metadata root dir
def GetGameHashesMetadataRootDir():
    return paths.join_paths(GetGameMetadataRootDir(), "Hashes")

# Get hashes metadata file
def GetGameHashesMetadataFile(game_supercategory, game_category, game_subcategory):
    return paths.join_paths(
        GetGameHashesMetadataRootDir(),
        game_supercategory,
        game_category,
        game_subcategory + ".json")

# Get json metadata root dir
def GetGameJsonMetadataRootDir():
    return paths.join_paths(GetGameMetadataRootDir(), "Json")

# Get json rom metadata dir
def GetJsonMetadataDir(game_supercategory, game_category, game_subcategory):
    return paths.join_paths(
        GetGameJsonMetadataRootDir(),
        game_supercategory,
        game_category,
        game_subcategory)

# Get json metadata file
def GetGameJsonMetadataFile(game_supercategory, game_category, game_subcategory, game_name):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return paths.join_paths(
        GetJsonMetadataDir(game_supercategory, game_category, game_subcategory),
        game_name_path,
        game_name + ".json")

# Get json metadata ignore file
def GetGameJsonMetadataIgnoreFile(game_supercategory, game_category, game_subcategory):
    return paths.join_paths(
        GetJsonMetadataDir(game_supercategory, game_category, game_subcategory),
        "ignores.json")

###########################################################
# Metadata - Files
###########################################################

# Get file metadata root dir
def GetFileMetadataRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "file_metadata_dir")

# Get audio metadata root dir
def GetFileAudioMetadataRootDir(metadata_type, genre_type):
    return paths.join_paths(GetFileMetadataRootDir(), "Audio", metadata_type, genre_type)

# Get audio metadata dir (with optional artist support)
def GetFileAudioMetadataDir(metadata_type, genre_type, artist_name = None):
    if artist_name:
        return paths.join_paths(GetFileMetadataRootDir(), "Audio", metadata_type, genre_type, artist_name)
    return paths.join_paths(GetFileMetadataRootDir(), "Audio", metadata_type, genre_type)

# Get audio metadata archive file
def GetFileAudioMetadataArchiveFile(genre_type, album_name):
    return paths.join_paths(GetFileAudioMetadataRootDir(config.AudioMetadataType.ARCHIVE, genre_type), album_name + ".txt")

# Get audio metadata album dir
def GetFileAudioMetadataAlbumDir(metadata_type, genre_type, album_name, artist_name = None):
    if genre_type:
        output_dir = GetFileAudioMetadataDir(metadata_type, genre_type, artist_name)
        return paths.join_paths(output_dir, album_name)
    else:
        return paths.join_paths(GetFileMetadataRootDir(), album_name)

# Get audio metadata file
def GetFileAudioMetadataFile(metadata_type, genre_type, album_name, artist_name = None):
    if genre_type:
        output_dir = GetFileAudioMetadataDir(metadata_type, genre_type, artist_name)
    else:
        output_dir = GetFileMetadataRootDir()
    return paths.join_paths(output_dir, f"{album_name}.json")

###########################################################
# Scripts
###########################################################

# Get scripts root dir
def GetScriptsRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "scripts_dir")

# Get scripts bin dir
def GetScriptsBinDir():
    return paths.join_paths(GetScriptsRootDir(), "bin")

# Get scripts icons dir
def GetScriptsIconsDir():
    return paths.join_paths(GetScriptsRootDir(), "icons")

# Get scripts lib dir
def GetScriptsLibDir():
    return paths.join_paths(GetScriptsRootDir(), "lib")

# Get scripts command extension
def GetScriptsCommandExtension():
    if IsWindowsPlatform():
        return ".bat"
    else:
        return ""

# Get scripts executable extension
def GetScriptsExecutableExtension():
    if IsWindowsPlatform():
        return ".exe"
    else:
        return ""

###########################################################
# Repositories
###########################################################

# Get repositories root dir
def GetRepositoriesRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "repositories_dir")

###########################################################
# Cache
###########################################################

# Get cache root dir
def GetCacheRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "cache_dir")

# Get cache gaming root dir
def GetCacheGamingRootDir():
    return paths.join_paths(
        GetCacheRootDir(),
        config.LockerFolderType.GAMING)

# Get cache gaming roms root dir
def GetCacheGamingRomsRootDir():
    return paths.join_paths(
        GetCacheGamingRootDir(),
        config.Supercategory.ROMS)

# Get cache gaming rom dir
def GetCacheGamingRomDir(game_category, game_subcategory, game_name):
    return paths.join_paths(
        GetCacheGamingRomsRootDir(),
        game_category,
        game_subcategory,
        game_name)

# Get cache gaming install root dir
def GetCacheGamingInstallsRootDir():
    return paths.join_paths(
        GetCacheGamingRootDir(),
        config.Supercategory.INSTALLS)

# Get cache gaming install dir
def GetCacheGamingInstallDir(game_category, game_subcategory, game_name):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return paths.join_paths(
        GetCacheGamingInstallsRootDir(),
        game_category,
        game_subcategory,
        game_name_path)

# Get cache gaming saves root dir
def GetCacheGamingSavesRootDir():
    return paths.join_paths(
        GetCacheGamingRootDir(),
        config.Supercategory.SAVES)

# Get cache gaming save dir
def GetCacheGamingSaveDir(game_category, game_subcategory, game_name, save_type = None):
    if save_type:
        return paths.join_paths(
            GetCacheGamingSavesRootDir(),
            game_category,
            game_subcategory,
            game_name,
            save_type)
    else:
        return paths.join_paths(
            GetCacheGamingSavesRootDir(),
            game_category,
            game_subcategory,
            game_name)

# Get cache gaming setup root dir
def GetCacheGamingSetupRootDir():
    return paths.join_paths(
        GetCacheGamingRootDir(),
        config.Supercategory.SETUP)

# Get cache gaming setup dir
def GetCacheGamingSetupDir(game_category, game_subcategory, game_name):
    return paths.join_paths(
        GetCacheGamingSetupRootDir(),
        game_category,
        game_subcategory,
        game_name)
