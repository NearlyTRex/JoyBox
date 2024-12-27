# Imports
import os
import sys
import enum

# Case enumeration type
class CaseEnum(enum.Enum):
    def __new__(cls, value, cvalue):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.cvalue = cvalue
        return obj
    @classmethod
    def members(cls):
        return [member for member in cls.__members__.values()]
    @classmethod
    def values(cls):
        return [member.value for member in cls]
    @classmethod
    def cvalues(cls):
        return [member.cvalue for member in cls]

# Locker types
class LockerType(CaseEnum):
    ARTWORK                 = ("artwork", "Artwork")
    BOOKS                   = ("books", "Books")
    DEVELOPMENT             = ("development", "Development")
    DOCUMENTS               = ("documents", "Documents")
    GAMING                  = ("gaming", "Gaming")
    MOVIES                  = ("movies", "Movies")
    MUSIC                   = ("music", "Music")
    PHOTOS                  = ("photos", "Photos")
    PROGRAMS                = ("programs", "Programs")

# Passphrase types
class PassphraseType(CaseEnum):
    NONE                    = ("none", "None")
    GENERAL                 = ("general", "General")
    LOCKER                  = ("locker", "Locker")

# Backup types
class BackupType(CaseEnum):
    COPY                    = ("copy", "Copy")
    ARCHIVE                 = ("archive", "Archive")

# Source types
class SourceType(CaseEnum):
    LOCAL                   = ("local", "Local")
    REMOTE                  = ("remote", "Remote")

# Generation modes
class GenerationType(CaseEnum):
    CUSTOM                  = ("custom", "Custom")
    STANDARD                = ("standard", "Standard")

# Steam id formats
class SteamIDFormatType(CaseEnum):
    STEAMID_64              = ("steamid64", "SteamID64")
    STEAMID_3L              = ("steamid3l", "SteamID3L")
    STEAMID_3S              = ("steamid3s", "SteamID3S")
    STEAMID_CL              = ("steamidcl", "SteamIDCL")
    STEAMID_CS              = ("steamidcs", "SteamIDCS")

# Steam branch formats
class SteamBranchType(CaseEnum):
    PUBLIC                  = ("public", "Public")

# Metadata format types
class MetadataFormatType(CaseEnum):
    PEGASUS                 = ("pegasus", "Pegasus")

# Metadata source types
class MetadataSourceType(CaseEnum):
    THEGAMESDB              = ("thegamesdb", "TheGamesDB")
    GAMEFAQS                = ("gamefaqs", "GameFAQs")
    STORE                   = ("store", "Store")

# Addon types
class AddonType(CaseEnum):
    DLC                     = ("dlc", "DLC")
    UPDATES                 = ("updates", "Updates")

# Launch types
class LaunchType(CaseEnum):
    NONE                    = ("none", "None")
    LAUNCH_FILE             = ("launch_file", "LaunchFile")
    LAUNCH_NAME             = ("launch_name", "LaunchName")

# Unit types
class UnitType(CaseEnum):
    SECONDS                 = ("seconds", "Seconds")
    MINUTES                 = ("minutes", "Minutes")
    HOURS                   = ("hours", "Hours")

# Prefix types
class PrefixType(CaseEnum):
    DEFAULT                 = ("default", "Default")
    TOOL                    = ("tool", "Tool")
    EMULATOR                = ("emulator", "Emulator")
    GAME                    = ("game", "Game")
    SETUP                   = ("setup", "Setup")

# Save types
class SaveType(CaseEnum):
    GENERAL                 = ("general", "General")
    WINE                    = ("wine", "Wine")
    SANDBOXIE               = ("sandboxie", "Sandboxie")

# Save action types
class SaveActionType(CaseEnum):
    PACK                    = ("pack", "Pack")
    UNPACK                  = ("unpack", "Unpack")

# Remote types
class RemoteType(CaseEnum):
    DRIVE                   = ("drive", "Drive")
    B2                      = ("b2", "B2")

# Remote action types
class RemoteActionType(CaseEnum):
    INIT                    = ("init", "Init")
    DOWNLOAD                = ("download", "Download")
    UPLOAD                  = ("upload", "Upload")
    PULL                    = ("pull", "Pull")
    PUSH                    = ("push", "Push")
    MERGE                   = ("merge", "Merge")
    DIFF                    = ("diff", "Diff")
    LIST                    = ("list", "List")
    MOUNT                   = ("mount", "Mount")
RemoteActionSyncTypes = [
    RemoteActionType.PULL,
    RemoteActionType.PUSH,
    RemoteActionType.MERGE
]
RemoteActionChangeTypes = [
    RemoteActionType.DOWNLOAD,
    RemoteActionType.UPLOAD,
    RemoteActionType.PULL,
    RemoteActionType.PUSH,
    RemoteActionType.MERGE
]

# Capture types
class CaptureType(CaseEnum):
    NONE                    = ("none", "None")
    SCREENSHOT              = ("screenshot", "Screenshot")
    VIDEO                   = ("video", "Video")

# Disc types
class DiscType(CaseEnum):
    NORMAL                  = ("normal", "Normal")
    MACWIN                  = ("macwin", "MacWin")

# Asset types
class AssetType(CaseEnum):
    BACKGROUND              = ("background", "Background")
    BOXBACK                 = ("boxback", "BoxBack")
    BOXFRONT                = ("boxfront", "BoxFront")
    LABEL                   = ("label", "Label")
    SCREENSHOT              = ("screenshot", "Screenshot")
    VIDEO                   = ("video", "Video")
AssetMinTypes = [
    AssetType.BOXFRONT,
    AssetType.VIDEO
]
AssetImageTypes = [
    AssetType.BACKGROUND,
    AssetType.BOXBACK,
    AssetType.BOXFRONT,
    AssetType.LABEL,
    AssetType.SCREENSHOT
]
AssetVideoTypes = [
    AssetType.VIDEO
]

# Message types
class MessageType(CaseEnum):
    GENERAL                 = ("general", "General")
    OK                      = ("ok", "OK")
    YES_NO                  = ("yesno", "YesNo")
    CANCEL                  = ("cancel", "Cancel")
    OK_CANCEL               = ("ok_cancel", "OkCancel")
    ERROR                   = ("error", "Error")
    AUTO_CLOSE              = ("auto_close", "AutoClose")
    GET_TEXT                = ("get_text", "GetText")
    GET_FILE                = ("get_file", "GetFile")
    GET_FOLDER              = ("get_folder", "GetFolder")

# Installer types
class InstallerType(CaseEnum):
    INNO                    = ("inno", "Inno")
    NSIS                    = ("nsis", "NSIS")
    INS                     = ("installshield", "InstallShield")
    SEVENZIP                = ("7zip", "7Zip")
    WINRAR                  = ("winrar", "WinRAR")
    UNKNOWN                 = ("unknown", "Unknown")

# Release types
class ReleaseType(CaseEnum):
    PROGRAM                 = ("program", "Program")
    INSTALLER               = ("installer", "Installer")
    ARCHIVE                 = ("archive", "Archive")

# Archive types
class ArchiveType(CaseEnum):
    ZIP                     = ("zip", "Zip")
    SEVENZIP                = ("7z", "7Z")

# Preset types
class PresetType(CaseEnum):
    BACKUP_MICROSOFT        = ("backup_microsoft", "Backup_Microsoft")
    BACKUP_NINTENDOGEN      = ("backup_nintendogen", "Backup_NintendoGen")
    BACKUP_NINTENDOSWITCH   = ("backup_nintendoswitch", "Backup_NintendoSwitch")
    BACKUP_OTHERGEN         = ("backup_othergen", "Backup_OtherGen")
    BACKUP_SONYGEN          = ("backup_sonygen", "Backup_SonyGen")
    BACKUP_SONYPS3          = ("backup_sonyps3", "Backup_SonyPS3")
    BACKUP_SONYPS4          = ("backup_sonyps4", "Backup_SonyPS4")
    BACKUP_SONYPSN          = ("backup_sonypsn", "Backup_SonyPSN")

# Store types
class StoreType(CaseEnum):
    AMAZON                  = ("amazon", "Amazon")
    GOG                     = ("gog", "GOG")
    EPIC                    = ("epic", "Epic")
    ITCHIO                  = ("itchio", "Itchio")
    LEGACY                  = ("legacy", "Legacy")
    STEAM                   = ("steam", "Steam")

# Store action types
class StoreActionType(CaseEnum):
    LOGIN                   = ("login", "Login")
    DISPLAY_PURCHASES       = ("display_purchases", "DisplayPurchases")
    IMPORT_PURCHASES        = ("import_purchases", "ImportPurchases")
    INSTALL_GAME            = ("install_game", "InstallGame")
    LAUNCH_GAME             = ("launch_game", "LaunchGame")
    DOWNLOAD_GAME           = ("download_game", "DownloadGame")
    DOWNLOAD_ASSET          = ("download_asset", "DownloadAsset")
    UPDATE_JSON             = ("update_json", "UpdateJson")
    UPDATE_METADATA         = ("update_metadata", "UpdateMetadata")
    CHECK_VERSIONS          = ("check_versions", "CheckVersions")
    EXPORT_SAVES            = ("export_saves", "ExportSaves")
    IMPORT_SAVES            = ("import_saves", "ImportSaves")

# Store identifier types
class StoreIdentifierType(CaseEnum):
    INFO                    = ("info", "Info")
    INSTALL                 = ("install", "Install")
    LAUNCH                  = ("launch", "Launch")
    DOWNLOAD                = ("download", "Download")
    ASSET                   = ("asset", "Asset")
    METADATA                = ("metadata", "Metadata")

# Playlist types
class PlaylistType(CaseEnum):
    TREE                    = ("tree", "Tree")
    LOCAL                   = ("local", "Local")

# Merge types
class MergeType(CaseEnum):
    REPLACE                 = ("replace", "Replace")
    ADDITIVE                = ("additive", "Additive")
    SAFE_REPLACE            = ("safereplace", "SafeReplace")
    SAFE_ADDITIVE           = ("safeadditive", "SafeAdditive")

# Web driver types
class WebDriverType(CaseEnum):
    FIREFOX                 = ("firefox", "Firefox")
    CHROME                  = ("chrome", "Chrome")

# Image types
class ImageType(CaseEnum):
    JPEG                    = ("jpeg", "JPEG")
    PNG                     = ("png", "PNG")
