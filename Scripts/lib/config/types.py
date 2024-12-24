# Imports
import os
import sys
import enum

# Case enumeration type
class CaseEnum(enum.Enum):
    def __new__(cls, value, lowercase, camelcase):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.lowercase = lowercase
        obj.camelcase = camelcase
        return obj
    @classmethod
    def members(cls):
        return [member for member in cls.__members__.values()]
    @classmethod
    def get_values(cls):
        return [member.value for member in cls]
    @classmethod
    def get_lowercase_values(cls):
        return [member.lowercase for member in cls]
    @classmethod
    def get_camelcase_values(cls):
        return [member.camelcase for member in cls]

# Locker types
class LockerType(CaseEnum):
    ARTWORK     = (0, "artwork", "Artwork")
    BOOKS       = (1, "books", "Books")
    DEVELOPMENT = (2, "development", "Development")
    DOCUMENTS   = (3, "documents", "Documents")
    GAMING      = (4, "gaming", "Gaming")
    MOVIES      = (5, "movies", "Movies")
    MUSIC       = (6, "music", "Music")
    PHOTOS      = (7, "photos", "Photos")
    PROGRAMS    = (8, "programs", "Programs")

# Passphrase types
class PassphraseType(CaseEnum):
    NONE        = (0, "none", "None")
    GENERAL     = (1, "general", "General")
    LOCKER      = (2, "locker", "Locker")

# Backup types
class BackupType(CaseEnum):
    COPY        = (0, "copy", "Copy")
    ARCHIVE     = (1, "archive", "Archive")
    SYNC        = (2, "sync", "Sync")

# Source types
class SourceType(CaseEnum):
    LOCAL       = (0, "local", "Local")
    REMOTE      = (1, "remote", "Remote")

# Generation modes
class GenerationType(CaseEnum):
    CUSTOM      = (0, "custom", "Custom")
    STANDARD    = (1, "standard", "Standard")

# Steam id formats
class SteamIDFormatType(CaseEnum):
    STEAMID_64  = (0, "steamid64", "SteamID64")
    STEAMID_3L  = (1, "steamid3l", "SteamID3L")
    STEAMID_3S  = (2, "steamid3s", "SteamID3S")
    STEAMID_CL  = (3, "steamidcl", "SteamIDCL")
    STEAMID_CS  = (4, "steamidcs", "SteamIDCS")

# Steam branch formats
class SteamBranchType(CaseEnum):
    PUBLIC      = (0, "public", "Public")

# Metadata format types
class MetadataFormatType(CaseEnum):
    PEGASUS     = (0, "pegasus", "Pegasus")

# Metadata source types
class MetadataSourceType(CaseEnum):
    THEGAMESDB  = (0, "thegamesdb", "TheGamesDB")
    GAMEFAQS    = (1, "gamefaqs", "GameFAQs")
    STORE       = (2, "store", "Store")

# Addon types
class AddonType(CaseEnum):
    DLC         = (0, "dlc", "DLC")
    UPDATES     = (1, "updates", "Updates")

# Launch types
class LaunchType(CaseEnum):
    NONE        = (0, "none", "None")
    LAUNCH_FILE = (1, "launch_file", "LaunchFile")
    LAUNCH_NAME = (2, "launch_name", "LaunchName")

# Unit types
class UnitType(CaseEnum):
    SECONDS     = (0, "seconds", "Seconds")
    MINUTES     = (1, "minutes", "Minutes")
    HOURS       = (2, "hours", "Hours")

# Prefix types
class PrefixType(CaseEnum):
    DEFAULT     = (0, "default", "Default")
    TOOL        = (1, "tool", "Tool")
    EMULATOR    = (2, "emulator", "Emulator")
    GAME        = (3, "game", "Game")
    SETUP       = (4, "setup", "Setup")

# Save types
class SaveType(CaseEnum):
    GENERAL     = (0, "general", "General")
    WINE        = (1, "wine", "Wine")
    SANDBOXIE   = (2, "sandboxie", "Sandboxie")

# Save action types
class SaveActionType(CaseEnum):
    PACK        = (0, "pack", "Pack")
    UNPACK      = (1, "unpack", "Unpack")

# Remote action types
class RemoteActionType(CaseEnum):
    INIT        = (0, "init", "Init")
    DOWNLOAD    = (1, "download", "Download")
    UPLOAD      = (2, "upload", "Upload")
    PULL        = (3, "pull", "Pull")
    PUSH        = (4, "push", "Push")
    MERGE       = (5, "merge", "Merge")
    DIFF        = (6, "diff", "Diff")
    LIST        = (7, "list", "List")
    MOUNT       = (8, "mount", "Mount")
class RemoteActionSyncType(CaseEnum):
    PULL = RemoteActionType.PULL
    PUSH = RemoteActionType.PUSH
    MERGE = RemoteActionType.MERGE
class RemoteActionChangeType(CaseEnum):
    DOWNLOAD = RemoteActionType.DOWNLOAD
    UPLOAD = RemoteActionType.UPLOAD
    PULL = RemoteActionType.PULL
    PUSH = RemoteActionType.PUSH
    MERGE = RemoteActionType.MERGE

# Capture types
class CaptureType(CaseEnum):
    NONE        = (0, "none", "None")
    SCREENSHOT  = (1, "screenshot", "Screenshot")
    VIDEO       = (2, "video", "Video")

# Disc types
class DiscType(CaseEnum):
    NORMAL      = (0, "normal", "Normal")
    MACWIN      = (1, "macwin", "MacWin")

# Asset types
class AssetType(CaseEnum):
    BACKGROUND  = (0, "background", "Background")
    BOXBACK     = (1, "boxback", "BoxBack")
    BOXFRONT    = (2, "boxfront", "BoxFront")
    LABEL       = (3, "label", "Label")
    SCREENSHOT  = (4, "screenshot", "Screenshot")
    VIDEO       = (5, "video", "Video")
class AssetMinType(CaseEnum):
    BOXFRONT = AssetType.BOXFRONT
    VIDEO = AssetType.VIDEO
class AssetImageType(CaseEnum):
    BACKGROUND = AssetType.BACKGROUND
    BOXBACK = AssetType.BOXBACK
    BOXFRONT = AssetType.BOXFRONT
    LABEL = AssetType.LABEL
    SCREENSHOT = AssetType.SCREENSHOT
class AssetVideoType(CaseEnum):
    VIDEO = AssetType.VIDEO

# Message types
class MessageType(CaseEnum):
    GENERAL     = (0, "general", "General")
    OK          = (1, "ok", "OK")
    YES_NO      = (2, "yesno", "YesNo")
    CANCEL      = (3, "cancel", "Cancel")
    OK_CANCEL   = (4, "ok_cancel", "OkCancel")
    ERROR       = (5, "error", "Error")
    AUTO_CLOSE  = (6, "auto_close", "AutoClose")
    GET_TEXT    = (7, "get_text", "GetText")
    GET_FILE    = (8, "get_file", "GetFile")
    GET_FOLDER  = (9, "get_folder", "GetFolder")

# Installer types
class InstallerType(CaseEnum):
    INNO        = (0, "inno", "Inno")
    NSIS        = (1, "nsis", "NSIS")
    INS         = (2, "installshield", "InstallShield")
    SEVENZIP    = (3, "7zip", "7Zip")
    WINRAR      = (4, "winrar", "WinRAR")
    UNKNOWN     = (5, "unknown", "Unknown")

# Release types
class ReleaseType(CaseEnum):
    PROGRAM     = (0, "program", "Program")
    INSTALLER   = (1, "installer", "Installer")
    ARCHIVE     = (2, "archive", "Archive")

# Sync remote types
class SyncRemoteType(CaseEnum):
    DRIVE       = (0, "drive", "Drive")
    B2          = (1, "b2", "B2")

# Archive types
class ArchiveType(CaseEnum):
    ZIP         = (0, "zip", "Zip")
    SEVENZIP    = (1, "7z", "7Z")

# Preset types
class PresetType(CaseEnum):
    BACKUP_MICROSOFT        = (0, "backup_microsoft", "Backup_Microsoft")
    BACKUP_NINTENDOGEN      = (1, "backup_nintendogen", "Backup_NintendoGen")
    BACKUP_NINTENDOSWITCH   = (2, "backup_nintendoswitch", "Backup_NintendoSwitch")
    BACKUP_OTHERGEN         = (3, "backup_othergen", "Backup_OtherGen")
    BACKUP_SONYGEN          = (4, "backup_sonygen", "Backup_SonyGen")
    BACKUP_SONYPS3          = (5, "backup_sonyps3", "Backup_SonyPS3")
    BACKUP_SONYPS4          = (6, "backup_sonyps4", "Backup_SonyPS4")
    BACKUP_SONYPSN          = (7, "backup_sonypsn", "Backup_SonyPSN")

# Store types
class StoreType(CaseEnum):
    AMAZON                  = (0, "amazon", "Amazon")
    GOG                     = (1, "gog", "GOG")
    EPIC                    = (2, "epic", "Epic")
    ITCHIO                  = (3, "itchio", "Itchio")
    LEGACY                  = (4, "legacy", "Legacy")
    STEAM                   = (5, "steam", "Steam")

# Store action types
class StoreActionType(CaseEnum):
    LOGIN                   = (0, "login", "Login")
    DISPLAY_PURCHASES       = (1, "display_purchases", "DisplayPurchases")
    IMPORT_PURCHASES        = (2, "import_purchases", "ImportPurchases")
    INSTALL_GAME            = (3, "install_game", "InstallGame")
    LAUNCH_GAME             = (4, "launch_game", "LaunchGame")
    DOWNLOAD_GAME           = (5, "download_game", "DownloadGame")
    DOWNLOAD_ASSET          = (6, "download_asset", "DownloadAsset")
    UPDATE_JSON             = (7, "update_json", "UpdateJson")
    UPDATE_METADATA         = (8, "update_metadata", "UpdateMetadata")
    CHECK_VERSIONS          = (9, "check_versions", "CheckVersions")
    EXPORT_SAVES            = (10, "export_saves", "ExportSaves")
    IMPORT_SAVES            = (11, "import_saves", "ImportSaves")

# Store identifier types
class StoreIdentifierType(CaseEnum):
    INFO                    = (0, "info", "Info")
    INSTALL                 = (1, "install", "Install")
    LAUNCH                  = (2, "launch", "Launch")
    DOWNLOAD                = (3, "download", "Download")
    ASSET                   = (4, "asset", "Asset")
    METADATA                = (5, "metadata", "Metadata")

# Playlist types
class PlaylistType(CaseEnum):
    TREE                    = (0, "tree", "Tree")
    LOCAL                   = (1, "local", "Local")

# Merge types
class MergeType(CaseEnum):
    REPLACE                 = (0, "replace", "Replace")
    ADDITIVE                = (1, "additive", "Additive")
    SAFE_REPLACE            = (2, "safereplace", "SafeReplace")
    SAFE_ADDITIVE           = (3, "safeadditive", "SafeAdditive")

# Web driver types
class WebDriverType(CaseEnum):
    FIREFOX                 = (0, "firefox", "Firefox")
    CHROME                  = (1, "chrome", "Chrome")

# Image types
class ImageType(CaseEnum):
    JPEG                    = (0, "jpeg", "JPEG")
    PNG                     = (1, "png", "PNG")
