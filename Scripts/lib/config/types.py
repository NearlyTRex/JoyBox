# Imports
import os
import sys
import enum

# Type enum
class EnumType(enum.Enum):
    def __new__(cls, value, cvalue = None):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.cvalue = cvalue if cvalue is not None else value
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

    @classmethod
    def is_valid(cls, value):
        if isinstance(value, cls):
            return True
        return value in cls.values()

    @classmethod
    def from_string(cls, value):
        for member in cls:
            if member.value.lower() == value.lower():
                return member
        return None

    @classmethod
    def to_string(cls, value):
        if isinstance(value, cls):
            return value.value
        if isinstance(value, str):
            member = cls.from_string(value)
            if member:
                return member.value
        return None

    @classmethod
    def to_lower_string(cls, value):
        value_str = cls.to_string(value)
        if value_str:
            return value_str.lower()
        return None

    @classmethod
    def to_upper_string(cls, value):
        value_str = cls.to_string(value)
        if value_str:
            return value_str.upper()
        return None

    def val(self):
        return self.value

    def lower(self):
        return self.value.lower()

    def upper(self):
        return self.value.upper()

# Locker types
class LockerType(EnumType):
    ARTWORK                 = ("Artwork")
    BOOKS                   = ("Books")
    DEVELOPMENT             = ("Development")
    DOCUMENTS               = ("Documents")
    GAMING                  = ("Gaming")
    MOVIES                  = ("Movies")
    MUSIC                   = ("Music")
    PHOTOS                  = ("Photos")
    PROGRAMS                = ("Programs")

# Passphrase types
class PassphraseType(EnumType):
    GENERAL                 = ("General")
    LOCKER                  = ("Locker")

# Backup types
class BackupType(EnumType):
    COPY                    = ("Copy")
    ARCHIVE                 = ("Archive")

# Github action type
class GithubActionType(EnumType):
    ARCHIVE                 = ("Archive")
    UPDATE                  = ("Update")

# Source types
class SourceType(EnumType):
    LOCAL                   = ("Local")
    REMOTE                  = ("Remote")

# Generation mode type
class GenerationModeType(EnumType):
    CUSTOM                  = ("Custom")
    STANDARD                = ("Standard")

# Analyze mode type
class AnalyzeModeType(EnumType):
    ALL                     = ("All")
    MISSING_GAME_FILES      = ("MissingGameFiles")
    UNPLAYABLE_GAMES        = ("UnplayableGames")

# Steam id formats
class SteamIDFormatType(EnumType):
    STEAMID_64              = ("SteamID64")
    STEAMID_3L              = ("SteamID3L")
    STEAMID_3S              = ("SteamID3S")
    STEAMID_CL              = ("SteamIDCL")
    STEAMID_CS              = ("SteamIDCS")

# Steam branch formats
class SteamBranchType(EnumType):
    PUBLIC                  = ("Public")

# Metadata format types
class MetadataFormatType(EnumType):
    PEGASUS                 = ("Pegasus")

# Metadata source types
class MetadataSourceType(EnumType):
    THEGAMESDB              = ("TheGamesDB")
    GAMEFAQS                = ("GameFAQs")
    STORE                   = ("Store")

# Addon types
class AddonType(EnumType):
    DLC                     = ("DLC")
    UPDATES                 = ("Updates")

# Launch types
class LaunchType(EnumType):
    NO_LAUNCHER             = ("NoLauncher")
    LAUNCH_FILE             = ("LaunchFile")
    LAUNCH_NAME             = ("LaunchName")

# Unit types
class UnitType(EnumType):
    SECONDS                 = ("Seconds")
    MINUTES                 = ("Minutes")
    HOURS                   = ("Hours")

# Prefix types
class PrefixType(EnumType):
    DEFAULT                 = ("Default")
    TOOL                    = ("Tool")
    EMULATOR                = ("Emulator")
    GAME                    = ("Game")
    SETUP                   = ("Setup")

# Save types
class SaveType(EnumType):
    GENERAL                 = ("General")
    WINE                    = ("Wine")
    SANDBOXIE               = ("Sandboxie")

# Save action types
class SaveActionType(EnumType):
    PACK                    = ("Pack")
    UNPACK                  = ("Unpack")

# Remote types
class RemoteType(EnumType):
    DRIVE                   = ("Drive")
    B2                      = ("B2")

# Remote action types
class RemoteActionType(EnumType):
    INIT                    = ("Init")
    DOWNLOAD                = ("Download")
    UPLOAD                  = ("Upload")
    PULL                    = ("Pull")
    PUSH                    = ("Push")
    MERGE                   = ("Merge")
    DIFF                    = ("Diff")
    LIST                    = ("List")
    MOUNT                   = ("Mount")

# Remote action type subsets
remote_action_sync_types = [
    RemoteActionType.PULL,
    RemoteActionType.PUSH,
    RemoteActionType.MERGE
]
remote_action_change_types = [
    RemoteActionType.DOWNLOAD,
    RemoteActionType.UPLOAD,
    RemoteActionType.PULL,
    RemoteActionType.PUSH,
    RemoteActionType.MERGE
]

# Capture types
class CaptureType(EnumType):
    SCREENSHOT              = ("Screenshot")
    VIDEO                   = ("Video")

# Disc types
class DiscType(EnumType):
    NORMAL                  = ("Normal")
    MACWIN                  = ("MacWin")

# Disc extract type
class DiscExtractType(EnumType):
    ISO                     = ("ISO")
    ARCHIVE                 = ("Archive")

# Disc source type
class DiscSourceType(EnumType):
    FOLDER                  = ("Folder")
    ZIP                     = ("Zip")

# Disc image type
class DiscImageType(EnumType):
    ISO                     = ("ISO")
    CUE                     = ("CUE")
    GDI                     = ("GDI")
    CHD                     = ("CHD")

# Asset types
class AssetType(EnumType):
    BACKGROUND              = ("Background")
    BOXBACK                 = ("BoxBack")
    BOXFRONT                = ("BoxFront")
    LABEL                   = ("Label")
    SCREENSHOT              = ("Screenshot")
    VIDEO                   = ("Video")

# Asset type subsets
asset_min_types = [
    AssetType.BOXFRONT,
    AssetType.VIDEO
]
asset_image_types = [
    AssetType.BACKGROUND,
    AssetType.BOXBACK,
    AssetType.BOXFRONT,
    AssetType.LABEL,
    AssetType.SCREENSHOT
]
asset_video_types = [
    AssetType.VIDEO
]

# Message types
class MessageType(EnumType):
    GENERAL                 = ("General")
    OK                      = ("OK")
    YES_NO                  = ("YesNo")
    CANCEL                  = ("Cancel")
    OK_CANCEL               = ("OkCancel")
    ERROR                   = ("Error")
    AUTO_CLOSE              = ("AutoClose")
    GET_TEXT                = ("GetText")
    GET_FILE                = ("GetFile")
    GET_FOLDER              = ("GetFolder")

# Installer types
class InstallerType(EnumType):
    INNO                    = ("Inno")
    NSIS                    = ("NSIS")
    INS                     = ("InstallShield")
    SEVENZIP                = ("7Zip")
    WINRAR                  = ("WinRAR")
    UNKNOWN                 = ("Unknown")

# Release types
class ReleaseType(EnumType):
    PROGRAM                 = ("Program")
    INSTALLER               = ("Installer")
    ARCHIVE                 = ("Archive")

# Archive types
class ArchiveType(EnumType):
    ZIP                     = ("Zip")
    SEVENZIP                = ("7Z")
    RAR                     = ("RAR")

# Preset tool types
class PresetToolType(EnumType):
    BACKUP_TOOL             = ("backup_tool")

# Preset option group types
class PresetOptionGroupType(EnumType):
    BACKUP_MICROSOFT        = ("Backup_Microsoft")
    BACKUP_NINTENDOGEN      = ("Backup_NintendoGen")
    BACKUP_NINTENDOSWITCH   = ("Backup_NintendoSwitch")
    BACKUP_OTHERGEN         = ("Backup_OtherGen")
    BACKUP_SONYGEN          = ("Backup_SonyGen")
    BACKUP_SONYPS3          = ("Backup_SonyPS3")
    BACKUP_SONYPS4          = ("Backup_SonyPS4")
    BACKUP_SONYPSN          = ("Backup_SonyPSN")

# Store types
class StoreType(EnumType):
    AMAZON                  = ("Amazon")
    GOG                     = ("GOG")
    EPIC                    = ("Epic")
    ITCHIO                  = ("Itchio")
    LEGACY                  = ("Legacy")
    STEAM                   = ("Steam")

# Store action types
class StoreActionType(EnumType):
    LOGIN                   = ("Login")
    DISPLAY_PURCHASES       = ("DisplayPurchases")
    IMPORT_PURCHASES        = ("ImportPurchases")
    INSTALL_GAME            = ("InstallGame")
    LAUNCH_GAME             = ("LaunchGame")
    DOWNLOAD_GAME           = ("DownloadGame")
    DOWNLOAD_ASSET          = ("DownloadAsset")
    UPDATE_JSON             = ("UpdateJson")
    UPDATE_METADATA         = ("UpdateMetadata")
    CHECK_VERSIONS          = ("CheckVersions")
    EXPORT_SAVES            = ("ExportSaves")
    IMPORT_SAVES            = ("ImportSaves")

# Store identifier types
class StoreIdentifierType(EnumType):
    INFO                    = ("Info")
    INSTALL                 = ("Install")
    LAUNCH                  = ("Launch")
    DOWNLOAD                = ("Download")
    ASSET                   = ("Asset")
    METADATA                = ("Metadata")

# Playlist types
class PlaylistType(EnumType):
    TREE                    = ("Tree")
    LOCAL                   = ("Local")

# Merge types
class MergeType(EnumType):
    REPLACE                 = ("Replace")
    ADDITIVE                = ("Additive")
    SAFE_REPLACE            = ("SafeReplace")
    SAFE_ADDITIVE           = ("SafeAdditive")

# Web driver types
class WebDriverType(EnumType):
    FIREFOX                 = ("Firefox")
    CHROME                  = ("Chrome")
    BRAVE                   = ("Brave")

# Image types (UPPER)
class ImageType(EnumType):
    JPEG                    = ("JPEG")
    PNG                     = ("PNG")
