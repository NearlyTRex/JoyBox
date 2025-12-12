# Imports
import os
import sys
import enum

# Type enum
class EnumType(enum.Enum):
    def __new__(cls, value, cvalue = None):
        if isinstance(value, EnumType):
            value = value.value
            cvalue = value.cval() if hasattr(value, 'cval') else value
        elif isinstance(value, str):
            cvalue = cvalue if cvalue is not None else value
        elif isinstance(value, tuple):
            value, cvalue = value
        obj = object.__new__(cls)
        obj._value_ = value
        obj.cvalue = cvalue
        return obj

    def __str__(self):
        return self.value

    def __add__(self, other):
        if isinstance(other, str):
            return self.value + other
        return NotImplemented

    def __radd__(self, other):
        if isinstance(other, str):
            return other + self.value
        return NotImplemented

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        if isinstance(other, EnumType):
            return self.val() == other.val()
        if isinstance(other, str):
            return self.val() == other
        return False

    def __lt__(self, other):
        if isinstance(other, EnumType):
            return self.val() < other.val()
        if isinstance(other, str):
            return self.val() < other
        return NotImplemented

    def __le__(self, other):
        if isinstance(other, EnumType):
            return self.val() <= other.val()
        if isinstance(other, str):
            return self.val() <= other
        return NotImplemented

    def __gt__(self, other):
        if isinstance(other, EnumType):
            return self.val() > other.val()
        if isinstance(other, str):
            return self.val() > other
        return NotImplemented

    def __ge__(self, other):
        if isinstance(other, EnumType):
            return self.val() >= other.val()
        if isinstance(other, str):
            return self.val() >= other
        return NotImplemented

    def __contains__(cls, other):
        if isinstance(other, cls):
            return other in cls.members()
        if isinstance(other, EnumType):
            for member in cls.members():
                if member.val() == other.val():
                    return True
        if isinstance(other, str):
            return any(member.val() == other for member in cls.members())
        return False

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
    def is_member(cls, value):
        return isinstance(value, cls)

    @classmethod
    def is_convertible(cls, value):
        if isinstance(value, cls):
            return True
        return value in cls.values()

    @classmethod
    def from_enum(cls, other):
        if isinstance(other, cls):
            return other
        if isinstance(other, EnumType):
            for member in cls.members():
                if member.val() == other.val():
                    return member
        if isinstance(other, str):
            for member in cls.members():
                if member.val() == other:
                    return member
        return None

    @classmethod
    def from_string(cls, value):
        for member in cls:
            if member.value.lower() == value.lower():
                return member
        return None

    @classmethod
    def from_list(cls, values):
        if not values:
            return None
        if isinstance(values, str):
            values = [v.strip() for v in values.split(",")]
        if isinstance(values, list):
            enum_list = []
            for value in values:
                if isinstance(value, str):
                    enum_value = cls.from_string(value)
                    if enum_value:
                        enum_list.append(enum_value)
                elif isinstance(value, cls):
                    enum_list.append(value)
            return enum_list if enum_list else None
        if isinstance(values, cls):
            return [values]
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

    def cval(self):
        return self.cvalue

    def lower(self):
        return self.value.lower()

    def upper(self):
        return self.value.upper()

# Setup parameters class
class SetupParams:
    def __init__(
        self,
        locker_type = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        self.locker_type = locker_type
        self.verbose = verbose
        self.pretend_run = pretend_run
        self.exit_on_failure = exit_on_failure

    @classmethod
    def from_args(cls, args):
        return cls(
            locker_type = getattr(args, 'locker_type', None),
            verbose = getattr(args, 'verbose', False),
            pretend_run = getattr(args, 'pretend_run', False),
            exit_on_failure = getattr(args, 'exit_on_failure', False))

    def to_dict(self):
        return {
            'locker_type': self.locker_type,
            'verbose': self.verbose,
            'pretend_run': self.pretend_run,
            'exit_on_failure': self.exit_on_failure
        }

# Locker types
class LockerType(EnumType):
    ALL                     = ("All")
    HETZNER                 = ("Hetzner")
    GDRIVE                  = ("Gdrive")

# Locker folder types
class LockerFolderType(EnumType):
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

# Cryption types
class CryptionType(EnumType):
    NONE                    = ("None")
    ENCRYPT                 = ("Encrypt")
    DECRYPT                 = ("Decrypt")

# Decompiler action type
class DecompilerActionType(EnumType):
    LAUNCH_PROGRAM          = ("LaunchProgram")
    RUN_HEADLESS            = ("RunHeadless")

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
    IMPORT                  = ("Import")
    EXPORT                  = ("Export")
    IMPORT_SAVE_PATHS       = ("ImportSavePaths")

# Remote types
class RemoteType(EnumType):
    DRIVE                   = ("Drive")
    B2                      = ("B2")
    WEBDAV                  = ("WebDAV")
    SFTP                    = ("SFTP")

# Remote action types
class RemoteActionType(EnumType):
    INIT                    = ("Init")
    DOWNLOAD                = ("Download")
    UPLOAD                  = ("Upload")
    PULL                    = ("Pull")
    PUSH                    = ("Push")
    MERGE                   = ("Merge")
    DIFF                    = ("Diff")
    DIFFSYNC                = ("DiffSync")
    EMPTYRECYCLE            = ("EmptyRecycle")
    LIST                    = ("List")
    MOUNT                   = ("Mount")

# Remote action sync types
class RemoteActionSyncType(EnumType):
    PULL                    = (RemoteActionType.PULL.val())
    PUSH                    = (RemoteActionType.PUSH.val())
    MERGE                   = (RemoteActionType.MERGE.val())

# Remote action change types
class RemoteActionChangeType(EnumType):
    DOWNLOAD                = (RemoteActionType.DOWNLOAD.val())
    UPLOAD                  = (RemoteActionType.UPLOAD.val())
    PULL                    = (RemoteActionType.PULL.val())
    PUSH                    = (RemoteActionType.PUSH.val())
    MERGE                   = (RemoteActionType.MERGE.val())

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
    ISO                     = ("Iso")
    ARCHIVE                 = ("Archive")

# Disc source type
class DiscSourceType(EnumType):
    FOLDER                  = ("Folder")
    ZIP                     = ("Zip")

# Asset types
class AssetType(EnumType):
    BACKGROUND              = ("Background", ".jpg")
    BOXBACK                 = ("BoxBack", ".jpg")
    BOXFRONT                = ("BoxFront", ".jpg")
    LABEL                   = ("Label", ".png")
    SCREENSHOT              = ("Screenshot", ".jpg")
    VIDEO                   = ("Video", ".mp4")

# Asset min types
class AssetMinType(EnumType):
    BOXFRONT                = (AssetType.BOXFRONT.val(), AssetType.BOXFRONT.cval())
    VIDEO                   = (AssetType.VIDEO.val(), AssetType.VIDEO.cval())

# Asset image types
class AssetImageType(EnumType):
    BACKGROUND              = (AssetType.BACKGROUND.val(), AssetType.BACKGROUND.cval())
    BOXBACK                 = (AssetType.BOXBACK.val(), AssetType.BOXBACK.cval())
    BOXFRONT                = (AssetType.BOXFRONT.val(), AssetType.BOXFRONT.cval())
    LABEL                   = (AssetType.LABEL.val(), AssetType.LABEL.cval())
    SCREENSHOT              = (AssetType.SCREENSHOT.val(), AssetType.SCREENSHOT.cval())

# Asset video types
class AssetVideoType(EnumType):
    VIDEO                   = (AssetType.VIDEO.val(), AssetType.VIDEO.cval())

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
    DISC                    = ("Disc")
    GOG                     = ("GOG")
    EPIC                    = ("Epic")
    HUMBLE_BUNDLE           = ("HumbleBundle")
    ITCHIO                  = ("Itchio")
    LEGACY                  = ("Legacy")
    PUPPET_COMBO            = ("PuppetCombo")
    RED_CANDLE              = ("RedCandle")
    SQUARE_ENIX             = ("SquareEnix")
    STEAM                   = ("Steam")
    ZOOM                    = ("Zoom")

# Store identifier types
class StoreIdentifierType(EnumType):
    INFO                    = ("Info")
    INSTALL                 = ("Install")
    LAUNCH                  = ("Launch")
    DOWNLOAD                = ("Download")
    ASSET                   = ("Asset")
    METADATA                = ("Metadata")
    PAGE                    = ("Page")

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

# Size types
class SizeType(EnumType):
    SMALL                   = ("Small")
    MEDIUM                  = ("Medium")
    LARGE                   = ("Large")

# Content delivery network types
class ContentDeliveryNetworkType(EnumType):
    CLOUDFLARE              = ("Cloudflare")
    FASTLY                  = ("Fastly")

# Audio metadata types
class AudioMetadataType(EnumType):
    ARCHIVE                 = ("Archive")
    HASH                    = ("Hash")
    TAG                     = ("Tag")

# Audio metadata action types
class AudioMetadataAction(EnumType):
    TAG                     = ("Tag")
    CLEAR                   = ("Clear")
    APPLY                   = ("Apply")

# Audio conversion action types
class AudioConversionAction(EnumType):
    AAX_TO_M4A              = ("AaxToM4a")

# Audio genre types
class AudioGenreType(EnumType):
    ASMR                    = ("ASMR")
    AUDIOBOOK               = ("Audiobook")
    CLASSICAL               = ("Classical")
    GAME                    = ("Game")
    RADIO                   = ("Radio")
    REGULAR                 = ("Regular")
    SOUNDTRACK              = ("Soundtrack")
    STORY                   = ("Story")
    THERAPY                 = ("Therapy")
