# Imports
import os
import getpass

# Local imports

# Project
PROJECT_NAME = "JoyBox"

# Minimum python version
MINIMUM_PYTHON_MAJOR_VERSION = 3
MINIMUM_PYTHON_MINOR_VERSION = 10
MINIMUM_PYTHON_PATCH_VERSION = 0
minimum_python_version = (
    MINIMUM_PYTHON_MAJOR_VERSION,
    MINIMUM_PYTHON_MINOR_VERSION,
    MINIMUM_PYTHON_PATCH_VERSION
)

# Tokens
TOKEN_ROM_STORAGE_ROOT = "ROM_STORAGE_ROOT"
TOKEN_ROM_JSON_ROOT = "ROM_JSON_ROOT"
TOKEN_TOOL_MAIN_ROOT = "TOOL_MAIN_ROOT"
TOKEN_EMULATOR_MAIN_ROOT = "EMULATOR_MAIN_ROOT"
TOKEN_EMULATOR_SETUP_ROOT = "EMULATOR_SETUP_ROOT"
TOKEN_SETUP_MAIN_ROOT = "SETUP_MAIN_ROOT"
TOKEN_HDD_MAIN_ROOT = "HDD_MAIN_ROOT"
TOKEN_DOS_MAIN_ROOT = "DOS_MAIN_ROOT"
TOKEN_SCUMM_MAIN_ROOT = "SCUMM_MAIN_ROOT"
TOKEN_DISC_MAIN_ROOT = "DISC_MAIN_ROOT"
TOKEN_DISC_UPDATE_ROOT = "DISC_UPDATE_ROOT"
TOKEN_DISC_ZERO_ROOT = "DISC_ZERO_ROOT"
TOKEN_DISC_ONE_ROOT = "DISC_ONE_ROOT"
TOKEN_DISC_TWO_ROOT = "DISC_TWO_ROOT"
TOKEN_DISC_THREE_ROOT = "DISC_THREE_ROOT"
TOKEN_DISC_FOUR_ROOT = "DISC_FOUR_ROOT"
TOKEN_DISC_FIVE_ROOT = "DISC_FIVE_ROOT"
TOKEN_DISC_SIX_ROOT = "DISC_SIX_ROOT"
TOKEN_DISC_SEVEN_ROOT = "DISC_SEVEN_ROOT"
TOKEN_GAME_NAME = "GAME_NAME"
TOKEN_GAME_FILE = "GAME_FILE"
TOKEN_GAME_DIR = "GAME_DIR"
TOKEN_GAME_SAVE_DIR = "GAME_SAVE_DIR"
TOKEN_GAME_INSTALL_DIR = "GAME_INSTALL_DIR"
TOKEN_PYTHON_BIN = "PYTHON_BIN"
TOKEN_USER_REGISTRY_DIR = "USER_REGISTRY_DIR"
TOKEN_USER_PROFILE_DIR = "USER_PROFILE_DIR"
TOKEN_USER_PUBLIC_DIR = "USER_PUBLIC_DIR"
TOKEN_STORE_INSTALL_DIR = "STORE_INSTALL_DIR"
TOKEN_STORE_USER_ID = "STORE_USER_ID"
TOKEN_COMMAND_SPLIT = "@=^=@"
TOKEN_GLOB = "*"
tokens_disc = [
    TOKEN_DISC_MAIN_ROOT,
    TOKEN_DISC_UPDATE_ROOT,
    TOKEN_DISC_ZERO_ROOT,
    TOKEN_DISC_ONE_ROOT,
    TOKEN_DISC_TWO_ROOT,
    TOKEN_DISC_THREE_ROOT,
    TOKEN_DISC_FOUR_ROOT,
    TOKEN_DISC_FIVE_ROOT,
    TOKEN_DISC_SIX_ROOT,
    TOKEN_DISC_SEVEN_ROOT
]
token_disc_names = {
    TOKEN_DISC_ZERO_ROOT: "Disc 0",
    TOKEN_DISC_ONE_ROOT: "Disc 1",
    TOKEN_DISC_TWO_ROOT: "Disc 2",
    TOKEN_DISC_THREE_ROOT: "Disc 3",
    TOKEN_DISC_FOUR_ROOT: "Disc 4",
    TOKEN_DISC_FIVE_ROOT: "Disc 5",
    TOKEN_DISC_SIX_ROOT: "Disc 6",
    TOKEN_DISC_SEVEN_ROOT: "Disc 7",
    TOKEN_DISC_UPDATE_ROOT: "Update"
}

# Separators
OS_CURDIR = os.sep
OS_PARDIR = os.pardir
OS_SEP = os.sep
OS_PATHSEP = "/"
OS_ENVPATHSEP = os.pathsep

# Drive roots
DRIVE_ROOT_WINDOWS = "C:\\"
DRIVE_ROOT_POSIX = "/"

# Mime types
mime_types_zip = ["application/zip"]
mime_types_7z = ["application/x-7z-compressed"]
mime_types_rar = ["application/x-rar-compressed"]
mime_types_lzh = ["application/x-lzh-compressed", "application/x-lha"]
mime_types_stuffit = ["application/x-stuffit", "application/x-sit"]
mime_types_tarball = ["application/x-gzip", "application/gzip"]
mime_types_disc = ["application/x-iso9660-image"]
mime_types_exe = ["application/x-dosexec"]
mime_types_appimage = ["application/x-executable"]

# Folders
GENERAL_FOLDER_NUMERIC = "#-0"
COMPUTER_FOLDER_DOS = "MS-DOS"
COMPUTER_FOLDER_SCUMM = "Scumm"
COMPUTER_FOLDER_APPDATA = "AppData"
COMPUTER_FOLDER_CONTACTS = "Contacts"
COMPUTER_FOLDER_DESKTOP = "Desktop"
COMPUTER_FOLDER_DOCUMENTS = "Documents"
COMPUTER_FOLDER_DOWNLOADS = "Downloads"
COMPUTER_FOLDER_FAVORITES = "Favorites"
COMPUTER_FOLDER_GAMEDATA = "GameData"
COMPUTER_FOLDER_LINKS = "Links"
COMPUTER_FOLDER_MUSIC = "Music"
COMPUTER_FOLDER_PICTURES = "Pictures"
COMPUTER_FOLDER_PUBLIC = "Public"
COMPUTER_FOLDER_REGISTRY = "Registry"
COMPUTER_FOLDER_SAVEDGAMES = "Saved Games"
COMPUTER_FOLDER_SEARCHES = "Searches"
COMPUTER_FOLDER_STORE = "Store"
COMPUTER_FOLDER_TEMP = "Temp"
COMPUTER_FOLDER_VIDEOS = "Videos"
computer_user_folders = [
    COMPUTER_FOLDER_APPDATA,
    COMPUTER_FOLDER_CONTACTS,
    COMPUTER_FOLDER_DESKTOP,
    COMPUTER_FOLDER_DOCUMENTS,
    COMPUTER_FOLDER_DOWNLOADS,
    COMPUTER_FOLDER_FAVORITES,
    COMPUTER_FOLDER_GAMEDATA,
    COMPUTER_FOLDER_LINKS,
    COMPUTER_FOLDER_MUSIC,
    COMPUTER_FOLDER_PICTURES,
    COMPUTER_FOLDER_PUBLIC,
    COMPUTER_FOLDER_REGISTRY,
    COMPUTER_FOLDER_SAVEDGAMES,
    COMPUTER_FOLDER_SEARCHES,
    COMPUTER_FOLDER_STORE,
    COMPUTER_FOLDER_TEMP,
    COMPUTER_FOLDER_VIDEOS
]

# Drives
DRIVE_PREFIX_CWD = "b"
DRIVE_AVAILABLE_START = "d"
DRIVE_AVAILABLE_END = "y"
drives_special = [
    DRIVE_PREFIX_CWD,
    "c",
    "z"
]
drives_regular = []
for code in range(ord(DRIVE_AVAILABLE_START), ord(DRIVE_AVAILABLE_END)):
    drives_regular.append(chr(code))

# Raw files index
RAW_FILES_INDEX = "raw_files.index"

# Default buildid
DEFAULT_BUILDID = "1.0"

# File sizes
BYTES_PER_KILOBYTE = 1024
BYTES_PER_MEGABYTE = BYTES_PER_KILOBYTE * 1024
BYTES_PER_GIGABYTE = BYTES_PER_MEGABYTE * 1024
MAX_DISC_DATA_SIZE_25GB = 22 * BYTES_PER_GIGABYTE
MAX_DISC_DATA_SIZE_50GB = 44 * BYTES_PER_GIGABYTE
MAX_DISC_DATA_SIZE_100GB = 88 * BYTES_PER_GIGABYTE

# Buffer sizes
HASH_CHUNK_SIZE = 64 * 1024 * 1024
TRANSFER_CHUNK_SIZE = 4096 * 1024

# Asset sizes
ASSET_BOXFRONT_WIDTH = 600
ASSET_BOXFRONT_HEIGHT = 900
asset_boxfront_dimensions = (ASSET_BOXFRONT_WIDTH, ASSET_BOXFRONT_HEIGHT)

# Cookie paths
COOKIE_SUFFIX_PATH = ".cookie.json"

# Ignored install paths
ignored_paths_install = [
    "ProgramData/Microsoft",
    "Program Files (x86)/Common Files",
    "Program Files (x86)/InstallShield Installation Information",
    "Program Files (x86)/Internet Explorer",
    "Program Files (x86)/Windows Media Player",
    "Program Files (x86)/Windows NT",
    "Program Files/Common Files",
    "Program Files/InstallShield Installation Information",
    "Program Files/Internet Explorer",
    "Program Files/Windows Media Player",
    "Program Files/Windows NT",
    "users",
    "windows",
    getpass.getuser()
]

# Registry
REGISTRY_FILENAME_SETUP = "setup.reg"
REGISTRY_FILENAME_GAME = "game.reg"
REGISTRY_FILENAME_USER = "user.reg"
registry_export_keys_setup = [
    "HKCU\\Software",
    "HKLM\\Software"
]
registry_export_keys_game = [
    "HKCU\\Software"
]
ignored_registry_keys_setup = [
    "HKEY_CURRENT_USER\\Software\\Microsoft",
    "HKEY_CURRENT_USER\\Software\\Wine",
    "HKEY_LOCAL_MACHINE\\Software\\Classes",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft"
]
ignored_registry_keys_game = [
    "HKEY_CURRENT_USER\\Software\\Microsoft",
    "HKEY_CURRENT_USER\\Software\\Wine"
]

# AppData
appdata_variants = {
    "/AppData/Local/": [
        "/Application Data/",
        "/Local Settings/Application Data/"
    ],
    "/AppData/Roaming/": [
        "/Application Data/",
        "/Local Settings/Application Data/"
    ]
}

# Flippable words
flippable_words = [
    "The",
    "A",
    "An"
]

# Filler words
filler_words = [
    "a",
    "and",
    "at",
    "as",
    "by",
    "for",
    "from",
    "in",
    "into",
    "is",
    "of",
    "on",
    "onto",
    "the",
    "to",
    "with"
]

# Rich text replacements
rich_text_replacements = {
    "“": "\"",
    "”": "\"",
    "＂": "\"",
    "’": "'",
    "ʻ": "'",
    "‘": "'",
    "…": "...",
    "•": "*",
    "·": "-",
    "—": "-",
    "–": "-",
    "？": "?",
    "｜": "|",
    "\\x7e": "~"
}

# Web text replacements
web_text_replacements = {
    "<span>": " ",
    "</span>": " ",
    "&lt;": " ",
    "&gt;": " ",
    "&quot;": " ",
    "&amp;": " ",
    "amp;": " ",
    "()": ""
}

# Path text replacements
path_text_replacements = {
    "<": "",
    ">": "",
    ":": "",
    "\"": "",
    "/": "",
    "\\": "",
    "|": "",
    "?": "",
    "*": ""
}
