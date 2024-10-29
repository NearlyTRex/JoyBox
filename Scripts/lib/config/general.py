# Imports
import os
import sys
import getpass

# Project
project_name = "JoyBox"

# Minimum python version
minimum_python_major_version = 3
minimum_python_minor_version = 10
minimum_python_patch_version = 0
minimum_python_version = (
    minimum_python_major_version,
    minimum_python_minor_version,
    minimum_python_patch_version
)

# Tokens
token_rom_storage_root = "ROM_STORAGE_ROOT"
token_rom_json_root = "ROM_JSON_ROOT"
token_tool_main_root = "TOOL_MAIN_ROOT"
token_emulator_main_root = "EMULATOR_MAIN_ROOT"
token_emulator_setup_root = "EMULATOR_SETUP_ROOT"
token_setup_main_root = "SETUP_MAIN_ROOT"
token_hdd_main_root = "HDD_MAIN_ROOT"
token_dos_main_root = "DOS_MAIN_ROOT"
token_scumm_main_root = "SCUMM_MAIN_ROOT"
token_disc_main_root = "DISC_MAIN_ROOT"
token_disc_update_root = "DISC_UPDATE_ROOT"
token_disc_zero_root = "DISC_ZERO_ROOT"
token_disc_one_root = "DISC_ONE_ROOT"
token_disc_two_root = "DISC_TWO_ROOT"
token_disc_three_root = "DISC_THREE_ROOT"
token_disc_four_root = "DISC_FOUR_ROOT"
token_disc_five_root = "DISC_FIVE_ROOT"
token_disc_six_root = "DISC_SIX_ROOT"
token_disc_seven_root = "DISC_SEVEN_ROOT"
token_game_name = "GAME_NAME"
token_game_file = "GAME_FILE"
token_game_dir = "GAME_DIR"
token_game_save_dir = "GAME_SAVE_DIR"
token_python_bin = "PYTHON_BIN"
token_user_registry_dir = "USER_REGISTRY_DIR"
token_user_profile_dir = "USER_PROFILE_DIR"
token_user_public_dir = "USER_PUBLIC_DIR"
token_store_install_dir = "STORE_INSTALL_DIR"
token_store_user_id = "STORE_USER_ID"
token_command_split = "@=^=@"
token_glob = "*"
tokens_disc = [
    token_disc_main_root,
    token_disc_update_root,
    token_disc_zero_root,
    token_disc_one_root,
    token_disc_two_root,
    token_disc_three_root,
    token_disc_four_root,
    token_disc_five_root,
    token_disc_six_root,
    token_disc_seven_root
]
token_disc_names = {
    token_disc_zero_root: "Disc 0",
    token_disc_one_root: "Disc 1",
    token_disc_two_root: "Disc 2",
    token_disc_three_root: "Disc 3",
    token_disc_four_root: "Disc 4",
    token_disc_five_root: "Disc 5",
    token_disc_six_root: "Disc 6",
    token_disc_seven_root: "Disc 7",
    token_disc_update_root: "Update"
}

# Separators
os_curdir = os.sep
os_pardir = os.pardir
os_sep = os.sep
os_pathsep = "/"
os_envpathsep = os.pathsep

# Drive roots
drive_root_windows = "C:\\"
drive_root_posix = "/"

# Extensions
encrypted_file_extension = ".enc"
computer_program_extensions = [".exe", ".lnk", ".bat"]
computer_archive_extensions_zip = [".zip", ".install"]
computer_archive_extensions_7z = [".7z"]
computer_archive_extensions_rar = [".rar"]
computer_archive_extensions_tarball = [
    ".tar.bz2", ".tb2", ".tbz", ".tbz2", ".tz2",    # bzip2
    ".tar.gz", ".taz", ".tgz",                      # gzip
    ".tar.lz",                                      # lzip
    ".tar.lzma", ".tlz",                            # lzma
    ".tar.lzo",                                     # lzop
    ".tar.xz", ".txz",                              # xz
    ".tar.Z", ".tZ,", ".taZ",                       # compress
    ".tar.zst", ".tzst"                             # zstd
]
computer_archive_extensions_exe = [".exe"]
computer_archive_extensions_appimage = [".AppImage"]
computer_archive_extensions = []
computer_archive_extensions += computer_archive_extensions_zip
computer_archive_extensions += computer_archive_extensions_7z
computer_archive_extensions += computer_archive_extensions_rar
computer_archive_extensions += computer_archive_extensions_tarball
computer_archive_extensions += computer_archive_extensions_exe
computer_archive_extensions += computer_archive_extensions_appimage
wiiu_encrypted_extensions = [".app", ".h3", ".tik", ".tmd", ".cert"]

# Folders
general_folder_numeric = "#-0"
computer_folder_dos = "MS-DOS"
computer_folder_scumm = "Scumm"
computer_folder_appdata = "AppData"
computer_folder_contacts = "Contacts"
computer_folder_desktop = "Desktop"
computer_folder_documents = "Documents"
computer_folder_downloads = "Downloads"
computer_folder_favorites = "Favorites"
computer_folder_gamedata = "GameData"
computer_folder_links = "Links"
computer_folder_music = "Music"
computer_folder_pictures = "Pictures"
computer_folder_public = "Public"
computer_folder_registry = "Registry"
computer_folder_savedgames = "Saved Games"
computer_folder_searches = "Searches"
computer_folder_store = "Store"
computer_folder_temp = "Temp"
computer_folder_videos = "Videos"
computer_user_folders = [
    computer_folder_appdata,
    computer_folder_contacts,
    computer_folder_desktop,
    computer_folder_documents,
    computer_folder_downloads,
    computer_folder_favorites,
    computer_folder_gamedata,
    computer_folder_links,
    computer_folder_music,
    computer_folder_pictures,
    computer_folder_public,
    computer_folder_registry,
    computer_folder_savedgames,
    computer_folder_searches,
    computer_folder_store,
    computer_folder_temp,
    computer_folder_videos
]

# Drives
drive_prefix_cwd = "b"
drive_available_start = "d"
drive_available_end = "y"
drives_special = [
    drive_prefix_cwd,
    "c",
    "z"
]
drives_regular = []
for code in range(ord(drive_available_start), ord(drive_available_end)):
    drives_regular.append(chr(code))

# Raw files index
raw_files_index = "raw_files.index"

# File sizes
bytes_per_kilobyte = 1024
bytes_per_megabyte = bytes_per_kilobyte * 1024
bytes_per_gigabyte = bytes_per_megabyte * 1024
max_disc_data_size_25gb = 22 * bytes_per_gigabyte
max_disc_data_size_50gb = 44 * bytes_per_gigabyte
max_disc_data_size_100gb = 88 * bytes_per_gigabyte

# Buffer sizes
hash_chunk_size = 2 ** 32
transfer_chunk_size = 4096 * 1024

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
registry_filename_setup = "setup.reg"
registry_filename_game = "game.reg"
registry_filename_user = "user.reg"
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
