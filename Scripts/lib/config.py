# Imports
import os
import sys
import getpass
import collections
import configprivate

############# Project #############
project_name = "JoyBox"

############# Defaults #############

# Default drive roots
default_drive_root_windows = "C:\\"
default_drive_root_posix = "/"
default_drive_root_wine = "drive_c"

# Default network share info
default_network_share_base_location = configprivate.nas_base_location
default_network_share_storage_folder = configprivate.nas_storage_folder
default_network_share_cache_folder = configprivate.nas_cache_folder
default_network_share_username = configprivate.nas_account
default_network_share_password = configprivate.nas_password

# Default setup locations
default_user_dir = os.path.expanduser("~")
default_local_cache_dir_windows = os.path.join(default_user_dir, "Cache")
default_local_cache_dir_linux = os.path.join(default_user_dir, "Cache")
default_remote_cache_dir_windows = "Y:\\"
default_remote_cache_dir_linux = os.path.join(default_drive_root_posix, "mnt", "Cache")
default_sync_dir_windows = os.path.join(default_user_dir, "Sync")
default_sync_dir_linux = os.path.join(default_user_dir, "Sync")
default_repositories_dir_windows = os.path.join(default_drive_root_windows, "Repositories")
default_repositories_dir_linux = os.path.join(default_user_dir, "Repositories")
default_storage_dir_windows = "X:\\"
default_storage_dir_linux = os.path.join(default_drive_root_posix, "mnt", "Storage")
default_login_script = os.path.join(default_user_dir, ".bashrc")
default_environment_script = os.path.join(default_user_dir, ".environment")

# Default Python install
default_python_exe = "python"
default_python3_exe = "python3"
default_python_pip_exe = "pip"
default_python3_pip_exe = "pip3"
default_python_install_dirs = [
    os.path.join(default_drive_root_windows, "Python311"),
    os.path.join(default_drive_root_posix, "usr", "bin")
]
default_python_venv_dir = os.path.join(default_user_dir, ".venv")

# Default Wine install
default_wine_exe = "wine"
default_wine_boot_exe = "wineboot"
default_wine_server_exe = "wineserver"
default_wine_tricks_exe = "winetricks"
default_wine_install_dirs = [
    os.path.join(default_drive_root_posix, "usr", "bin")
]
default_wine_sandbox_dir = os.path.join(default_user_dir, "Sandbox")

# Default Sandboxie install
default_sandboxie_exe = "Start"
default_sandboxie_ini_exe = "SbieIni"
default_sandboxie_rpcss_exe = "SandboxieRpcSs"
default_sandboxie_dcomlaunch_exe = "SandboxieDcomLaunch"
default_sandboxie_install_dirs = [
    os.path.join(default_drive_root_windows, "Program Files", "Sandboxie-Plus")
]
default_sandboxie_sandbox_dir = os.path.join(default_drive_root_windows, "Sandbox", getpass.getuser())

# Default Firefox install
default_firefox_exe = "firefox"
default_firefox_install_dirs = [
    os.path.join(default_drive_root_windows, "Program Files", "Mozilla Firefox"),
    os.path.join(default_drive_root_posix, "usr", "bin"),
    os.path.join(default_drive_root_posix, "snap", "bin")
]

# Default 7-Zip install
default_7zip_exe = "7z"
default_7zip_standalone_exe = "7za"
default_7zip_install_dirs = [
    os.path.join(default_drive_root_windows, "Program Files", "7-Zip"),
    os.path.join(default_drive_root_posix, "usr", "bin")
]

# Default XorrISO install
default_xorriso_exe = "xorriso"
default_xorriso_install_dirs = [
    os.path.join(default_drive_root_windows, "cygwin64", "bin"),
    os.path.join(default_drive_root_posix, "usr", "bin")
]

# Default MameTools install
default_mame_chdman_exe = "chdman"
default_mame_chdman_install_dirs = [
    os.path.join(default_drive_root_posix, "usr", "bin")
]

# Default system tools
default_wget_exe = "wget"
default_curl_exe = "curl"
default_file_exe = "file"
default_reg_exe = "reg"
default_xrandr_exe = "xrandr"
default_system_tools_names_windows = [
    default_curl_exe,
    default_file_exe,
    default_reg_exe
]
default_system_tools_names_linux = [
    default_wget_exe,
    default_curl_exe,
    default_file_exe,
    default_xrandr_exe
]
default_system_tools_dirs = [
    os.path.join(default_drive_root_windows, "Windows", "System32"),
    os.path.join(default_drive_root_windows, "cygwin64", "bin"),
    os.path.join(default_drive_root_posix, "usr", "bin")
]

# Default resolution
default_screen_resolution_w = 1920
default_screen_resolution_h = 1080
default_screen_resolution_c = 32

# Default flags
default_flag_verbose = True
default_flag_exit_on_failure = True
default_flag_fullscreen = True
default_flag_keep_setup_files = False

# Default options
default_option_winver = ""
default_hash_chunk_size = 2 ** 32

# Default capture
default_capture_duration = 300
default_capture_interval = 1
default_capture_origin = (0, 0)
default_capture_resolution_w = default_screen_resolution_w
default_capture_resolution_h = default_screen_resolution_h
default_capture_resolution = (default_capture_resolution_w, default_capture_resolution_h)
default_capture_framerate = 30

# Steam options
default_steam_username = configprivate.steam_username
default_steam_userid = configprivate.steam_userid

############# Other Config #############

# Units
unit_type_seconds = "seconds"
unit_type_minutes = "minutes"
unit_type_hours = "hours"

# Environment variables
environment_path = "PATH"
environment_local_cache_root_dir = "JB_LOCAL_CACHE_ROOT_DIR"
environment_remote_cache_root_dir = "JB_REMOTE_CACHE_ROOT_DIR"
environment_sync_root_dir = "JB_SYNC_ROOT_DIR"
environment_repositories_root_dir = "JB_REPOSITORIES_ROOT_DIR"
environment_storage_root_dir = "JB_STORAGE_ROOT_DIR"
environment_network_share_base_location = "JB_NETWORK_SHARE_BASE_LOCATION"
environment_network_share_storage_folder = "JB_NETWORK_SHARE_STORAGE_FOLDER"
environment_network_share_cache_folder = "JB_NETWORK_SHARE_CACHE_FOLDER"
environment_network_share_username = "JB_NETWORK_SHARE_USERNAME"
environment_network_share_password = "JB_NETWORK_SHARE_PASSWORD"
environment_launchrom_program = "JB_LAUNCHROM_PROGRAM"
environment_vars = [
    environment_local_cache_root_dir,
    environment_remote_cache_root_dir,
    environment_sync_root_dir,
    environment_repositories_root_dir,
    environment_storage_root_dir,
    environment_network_share_base_location,
    environment_network_share_storage_folder,
    environment_network_share_cache_folder,
    environment_network_share_username,
    environment_network_share_password,
    environment_launchrom_program
]

# Tokens
token_rom_storage_root = "$ROM_STORAGE_ROOT"
token_rom_json_root = "$ROM_JSON_ROOT"
token_tool_main_root = "$TOOL_MAIN_ROOT"
token_emulator_main_root = "$EMULATOR_MAIN_ROOT"
token_setup_main_root = "$SETUP_MAIN_ROOT"
token_hdd_main_root = "$HDD_MAIN_ROOT"
token_dos_main_root = "$DOS_MAIN_ROOT"
token_scumm_main_root = "$SCUMM_MAIN_ROOT"
token_disc_main_root = "$DISC_MAIN_ROOT"
token_disc_zero_root = "$DISC_ZERO_ROOT"
token_disc_one_root = "$DISC_ONE_ROOT"
token_disc_two_root = "$DISC_TWO_ROOT"
token_disc_three_root = "$DISC_THREE_ROOT"
token_disc_four_root = "$DISC_FOUR_ROOT"
token_disc_five_root = "$DISC_FIVE_ROOT"
token_disc_six_root = "$DISC_SIX_ROOT"
token_disc_seven_root = "$DISC_SEVEN_ROOT"
token_game_name = "$GAME_NAME"
token_game_file = "$GAME_FILE"
token_game_dir = "$GAME_DIR"
token_game_save_dir = "$GAME_SAVE_DIR"
token_command_split = "@=^=@"
token_glob = "*"
tokens_disc = [
    token_disc_zero_root,
    token_disc_one_root,
    token_disc_two_root,
    token_disc_three_root,
    token_disc_four_root,
    token_disc_five_root,
    token_disc_six_root,
    token_disc_seven_root,
    token_disc_main_root
]
token_disc_names = {
    token_disc_zero_root: "Disc 0",
    token_disc_one_root: "Disc 1",
    token_disc_two_root: "Disc 2",
    token_disc_three_root: "Disc 3",
    token_disc_four_root: "Disc 4",
    token_disc_five_root: "Disc 5",
    token_disc_six_root: "Disc 6",
    token_disc_seven_root: "Disc 7"
}

# Prefixes
prefix_name_default = "Default"
prefix_name_tool = "Tool"
prefix_name_emulator = "Emulator"
prefix_name_game = "Game"
prefix_name_setup = "Setup"

# Separators
os_curdir = os.sep
os_pardir = os.pardir
os_sep = os.sep
os_pathsep = "/"
os_envpathsep = os.pathsep

# Extensions
computer_program_extensions = [".exe", ".lnk", ".bat"]
computer_archive_extensions_regular = [".zip", ".7z", ".rar"]
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
computer_archive_extensions = computer_archive_extensions_regular + computer_archive_extensions_tarball
wiiu_encrypted_extensions = [".app", ".h3", ".tik", ".tmd", ".cert"]

# Folders
general_numeric_folder = "#-0"
computer_dos_folder = "MS-DOS"
computer_scumm_folder = "Scumm"
computer_registry_folder = "Registry"
computer_game_data_folder = "GameData"
computer_appdata_folder = "AppData"
computer_temp_folder = "Temp"
computer_user_folders_builtin = [
    "AppData",
    "Contacts",
    "Desktop",
    "Documents",
    "Downloads",
    "Favorites",
    "Links",
    "Music",
    "Pictures",
    "Saved Games",
    "Searches",
    "Temp",
    "Videos"
]
computer_user_folders = computer_user_folders_builtin + [computer_game_data_folder]

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

# Save formats
save_format_general = "General"
save_format_wine = "Wine"
save_format_sandboxie = "Sandboxie"

# Capture types
capture_type_none = "none"
capture_type_screenshot = "screenshot"
capture_type_video = "video"

# Disc types
disc_type_normal = "normal"
disc_type_macwin = "macwin"

# Asset types
asset_type_background = "Background"
asset_type_boxback = "BoxBack"
asset_type_boxfront = "BoxFront"
asset_type_label = "Label"
asset_type_screenshot = "Screenshot"
asset_type_video = "Video"
asset_types_all = [
    asset_type_background,
    asset_type_boxback,
    asset_type_boxfront,
    asset_type_label,
    asset_type_screenshot,
    asset_type_video
]
asset_types_min = [
    asset_type_background,
    asset_type_boxback,
    asset_type_boxfront,
    asset_type_screenshot
]
asset_type_extensions = {
    asset_type_background: ".jpg",
    asset_type_boxback: ".jpg",
    asset_type_boxfront: ".jpg",
    asset_type_label: ".png",
    asset_type_screenshot: ".jpg",
    asset_type_video: ".mp4",
}

# Message types
message_type_general = "general"
message_type_ok = "ok"
message_type_yes_no = "yesno"
message_type_cancel = "cancel"
message_type_ok_cancel = "ok_cancel"
message_type_error = "error"
message_type_auto_close = "auto_close"
message_type_get_text = "get_text"
message_type_get_file = "get_file"
message_type_get_folder = "get_folder"

# Installer formats
installer_format_inno = "inno"
installer_format_nsis = "nsis"
installer_format_ins = "installshield"
installer_format_7zip = "7zip"
installer_format_winrar = "winrar"
installer_format_unknown = "unknown"

# Raw files index
raw_files_index = "raw_files.index"

# File sizes
bytes_per_kilobyte = 1024
bytes_per_megabyte = bytes_per_kilobyte * 1024
bytes_per_gigabyte = bytes_per_megabyte * 1024
max_disc_data_size_25gb = 22 * bytes_per_gigabyte
max_disc_data_size_50gb = 44 * bytes_per_gigabyte
max_disc_data_size_100gb = 88 * bytes_per_gigabyte

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

############# Python Config #############

# Minimum python version
minimum_python_major_version = 3
minimum_python_minor_version = 10
minimum_python_patch_version = 0
minimum_python_version = (minimum_python_major_version, minimum_python_minor_version, minimum_python_patch_version)

# Required python modules
required_python_modules_linux = []
required_python_modules_windows = [
    "pywin32",
    "pyuac"
]
required_python_modules_all = [
    "pip",
    "wheel",
    "psutil",
    "selenium",
    "requests",
    "pathlib",
    "PySimpleGUI",
    "Pillow",
    "pyautogui",
    "bs4",
    "lxml",
    "mergedeep",
    "fuzzywuzzy",
    "dictdiffer",
    "termcolor",
    "pycryptodome",
    "pycryptodomex",
    "cryptography",
    "aenum",
    "fastxor",
    "packaging",
    "ecdsa",
    "make_playlist",
    "schedule",
    "python-dateutil",
    "xxhash"
]

############# Packages Config #############

# Required system packages
required_system_packages_windows = []
required_system_packages_linux = [

    # Building
    "autoconf",
    "automake",
    "build-essential",
    "clang",
    "cmake",
    "extra-cmake-modules",
    "g++",
    "gcc",
    "libtool-bin",
    "lld",
    "make",
    "nasm",
    "ninja-build",
    "pkg-config",
    "xa65",

    # Tools
    "bison",
    "dos2unix",
    "ffmpeg",
    "flex",
    "gettext",
    "git",
    "zip",

    # GTK
    "libcanberra-gtk-module",
    "libgtk-3-dev",
    "libgtk2.0-dev",

    # SDL
    "libsdl-net1.2-dev",
    "libsdl2-dev",
    "libsdl2-0.0",
    "libsdl2-net-dev",
    "libsdl2-ttf-dev",

    # SFML
    "libsfml-dev",

    # Qt5
    "libqt5gamepad5-dev",
    "libqt5multimedia5-plugins",
    "libqt5opengl5-dev",
    "libqt5svg5-dev",
    "qt5-qmake",
    "qtbase5-dev-tools",
    "qtbase5-dev",
    "qtbase5-private-dev",
    "qtdeclarative5-dev",
    "qtmultimedia5-dev",
    "qttools5-dev-tools",

    # Qt6
    "libqt6opengl6-dev",
    "libqt6svg6-dev",
    "qmake6",
    "qt6-base-dev-tools",
    "qt6-base-dev",
    "qt6-base-private-dev",
    "qt6-l10n-tools",
    "qt6-multimedia-dev",
    "qt6-tools-dev-tools",
    "qt6-tools-dev",

    # Qt
    "qml-module-qtgraphicaleffects",
    "qml-module-qtmultimedia",
    "qtchooser",

    # OpenGL
    "glslang-dev",
    "glslang-tools",
    "libepoxy-dev",
    "libgl-dev",
    "libgl1-mesa-dev",
    "libglew-dev",

    # Python
    "python3-tk",
    "python3-yaml",

    # Security
    "ca-certificates",
    "libmbedtls-dev",
    "libssl-dev",
    "openssl",

    # Compression
    "libarchive-dev",
    "libbz2-dev",
    "liblzo2-dev",
    "libzstd-dev",
    "zlib1g-dev",

    # Audiovisual
    "jackd",
    "libasound-dev",
    "libasound2-dev",
    "libavcodec-dev",
    "libavcodec-extra",
    "libavdevice-dev",
    "libavformat-dev",
    "libavutil-dev",
    "libfdk-aac-dev",
    "libflac-dev",
    "libfontconfig-dev",
    "libfreetype-dev",
    "libfreetype6-dev",
    "libjpeg-dev",
    "libmpeg2-4-dev",
    "libncurses-dev",
    "libopenal-dev",
    "libpangocairo-1.0-0",
    "libpipewire-0.3-dev",
    "libpixman-1-dev",
    "libpng-dev",
    "libpulse-dev",
    "libsamplerate0-dev",
    "libsndio-dev",
    "libswscale-dev",
    "libtheora-dev",
    "libvorbis-dev",
    "libx11-dev",
    "libxext-dev",
    "libxrandr-dev",
    "xorg-dev",

    # Input
    "libbluetooth-dev",
    "libevdev-dev",
    "libhidapi-dev",
    "libsystemd-dev",
    "libudev-dev",
    "libusb-1.0-0-dev",
    "libxi-dev",
    "libxkbfile-dev",
    "libxtst-dev",

    # Networking
    "bridge-utils",
    "libcurl4-openssl-dev",
    "libminiupnpc-dev",
    "libpcap-dev",
    "libslirp-dev",

    # Virtual machines
    "libvirt-clients",
    "libvirt-daemon-system",
    "ovmf",
    "qemu-kvm",
    "qemu-utils",
    "virt-manager",
    "virtualbox",

    # Utility
    "libglib2.0-dev",
    "libpugixml-dev",
    "xdg-desktop-portal"
]
required_system_packages_all = []

############# Categories Config #############

# Categories
game_supercategory_roms = "Roms"
game_supercategory_dlc = "DLC"
game_supercategory_updates = "Updates"
game_supercategory_saves = "Saves"
game_supercategory_setup = "Setup"
game_supercategory_installs = "Installs"
game_supercategories = [
    game_supercategory_roms,
    game_supercategory_dlc,
    game_supercategory_updates,
    game_supercategory_saves,
    game_supercategory_setup,
    game_supercategory_installs
]
game_category_computer = "Computer"
game_category_microsoft = "Microsoft"
game_category_nintendo = "Nintendo"
game_category_sony = "Sony"
game_category_other = "Other"
game_subcategory_disc = "Disc"
game_platforms = {
    "Computer": [
        "Amazon Games",
        "Disc",
        "Epic Games",
        "GOG",
        "Humble Bundle",
        "Itchio",
        "Puppet Combo",
        "Red Candle",
        "Square Enix",
        "Steam",
        "Zoom"
    ],
    "Microsoft": [
        "Microsoft MSX",
        "Microsoft Xbox",
        "Microsoft Xbox 360",
        "Microsoft Xbox 360 GOD",
        "Microsoft Xbox 360 XBLA",
        "Microsoft Xbox 360 XIG",
        "Microsoft Xbox One",
        "Microsoft Xbox One GOD"
    ],
    "Nintendo": [
        "Nintendo 3DS",
        "Nintendo 3DS Apps",
        "Nintendo 3DS eShop",
        "Nintendo 64",
        "Nintendo DS",
        "Nintendo DSi",
        "Nintendo Famicom",
        "Nintendo Game Boy",
        "Nintendo Game Boy Advance",
        "Nintendo Game Boy Advance e-Reader",
        "Nintendo Game Boy Color",
        "Nintendo Gamecube",
        "Nintendo NES",
        "Nintendo SNES",
        "Nintendo Super Famicom",
        "Nintendo Super Game Boy",
        "Nintendo Super Game Boy Color",
        "Nintendo Switch",
        "Nintendo Switch eShop",
        "Nintendo Virtual Boy",
        "Nintendo Wii",
        "Nintendo Wii U",
        "Nintendo Wii U eShop"
    ],
    "Other": [
        "Apple iOS",
        "Apple MacOS 8",
        "Arcade",
        "Atari 800",
        "Atari 2600",
        "Atari 5200",
        "Atari 7800",
        "Atari Jaguar",
        "Atari Jaguar CD",
        "Atari Lynx",
        "Bandai WonderSwan",
        "Bandai WonderSwan Color",
        "Coleco ColecoVision",
        "Commodore 64",
        "Commodore Amiga",
        "Google Android",
        "Magnavox Odyssey 2",
        "Mattel Intellivision",
        "NEC SuperGrafx",
        "NEC TurboGrafx CD & PC-Engine CD",
        "NEC TurboGrafx-16 & PC-Engine",
        "Nokia N-Gage",
        "Panasonic 3DO",
        "Philips CDi",
        "SNK Neo Geo Pocket Color",
        "Sega 32X",
        "Sega CD",
        "Sega CD 32X",
        "Sega Dreamcast",
        "Sega Game Gear",
        "Sega Genesis",
        "Sega Master System",
        "Sega Saturn",
        "Sinclair ZX Spectrum",
        "Texas Instruments TI-99-4A",
        "Tiger Game.com"
    ],
    "Sony": [
        "Sony PlayStation",
        "Sony PlayStation 2",
        "Sony PlayStation 3",
        "Sony PlayStation 4",
        "Sony PlayStation Network - PlayStation 3",
        "Sony PlayStation Network - PlayStation 4",
        "Sony PlayStation Network - PlayStation Portable",
        "Sony PlayStation Network - PlayStation Portable Minis",
        "Sony PlayStation Network - PlayStation Vita",
        "Sony PlayStation Portable",
        "Sony PlayStation Portable Video",
        "Sony PlayStation Vita"
    ]
}

############# Launcher Config #############

# No launcher
no_launcher_platforms = [

    # Microsoft
    "Microsoft Xbox One GOD",
    "Microsoft Xbox One",

    # Other
    "Apple iOS",
    "Google Android",

    # Sony
    "Sony PlayStation 4",
    "Sony PlayStation Network - PlayStation 4",
    "Sony PlayStation Portable Video"
]

############# Json Config #############

json_launch_name_platforms = [

    # Other
    "Arcade",
    "Nokia N-Gage",

    # Sony
    "Sony PlayStation Network - PlayStation Vita",
    "Sony PlayStation Vita"
]

############# Addon Config #############

addon_platform_mapping = {

    # Microsoft
    "Microsoft Xbox 360": {
        "dlc": True,
        "updates": True
    },
    "Microsoft Xbox 360 GOD": {
        "dlc": True,
        "updates": True
    },
    "Microsoft Xbox 360 XBLA": {
        "dlc": True,
        "updates": True
    },

    # Nintendo
    "Nintendo 3DS": {
        "dlc": True,
        "updates": True
    },
    "Nintendo 3DS eShop": {
        "dlc": True,
        "updates": True
    },
    "Nintendo Switch": {
        "dlc": True,
        "updates": True
    },
    "Nintendo Switch eShop": {
        "dlc": True,
        "updates": True
    },
    "Nintendo Wii": {
        "dlc": True
    },
    "Nintendo Wii U": {
        "dlc": True,
        "updates": True
    },
    "Nintendo Wii U eShop": {
        "dlc": True,
        "updates": True
    },

    # Sony
    "Sony PlayStation 3": {
        "dlc": True,
        "updates": True
    },
    "Sony PlayStation 4": {
        "updates": True
    },
    "Sony PlayStation Network - PlayStation 3": {
        "dlc": True,
        "updates": True
    },
    "Sony PlayStation Network - PlayStation 4": {
        "updates": True
    },
    "Sony PlayStation Network - PlayStation Portable": {
        "dlc": True,
        "updates": True
    },
    "Sony PlayStation Network - PlayStation Vita": {
        "dlc": True,
        "updates": True
    },
    "Sony PlayStation Portable": {
        "dlc": True,
        "updates": True
    },
    "Sony PlayStation Vita": {
        "dlc": True,
        "updates": True
    }
}

############# Transform Config #############

transform_platform_mapping = {

    # Computer
    "Computer - Disc": {
        "exe_to_install": True
    },
    "Computer - GOG": {
        "exe_to_install": True
    },
    "Computer - Humble Bundle": {
        "exe_to_install": True
    },
    "Computer - Red Candle": {
        "exe_to_install": True
    },
    "Computer - Square Enix": {
        "exe_to_install": True
    },
    "Computer - Zoom": {
        "exe_to_install": True
    },
    "Computer - Amazon Games": {
        "exe_to_raw_plain": True
    },
    "Computer - Epic Games": {
        "exe_to_raw_plain": True
    },
    "Computer - Itchio": {
        "exe_to_raw_plain": True
    },
    "Computer - Puppet Combo": {
        "exe_to_raw_plain": True
    },
    "Computer - Steam": {
        "exe_to_raw_plain": True
    },

    # Microsoft
    "Microsoft Xbox": {
        "chd_to_iso": True,
        "iso_to_xiso": True
    },
    "Microsoft Xbox 360": {
        "chd_to_iso": True,
        "iso_to_xiso": True
    },

    # Sony
    "Sony PlayStation 3": {
        "chd_to_iso": True,
        "iso_to_raw_ps3": True
    },
    "Sony PlayStation Network - PlayStation 3": {
        "pkg_to_raw_ps3": True
    },
    "Sony PlayStation Network - PlayStation Vita": {
        "pkg_to_raw_psv": True
    }
}

############# Metadata Config #############

# Metadata formats
metadata_format_gamelist = "gamelist"
metadata_format_pegasus = "pegasus"
metadata_formats = [
    metadata_format_gamelist,
    metadata_format_pegasus
]

# Metadata sources
metadata_source_thegamesdb = "thegamesdb"
metadata_source_gamefaqs = "gamefaqs"
metadata_source_itchio = "itchio"

# Metadata keys
metadata_key_game = "game"
metadata_key_platform = "platform"
metadata_key_file = "file"
metadata_key_description = "description"
metadata_key_genre = "genre"
metadata_key_tag = "tag"
metadata_key_coop = "coop"
metadata_key_developer = "developer"
metadata_key_publisher = "publisher"
metadata_key_players = "players"
metadata_key_release = "release"
metadata_key_background = "background"
metadata_key_boxback = "boxback"
metadata_key_boxfront = "boxfront"
metadata_key_label = "label"
metadata_key_screenshot = "screenshot"
metadata_key_video = "video"

# Json keys
general_key_files = "files"
general_key_launch_name = "launch_name"
general_key_launch_file = "launch_file"
general_key_launch_dir = "launch_dir"
general_key_transform_file = "transform_file"
general_key_dlc = "dlc"
general_key_update = "update"
computer_key_installer_exe = "installer_exe"
computer_key_installer_dos_exe = "installer_dos_exe"
computer_key_installer_type = "installer_type"
computer_key_disc_type = "disc_type"
computer_key_main_game_exe = "main_game_exe"
computer_key_main_game_exe_cwd = "main_game_exe_cwd"
computer_key_main_game_exe_args = "main_game_exe_args"
computer_key_main_game_dos_exe = "main_game_dos_exe"
computer_key_main_game_dos_exe_cwd = "main_game_dos_exe_cwd"
computer_key_main_game_dos_exe_args = "main_game_dos_exe_args"
computer_key_main_game_win31_exe = "main_game_win31_exe"
computer_key_main_game_win31_exe_cwd = "main_game_win31_exe_cwd"
computer_key_main_game_win31_exe_args = "main_game_win31_exe_args"
computer_key_dependencies = "dependencies"
computer_key_source_dir = "source_dir"
computer_key_source_file = "source_file"
computer_key_base_name = "base_name"
computer_key_regular_name = "regular_name"
computer_key_supercategory = "supercategory"
computer_key_category = "category"
computer_key_subcategory = "subcategory"
computer_key_platform = "platform"
computer_key_dlc = "dlc"
computer_key_update = "update"
computer_key_extra = "extra"
computer_key_sandbox = "sandbox"
computer_key_sandbox_sandboxie = "sandboxie"
computer_key_sandbox_wine = "wine"
computer_key_sandbox_wine_tricks = "tricks"
computer_key_sandbox_wine_overrides = "overrides"
computer_key_sandbox_wine_use_dxvk = "use_dxvk"
computer_key_sandbox_wine_use_vkd3dproton = "use_vkd3dproton"
computer_key_steps = "steps"
computer_key_steps_preinstall = "preinstall"
computer_key_steps_postinstall = "postinstall"
computer_key_sync = "sync"
computer_key_sync_search = "search"
computer_key_sync_data = "data"
computer_key_registry = "registry"
computer_key_registry_keep_setup = "keep_setup"
computer_key_registry_setup_keys = "setup_keys"
computer_key_winver = "winver"
computer_key_is_32_bit = "is_32_bit"
computer_key_is_dos = "is_dos"
computer_key_is_win31 = "is_win31"
computer_key_is_scumm = "is_scumm"
computer_keys_list_type = [
    computer_key_installer_exe,
    computer_key_installer_dos_exe,
    computer_key_main_game_exe,
    computer_key_main_game_dos_exe,
    computer_key_main_game_win31_exe,
    computer_key_dependencies,
    computer_key_dlc,
    computer_key_update,
    computer_key_extra
]
computer_keys_dict_type = [
    computer_key_main_game_exe_cwd,
    computer_key_main_game_exe_args,
    computer_key_main_game_dos_exe_cwd,
    computer_key_main_game_dos_exe_args,
    computer_key_main_game_win31_exe_cwd,
    computer_key_main_game_win31_exe_args,
    computer_key_sandbox,
    computer_key_steps,
    computer_key_sync,
    computer_key_registry
]
computer_keys_bool_type = [
    computer_key_is_32_bit,
    computer_key_is_dos,
    computer_key_is_win31,
    computer_key_is_scumm
]
computer_keys_str_type = [
    computer_key_installer_type,
    computer_key_disc_type,
    computer_key_winver
]

# Metadata filter keys
filter_launchable_only = "launchable_only"
filter_bool_keys = [
    filter_launchable_only
]

# Game type weights
gametype_counter = 0
gametype_weights = collections.OrderedDict()
gametype_weights[".m3u"] = gametype_counter; gametype_counter += 1      # Playlist
gametype_weights[".json"] = gametype_counter; gametype_counter += 1     # Json
gametype_weights[".exe"] = gametype_counter; gametype_counter += 1      # Windows executable
gametype_weights[".msi"] = gametype_counter; gametype_counter += 1      # Windows installer
gametype_weights[".apk"] = gametype_counter; gametype_counter += 1      # Google Android
gametype_weights[".ipa"] = gametype_counter; gametype_counter += 1      # Apple iOS
gametype_weights[".img"] = gametype_counter; gametype_counter += 1      # Apple MacOS 8
gametype_weights[".adf"] = gametype_counter; gametype_counter += 1      # Commodore Amiga - Disk
gametype_weights[".g64"] = gametype_counter; gametype_counter += 1      # Commodore 64 - G64
gametype_weights[".crt"] = gametype_counter; gametype_counter += 1      # Commodore 64 - Cartridge
gametype_weights[".tap"] = gametype_counter; gametype_counter += 1      # Commodore 64 - Tape
gametype_weights[".ipf"] = gametype_counter; gametype_counter += 1      # Commodore 64 - Disk
gametype_weights[".lnx"] = gametype_counter; gametype_counter += 1      # Atari Lynx
gametype_weights[".nes"] = gametype_counter; gametype_counter += 1      # Nintendo NES
gametype_weights[".sfc"] = gametype_counter; gametype_counter += 1      # Nintendo SNES
gametype_weights[".gba"] = gametype_counter; gametype_counter += 1      # Nintendo GBA
gametype_weights[".nds"] = gametype_counter; gametype_counter += 1      # Nintendo DS/i
gametype_weights[".trim.3ds"] = gametype_counter; gametype_counter += 1 # Nintendo 3DS
gametype_weights[".cut.xci"] = gametype_counter; gametype_counter += 1  # Nintendo Switch Cartridge
gametype_weights[".nsp"] = gametype_counter; gametype_counter += 1      # Nintendo Swith eShop
gametype_weights[".rvz"] = gametype_counter; gametype_counter += 1      # Nintendo Wii/Gamecube
gametype_weights[".iso.wux"] = gametype_counter; gametype_counter += 1  # Nintendo Wii U Disc
gametype_weights[".wua"] = gametype_counter; gametype_counter += 1      # Nintendo Wii U eShop
gametype_weights[".cue"] = gametype_counter; gametype_counter += 1      # General disc - CUE
gametype_weights[".chd"] = gametype_counter; gametype_counter += 1      # General disc - CHD
gametype_weights[".ccd"] = gametype_counter; gametype_counter += 1      # General disc - CCD
gametype_weights[".cdi"] = gametype_counter; gametype_counter += 1      # General disc - CDI
gametype_weights[".pkg"] = gametype_counter; gametype_counter += 1      # Sony PSN Package
gametype_weights[".txt"] = gametype_counter; gametype_counter += 1      # General index
gametype_weights[".zip"] = gametype_counter; gametype_counter += 1      # Zip archive

# Other game types
gametype_weight_else = 100

# Cookie file
itchio_cookie_filename = "itchio.cookie.txt"

# TheGamesDB platform ids
thegamesdb_platform_ids = {

    # Computer
    "Computer - Amazon Games": "1",
    "Computer - Disc": "1",
    "Computer - Epic Games": "1",
    "Computer - GOG": "1",
    "Computer - Humble Bundle": "1",
    "Computer - Itchio": "1",
    "Computer - Puppet Combo": "1",
    "Computer - Red Candle": "1",
    "Computer - Square Enix": "1",
    "Computer - Steam": "1",
    "Computer - Zoom": "1",

    # Microsoft
    "Microsoft MSX": "4929",
    "Microsoft Xbox": "14",
    "Microsoft Xbox 360": "15",
    "Microsoft Xbox 360 GOD": "15",
    "Microsoft Xbox 360 XBLA": "15",
    "Microsoft Xbox 360 XIG": "15",
    "Microsoft Xbox One": "4920",
    "Microsoft Xbox One GOD": "4920",

    # Nintendo
    "Nintendo 3DS": "4912",
    "Nintendo 3DS Apps": "4912",
    "Nintendo 3DS eShop": "4912",
    "Nintendo 64": "3",
    "Nintendo DS": "8",
    "Nintendo DSi": "8",
    "Nintendo Famicom": "7",
    "Nintendo Game Boy": "4",
    "Nintendo Game Boy Advance": "5",
    "Nintendo Game Boy Advance e-Reader": "5",
    "Nintendo Game Boy Color": "41",
    "Nintendo Gamecube": "2",
    "Nintendo NES": "7",
    "Nintendo SNES": "6",
    "Nintendo Super Famicom": "6",
    "Nintendo Super Game Boy": "4",
    "Nintendo Super Game Boy Color": "41",
    "Nintendo Switch": "4971",
    "Nintendo Switch eShop": "4971",
    "Nintendo Virtual Boy": "4918",
    "Nintendo Wii": "9",
    "Nintendo Wii U": "38",
    "Nintendo Wii U eShop": "38",

    # Sony
    "Sony PlayStation": "10",
    "Sony PlayStation 2": "11",
    "Sony PlayStation 3": "12",
    "Sony PlayStation 4": "4919",
    "Sony PlayStation Network - PlayStation 3": "12",
    "Sony PlayStation Network - PlayStation 4": "4919",
    "Sony PlayStation Network - PlayStation Portable": "13",
    "Sony PlayStation Network - PlayStation Portable Minis": "13",
    "Sony PlayStation Network - PlayStation Vita": "39",
    "Sony PlayStation Portable": "13",
    "Sony PlayStation Portable Video": "13",
    "Sony PlayStation Vita": "39",

    # Other
    "Apple iOS": "4915",
    "Arcade": "23",
    "Atari 2600": "22",
    "Atari 5200": "26",
    "Atari 7800": "27",
    "Atari Jaguar": "28",
    "Atari Jaguar CD": "29",
    "Atari Lynx": "4924",
    "Bandai WonderSwan": "4925",
    "Bandai WonderSwan Color": "4926",
    "Coleco ColecoVision": "31",
    "Commodore 64": "40",
    "Commodore Amiga": "4911",
    "Google Android": "4916",
    "Magnavox Odyssey 2": "4927",
    "Mattel Intellivision": "32",
    "NEC SuperGrafx": "34",
    "NEC TurboGrafx CD & PC-Engine CD": "4955",
    "NEC TurboGrafx-16 & PC-Engine": "34",
    "Nokia N-Gage": "4938",
    "Panasonic 3DO": "25",
    "Philips CDi": "4917",
    "SNK Neo Geo Pocket Color": "4923",
    "Sega 32X": "33",
    "Sega CD": "21",
    "Sega CD 32X": "33",
    "Sega Dreamcast": "16",
    "Sega Game Gear": "20",
    "Sega Genesis": "18",
    "Sega Master System": "35",
    "Sega Saturn": "17",
    "Sinclair ZX Spectrum": "4913",
    "Texas Instruments TI-99-4A": "4953",
    "Tiger Game.com": "4940"
}
