# Imports
import os, os.path
import os.path
import sys

# Local imports
import config
import system
import environment
import cache
import command
import programs
import release
import sandbox
import metadata
import display
import ini
import gui
import gameinfo
import emulatorbase

# Config files
config_files = {}
config_file_general_dos = """
[dosbox]
working directory default = $EMULATOR_SETUP_ROOT
"""
config_file_general_win31 = """
[dosbox]
working directory default = $EMULATOR_SETUP_ROOT
memsize = 256
machine = svga_s3trio64

[cpu]
cputype = pentium
core = normal

[pci]
voodoo = false

[dos]
hard drive data rate limit = 0
floppy drive data rate limit = 0

[ide, primary]
int13fakeio = true
int13fakev86io = false
"""
config_files["DosBoxX/windows/dosbox-x.conf"] = config_file_general_dos
config_files["DosBoxX/windows/dosbox-x.win31.conf"] = config_file_general_win31
config_files["DosBoxX/linux/DosBoxX.AppImage.home/.config/dosbox-x/dosbox-x.conf"] = config_file_general_dos
config_files["DosBoxX/linux/DosBoxX.AppImage.home/.config/dosbox-x/dosbox-x.win31.conf"] = config_file_general_win31
config_files["ScummVM/windows/scummvm.ini"] = ""
config_files["ScummVM/linux/ScummVM.AppImage.home/.config/scummvm/scummvm.ini"] = ""

# System files
system_files = {}

# Build disc token map
def BuildDiscTokenMap(disc_files = [], use_drive_letters = False):

    # Create disc token map
    disc_token_map = {}
    disc_letter_index = 0
    for disc_file in disc_files:

        # Get drive letter
        disc_letter_drive = config.drives_regular[disc_letter_index]
        disc_letter_index += 1

        # Get file basename
        disc_file_basename = system.GetFilenameBasename(disc_file)

        # Find which token to use
        disc_token_to_use = None
        for disc_token, disc_name in config.token_disc_names.items():
            if disc_name in disc_file:
                disc_token_to_use = disc_token
                break
        else:
            disc_token_to_use = config.token_disc_main_root

        # Add entry
        if disc_token_to_use:
            if use_drive_letters:
                disc_token_map[disc_token_to_use] = "%s:/" % disc_letter_drive
            else:
                disc_token_map[disc_token_to_use] = disc_file_basename
    return disc_token_map

# Resolve json path
def ResolveJsonPath(
    path,
    setup_base_dir,
    hdd_base_dir,
    disc_base_dir,
    disc_token_map = {}):
    replace_from = ""
    replace_to = ""
    if path.startswith(config.token_setup_main_root):
        replace_from = config.token_setup_main_root
        replace_to = setup_base_dir
    elif path.startswith(config.token_hdd_main_root):
        replace_from = config.token_hdd_main_root
        replace_to = hdd_base_dir
    elif path.startswith(config.token_dos_main_root):
        replace_from = config.token_dos_main_root
        replace_to = os.path.join(hdd_base_dir, config.computer_dos_folder)
    elif path.startswith(config.token_scumm_main_root):
        replace_from = config.token_scumm_main_root
        replace_to = os.path.join(hdd_base_dir, config.computer_scumm_folder)
    for disc_token in config.tokens_disc:
        if disc_token in path and disc_token in disc_token_map:
            mapped_value = disc_token_map[disc_token]
            replace_from = disc_token
            if len(disc_token_map[disc_token]) > 3:
                replace_to = os.path.join(disc_base_dir, disc_token_map[disc_token])
            else:
                replace_to = disc_token_map[disc_token]
            break
    return path.replace(replace_from, replace_to)

# Resolve json paths
def ResolveJsonPaths(
    paths,
    setup_base_dir,
    hdd_base_dir,
    disc_base_dir,
    disc_token_map = {}):
    new_paths = []
    for path in paths:
        new_paths.append(ResolveJsonPath(
            path = path,
            setup_base_dir = setup_base_dir,
            hdd_base_dir = hdd_base_dir,
            disc_base_dir = disc_base_dir,
            disc_token_map = disc_token_map))
    return new_paths

# Get dos launch command
def GetDosLaunchCommand(
    prefix_dir,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    start_program = None,
    start_letter = "c",
    start_offset = None,
    fullscreen = False):

    # Check params
    system.AssertPathExists(prefix_dir, "prefix_dir")

    # Get prefix c drive
    prefix_c_drive = sandbox.GetRealDrivePath(
        prefix_dir = prefix_dir,
        drive = "c",
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix)

    # Get dos drives
    dos_c_drive = os.path.join(prefix_c_drive, config.computer_dos_folder, "C")
    dos_d_drive = os.path.join(prefix_c_drive, config.computer_dos_folder, "D")

    # Search for disc images
    disc_images = system.BuildFileListByExtensions(dos_d_drive, [".chd"])

    # Create launch command
    launch_cmd = [programs.GetEmulatorProgram("DosBoxX")]

    # Add config file
    launch_cmd += [
        "-conf",
        programs.GetEmulatorPathConfigValue("DosBoxX", "config_file")
    ]

    # Add c drive mount
    launch_cmd += [
        "-c", "mount c \"%s\"" % dos_c_drive
    ]

    # Add disc drive mounts
    if len(disc_images):
        disc_index = 0
        for disc_image in disc_images:
            launch_cmd += [
                "-c", "imgmount %s \"%s\" -t iso" % (config.drives_regular[disc_index], disc_image),
            ]
            disc_index += 1

    # Add initial launch params
    launch_cmd += ["-c", "%s:" % start_letter]
    if system.IsPathValid(start_offset):
        launch_cmd += ["-c", "cd %s" % start_offset]
    if system.IsPathValid(start_program):
        launch_cmd += ["-c", "%s" % system.GetFilenameFile(start_program)]

    # Add other flags
    if fullscreen:
        launch_cmd += ["-fullscreen"]

    # Return launch command
    return launch_cmd

# Get win31 launch command
def GetWin31LaunchCommand(
    prefix_dir,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    start_program = None,
    start_letter = "c",
    start_offset = None,
    fullscreen = False):

    # Check params
    system.AssertPathExists(prefix_dir, "prefix_dir")

    # Get prefix c drive
    prefix_c_drive = sandbox.GetRealDrivePath(
        prefix_dir = prefix_dir,
        drive = "c",
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix)

    # Get dos drives
    dos_c_drive = os.path.join(prefix_c_drive, config.computer_dos_folder, "C")
    dos_d_drive = os.path.join(prefix_c_drive, config.computer_dos_folder, "D")

    # Search for disc images
    disc_images = system.BuildFileListByExtensions(dos_d_drive, [".chd"])

    # Create launch command
    launch_cmd = [programs.GetEmulatorProgram("DosBoxX")]

    # Add config file
    launch_cmd += [
        "-conf",
        programs.GetEmulatorPathConfigValue("DosBoxX", "config_file_win31")
    ]

    # Add c drive mount
    launch_cmd += [
        "-c", "mount c \"%s\"" % dos_c_drive
    ]

    # Add disc drive mounts
    if len(disc_images):
        disc_index = 0
        for disc_image in disc_images:
            launch_cmd += [
                "-c", "imgmount %s \"%s\" -t iso" % (config.drives_regular[disc_index], disc_image),
            ]
            disc_index += 1

    # Add initial launch params
    launch_cmd += ["-c", "SET PATH=%PATH%;C:\WINDOWS;"]
    launch_cmd += ["-c", "SET TEMP=C:\WINDOWS\TEMP"]
    launch_cmd += ["-c", "%s:" % start_letter]
    if system.IsPathValid(start_offset):
        launch_cmd += ["-c", "cd %s" % start_offset]
    if system.IsPathValid(start_program):
        launch_cmd += ["-c", "WIN RUNEXIT %s" % system.GetFilenameFile(start_program)]
        launch_cmd += ["-c", "EXIT"]

    # Add other flags
    if fullscreen:
        launch_cmd += ["-fullscreen"]

    # Return launch command
    return launch_cmd

# Get scumm launch command
def GetScummLaunchCommand(
    prefix_dir,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    fullscreen = False):

    # Check params
    system.AssertPathExists(prefix_dir, "prefix_dir")

    # Get prefix c drive
    prefix_c_drive = sandbox.GetRealDrivePath(
        prefix_dir = prefix_dir,
        drive = "c",
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix)

    # Get prefix user profile path
    prefix_user_profile = sandbox.GetUserProfilePath(
        prefix_dir = prefix_dir,
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix)

    # Create launch command
    launch_cmd = [programs.GetEmulatorProgram("ScummVM")]
    launch_cmd += [
        "--path=%s" % os.path.join(prefix_c_drive, config.computer_scumm_folder)
    ]
    launch_cmd += ["--auto-detect"]
    launch_cmd += [
        "--savepath=%s" % os.path.join(prefix_user_profile, config.computer_game_data_folder)
    ]
    if fullscreen:
        launch_cmd += ["--fullscreen"]

    # Return launch command
    return launch_cmd

# Get selected launch info
def GetSelectedLaunchInfo(
    game_info,
    base_dir,
    default_cwd,
    key_exe_list,
    key_exe_cwd_dict,
    key_exe_args_dict):

    # Get game exe list
    game_exe_list = game_info.get_value(key_exe_list)

    # Get cwd and arg dicts
    game_exe_cwds = game_info.get_value(key_exe_cwd_dict)
    game_exe_args = game_info.get_value(key_exe_args_dict)

    # No existing entries
    if len(game_exe_list) == 0:

        # Get the complete list of runnable files from the install
        runnable_files_all = system.BuildFileListByExtensions(
            root = base_dir,
            extensions = config.computer_program_extensions,
            use_relative_paths = True,
            follow_symlink_dirs = True)

        # Parse down the complete list to the ones most likely to be games
        runnable_files_likely = []
        for relative_path in runnable_files_all:
            path_to_add = system.NormalizeFilePath(relative_path, separator = config.os_pathsep)
            should_ignore = False
            for ignore_path in config.ignored_paths_install:
                if path_to_add.startswith(ignore_path):
                    should_ignore = True
                    break
            if should_ignore:
                continue
            runnable_files_likely.append(path_to_add)

        # Generate working directories
        runnable_files_cwds = {}
        for runnable_file in runnable_files_likely:
            runnable_files_cwds[runnable_file] = system.GetFilenameDirectory(runnable_file)

        # Use list of likely files
        game_exe_list = runnable_files_likely

        # Get original json file
        json_file = environment.GetJsonRomMetadataFile(
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name())

        # Try to record these for later
        new_json_data = system.ReadJsonFile(json_file)
        new_json_data[key_exe_list] = runnable_files_likely
        new_json_data[key_exe_cwd_dict] = runnable_files_cwds
        system.WriteJsonFile(json_file, new_json_data)

    # Get launch info
    def GetLaunchInfo(game_exe):
        cmd = os.path.join(base_dir, game_exe)
        cwd = default_cwd
        args = []
        if game_exe in game_exe_cwds:
            cwd = game_exe_cwds[game_exe]
        if game_exe in game_exe_args:
            args = game_exe_args[game_exe]
        return [cmd, cwd, args]

    # Check that we have something to run
    if len(game_exe_list) == 0:
        gui.DisplayErrorPopup(
            title_text = "No runnable files",
            message_text = "Computer install has no runnable files")

    # If we have exactly one choice, use that
    if len(game_exe_list) == 1:
        return GetLaunchInfo(game_exe_list[0])

    # Create launch command
    launch_cmd = []
    launch_cwd = ""
    launch_args = []

    # Handle game selection
    def HandleGameSelection(selected_file):
        nonlocal launch_cmd
        nonlocal launch_cwd
        nonlocal launch_args
        launch_cmd, launch_cwd, launch_args = GetLaunchInfo(selected_file)

    # Display list of runnable files and let user decide which to run
    gui.DisplayChoicesWindow(
        choice_list = game_exe_list,
        title_text = "Select Program",
        message_text = "Select program to run",
        button_text = "Run program",
        run_func = HandleGameSelection)

    # Return launch info
    return [launch_cmd, launch_cwd, launch_args]

# Computer emulator
class Computer(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Computer"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.platform_computer_amazon_games,
            config.platform_computer_disc,
            config.platform_computer_epic_games,
            config.platform_computer_gog,
            config.platform_computer_humble_bundle,
            config.platform_computer_itchio,
            config.platform_computer_puppet_combo,
            config.platform_computer_red_candle,
            config.platform_computer_square_enix,
            config.platform_computer_steam,
            config.platform_computer_zoom
        ]

    # Get config
    def GetConfig(self):
        return {

            # DosBoxX
            "DosBoxX": {
                "program": {
                    "windows": "DosBoxX/windows/dosbox-x.exe",
                    "linux": "DosBoxX/linux/DosBoxX.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "DosBoxX/windows",
                    "linux": "DosBoxX/linux"
                },
                "config_file": {
                    "windows": "DosBoxX/windows/dosbox-x.conf",
                    "linux": "DosBoxX/linux/DosBoxX.AppImage.home/.config/dosbox-x/dosbox-x.conf"
                },
                "config_file_win31": {
                    "windows": "DosBoxX/windows/dosbox-x.win31.conf",
                    "linux": "DosBoxX/linux/DosBoxX.AppImage.home/.config/dosbox-x/dosbox-x.win31.conf"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            },

            # ScummVM
            "ScummVM": {
                "program": {
                    "windows": "ScummVM/windows/scummvm.exe",
                    "linux": "ScummVM/linux/ScummVM.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "ScummVM/windows",
                    "linux": "ScummVM/linux"
                },
                "config_file": {
                    "windows": "ScummVM/windows/scummvm.ini",
                    "linux": "ScummVM/linux/ScummVM.AppImage.home/.config/scummvm/scummvm.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Get save type
    def GetSaveType(self):
        if environment.IsWindowsPlatform():
            return config.save_type_sandboxie
        else:
            return config.save_type_wine

    # Get config file
    def GetConfigFile(self, emulator_platform = None):
        return None

    # Get save base dir
    def GetSaveBaseDir(self, emulator_platform = None):
        return None

    # Get save sub dirs
    def GetSaveSubDirs(self, emulator_platform = None):
        return None

    # Get save dir
    def GetSaveDir(self, emulator_platform = None):
        return None

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows programs
        if programs.ShouldProgramBeInstalled("DosBoxX", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "joncampbell123",
                github_repo = "dosbox-x",
                starts_with = "dosbox-x-vsbuild-win64",
                ends_with = ".zip",
                search_file = "dosbox-x.exe",
                install_name = "DosBoxX",
                install_dir = programs.GetProgramInstallDir("DosBoxX", "windows"),
                backups_dir = programs.GetProgramBackupDir("DosBoxX", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup DosBoxX")
        if programs.ShouldProgramBeInstalled("ScummVM", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://www.scummvm.org/downloads",
                webpage_base_url = "https://www.scummvm.org",
                starts_with = "https://downloads.scummvm.org/frs/scummvm/",
                ends_with = "win32-x86_64.zip",
                search_file = "SDL2.dll",
                install_name = "ScummVM",
                install_dir = programs.GetProgramInstallDir("ScummVM", "windows"),
                backups_dir = programs.GetProgramBackupDir("ScummVM", "windows"),
                rename_files = [
                    {"from": "scummvm-*.exe", "to": "scummvm.exe", "ratio": 75}
                ],
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup ScummVM")

        # Build linux programs
        if programs.ShouldProgramBeInstalled("DosBoxX", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/DosboxX.git",
                install_name = "DosBoxX",
                install_dir = programs.GetProgramInstallDir("DosBoxX", "linux"),
                backups_dir = programs.GetProgramBackupDir("DosBoxX", "linux"),
                build_cmd = [
                    "./build-sdl2"
                ],
                internal_copies = [
                    {"from": "Source/src/dosbox-x", "to": "AppImage/usr/bin/dosbox-x"},
                    {"from": "Source/CHANGELOG", "to": "AppImage/usr/share/dosbox-x/CHANGELOG"},
                    {"from": "Source/dosbox-x.reference.conf", "to": "AppImage/usr/share/dosbox-x/dosbox-x.reference.conf"},
                    {"from": "Source/dosbox-x.reference.full.conf", "to": "AppImage/usr/share/dosbox-x/dosbox-x.reference.full.conf"},
                    {"from": "Source/contrib/fonts/FREECG98.BMP", "to": "AppImage/usr/share/dosbox-x/FREECG98.BMP"},
                    {"from": "Source/contrib/fonts/Nouveau_IBM.ttf", "to": "AppImage/usr/share/dosbox-x/Nouveau_IBM.ttf"},
                    {"from": "Source/contrib/fonts/SarasaGothicFixed.ttf", "to": "AppImage/usr/share/dosbox-x/SarasaGothicFixed.ttf"},
                    {"from": "Source/contrib/fonts/wqy_11pt.bdf", "to": "AppImage/usr/share/dosbox-x/wqy_11pt.bdf"},
                    {"from": "Source/contrib/fonts/wqy_12pt.bdf", "to": "AppImage/usr/share/dosbox-x/wqy_12pt.bdf"},
                    {"from": "Source/contrib/windows/installer/drivez_readme.txt", "to": "AppImage/usr/share/dosbox-x/drivez/readme.txt"},
                    {"from": "Source/contrib/glshaders", "to": "AppImage/usr/share/dosbox-x/glshaders"},
                    {"from": "Source/contrib/translations/de/de_DE.lng", "to": "AppImage/usr/share/dosbox-x/languages/de_DE.lng"},
                    {"from": "Source/contrib/translations/en/en_US.lng", "to": "AppImage/usr/share/dosbox-x/languages/en_US.lng"},
                    {"from": "Source/contrib/translations/es/es_ES.lng", "to": "AppImage/usr/share/dosbox-x/languages/es_ES.lng"},
                    {"from": "Source/contrib/translations/fr/fr_FR.lng", "to": "AppImage/usr/share/dosbox-x/languages/fr_FR.lng"},
                    {"from": "Source/contrib/translations/ja/ja_JP.lng", "to": "AppImage/usr/share/dosbox-x/languages/ja_JP.lng"},
                    {"from": "Source/contrib/translations/ko/ko_KR.lng", "to": "AppImage/usr/share/dosbox-x/languages/ko_KR.lng"},
                    {"from": "Source/contrib/translations/nl/nl_NL.lng", "to": "AppImage/usr/share/dosbox-x/languages/nl_NL.lng"},
                    {"from": "Source/contrib/translations/pt/pt_BR.lng", "to": "AppImage/usr/share/dosbox-x/languages/pt_BR.lng"},
                    {"from": "Source/contrib/translations/tr/tr_TR.lng", "to": "AppImage/usr/share/dosbox-x/languages/tr_TR.lng"},
                    {"from": "Source/contrib/translations/zh/zh_CN.lng", "to": "AppImage/usr/share/dosbox-x/languages/zh_CN.lng"},
                    {"from": "Source/contrib/translations/zh/zh_TW.lng", "to": "AppImage/usr/share/dosbox-x/languages/zh_TW.lng"},
                    {"from": "Source/contrib/linux/com.dosbox_x.DOSBox-X.desktop", "to": "AppImage/app.desktop"},
                    {"from": "Source/contrib/icons/dosbox-x.png", "to": "AppImage/dosbox-x.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/dosbox-x", "to": "AppRun"}
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup DosBoxX")
        if programs.ShouldProgramBeInstalled("ScummVM", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/ScummVM.git",
                install_name = "ScummVM",
                install_dir = programs.GetProgramInstallDir("ScummVM", "linux"),
                backups_dir = programs.GetProgramBackupDir("ScummVM", "linux"),
                build_cmd = [
                    "./configure",
                    "&&",
                    "make", "-j10"
                ],
                internal_copies = [
                    {"from": "Source/scummvm", "to": "AppImage/usr/bin/scummvm"},
                    {"from": "Source/gui/themes/*.dat", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/gui/themes/*.zip", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/dists/networking/wwwroot.zip", "to": "AppImage/usr/local/share/scummvm/wwwroot.zip"},
                    {"from": "Source/dists/engine-data/*.dat", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/dists/engine-data/*.zip", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/dists/engine-data/*.tbl", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/dists/engine-data/*.cpt", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/dists/engine-data/*.lab", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/dists/pred.dic", "to": "AppImage/usr/local/share/scummvm/pred.dic"},
                    {"from": "Source/engines/grim/shaders/*.fragment", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/engines/grim/shaders/*.vertex", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/engines/stark/shaders/*.fragment", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/engines/stark/shaders/*.vertex", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/engines/wintermute/base/gfx/opengl/shaders/*.fragment", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/engines/wintermute/base/gfx/opengl/shaders/*.vertex", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/engines/freescape/shaders/*.fragment", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/engines/freescape/shaders/*.vertex", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/dists/org.scummvm.scummvm.desktop", "to": "AppImage/org.scummvm.scummvm.desktop"},
                    {"from": "Source/icons/scummvm.svg", "to": "AppImage/org.scummvm.scummvm.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/scummvm", "to": "AppRun"}
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup ScummVM")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("DosBoxX", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("DosBoxX", "windows"),
                install_name = "DosBoxX",
                install_dir = programs.GetProgramInstallDir("DosBoxX", "windows"),
                search_file = "dosbox-x.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup DosBoxX")
        if programs.ShouldProgramBeInstalled("ScummVM", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("ScummVM", "windows"),
                install_name = "ScummVM",
                install_dir = programs.GetProgramInstallDir("ScummVM", "windows"),
                search_file = "scummvm.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup ScummVM")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("DosBoxX", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("DosBoxX", "linux"),
                install_name = "DosBoxX",
                install_dir = programs.GetProgramInstallDir("DosBoxX", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup DosBoxX")
        if programs.ShouldProgramBeInstalled("ScummVM", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("ScummVM", "linux"),
                install_name = "ScummVM",
                install_dir = programs.GetProgramInstallDir("ScummVM", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup ScummVM")

    # Configure
    def Configure(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup DosBoxX/ScummVM config files")

    # Launch
    def Launch(
        self,
        game_info,
        capture_type,
        fullscreen = False,
        verbose = False,
        exit_on_failure = False):

        # Check if command should be run via wine/sandboxie
        should_run_via_wine = environment.IsLinuxPlatform()
        should_run_via_sandboxie = environment.IsWindowsPlatform()

        # Get launch info
        launch_name = game_info.get_name()
        launch_category = game_info.get_category()
        launch_subcategory = game_info.get_subcategory()
        launch_platform = game_info.get_platform()
        launch_artwork = game_info.get_boxfront_asset()
        launch_save_dir = game_info.get_save_dir()
        launch_general_save_dir = game_info.get_general_save_dir()
        launch_cache_dir = game_info.get_local_cache_dir()
        launch_info_wine_setup = game_info.get_wine_setup()
        launch_info_sandboxie_setup = game_info.get_sandboxie_setup()
        launch_info_sync_search = system.NormalizeFilePath(game_info.get_sync_search())
        launch_info_sync_data = game_info.get_sync_data()
        launch_info_registry_setup_keys = game_info.get_setup_registry_keys()
        launch_info_registry_game_keys = game_info.get_game_registry_keys()
        launch_info_winver = game_info.get_winver()
        launch_info_is_32_bit = game_info.is_32_bit()
        launch_info_is_dos = game_info.is_dos()
        launch_info_is_win31 = game_info.is_win31()
        launch_info_is_scumm = game_info.is_scumm()

        # Install game to cache
        cache.InstallGameToCache(
            game_info = game_info,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Get mount links
        mount_links = []
        for obj in system.GetDirectoryContents(launch_cache_dir):
            mount_links.append({
                "from": os.path.join(launch_cache_dir, obj),
                "to": obj
            })

        # Create linked prefix
        def CreateGamePrefix():
            return sandbox.CreateLinkedPrefix(
                prefix_dir = launch_save_dir,
                prefix_name = config.prefix_type_game,
                prefix_winver = launch_info_winver,
                general_prefix_dir = launch_general_save_dir,
                other_links = mount_links,
                clean_existing = False,
                is_wine_prefix = should_run_via_wine,
                is_sandboxie_prefix = should_run_via_sandboxie,
                wine_setup = launch_info_wine_setup,
                sandboxie_setup = launch_info_sandboxie_setup,
                is_32_bit = launch_info_is_32_bit,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        gui.DisplayLoadingWindow(
            title_text = "Creating game prefix",
            message_text = "Creating game prefix\n%s\n%s" % (launch_name, launch_platform),
            failure_text = "Unable to create game prefix",
            image_file = launch_artwork,
            run_func = CreateGamePrefix)

        # Create user files
        if launch_category == config.game_category_computer:

            # Steam
            if launch_subcategory == config.game_subcategory_steam:

                # Create steam username file
                steam_username = ini.GetIniValue("UserData.Steam", "steam_username")
                if steam_username:
                    system.TouchFile(
                        src = sandbox.GetGoldbergSteamEmuUserNameFile(launch_general_save_dir),
                        contents = "%s\n" % steam_username,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)

                # Create steam userid file
                steam_userid = ini.GetIniValue("UserData.Steam", "steam_userid")
                if steam_userid:
                    system.TouchFile(
                        src = sandbox.GetGoldbergSteamEmuUserIDFile(launch_general_save_dir),
                        contents = "%s\n" % steam_userid,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)

        # Get user profile
        user_profile_dir = sandbox.GetUserProfilePath(
            prefix_dir = launch_save_dir,
            is_wine_prefix = should_run_via_wine,
            is_sandboxie_prefix = should_run_via_sandboxie)

        # Build list of dirs to clear
        dirs_to_clear = []
        dirs_to_clear += [os.path.join(user_profile_dir, config.computer_temp_folder)]
        dirs_to_clear += [os.path.join(user_profile_dir, config.computer_appdata_folder, "Local", "CrashDumps")]

        # Find sync base directory
        sync_basedir = None
        if len(launch_info_sync_search):
            for sync_search_file in system.BuildFileList(launch_cache_dir):
                if sync_search_file.endswith(launch_info_sync_search):
                    sync_basedir = system.GetFilenameDirectory(sync_search_file)
                    break

        # Get sync objects
        sync_objs = sandbox.GetPrefixSyncObjs(
            prefix_dir = launch_save_dir,
            general_prefix_dir = launch_general_save_dir,
            is_wine_prefix = should_run_via_wine,
            is_sandboxie_prefix = should_run_via_sandboxie,
            user_data_sync_basedir = sync_basedir,
            user_data_sync_objs = launch_info_sync_data)

        # Get prefix c drive
        prefix_c_drive = sandbox.GetRealDrivePath(
            prefix_dir = launch_save_dir,
            drive = "c",
            is_wine_prefix = should_run_via_wine,
            is_sandboxie_prefix = should_run_via_sandboxie)

        # Get dos drives
        dos_c_drive = os.path.join(prefix_c_drive, config.computer_dos_folder, "C")
        dos_d_drive = os.path.join(prefix_c_drive, config.computer_dos_folder, "D")

        # Get launch info
        launch_info_cmd = []
        launch_info_cwd = ""
        launch_info_args = []
        launch_info_options = None

        # Dos launcher
        if launch_info_is_dos:
            selected_cmd, selected_cwd, selected_args = GetSelectedLaunchInfo(
                game_info = game_info,
                base_dir = dos_c_drive,
                default_cwd = dos_c_drive,
                key_exe_list = config.json_key_main_game_dos_exe,
                key_exe_cwd_dict = config.json_key_main_game_dos_exe_cwd,
                key_exe_args_dict = config.json_key_main_game_dos_exe_args)
            if selected_cmd:
                launch_info_cmd = GetDosLaunchCommand(
                    prefix_dir = launch_save_dir,
                    is_wine_prefix = should_run_via_wine,
                    is_sandboxie_prefix = should_run_via_sandboxie,
                    start_program = selected_cmd,
                    start_letter = "c",
                    start_offset = selected_cwd,
                    fullscreen = fullscreen)
                launch_info_options = command.CommandOptions(
                    prefix_dir = launch_save_dir,
                    prefix_name = config.prefix_type_game,
                    prefix_winver = launch_info_winver,
                    prefix_cwd = launch_info_cwd,
                    is_wine_prefix = should_run_via_wine,
                    is_sandboxie_prefix = should_run_via_sandboxie)

        # Win31 launcher
        elif launch_info_is_win31:
            selected_cmd, selected_cwd, selected_args = GetSelectedLaunchInfo(
                game_info = game_info,
                base_dir = dos_c_drive,
                default_cwd = dos_c_drive,
                key_exe_list = config.json_key_main_game_win31_exe,
                key_exe_cwd_dict = config.json_key_main_game_win31_exe_cwd,
                key_exe_args_dict = config.json_key_main_game_win31_exe_args)
            if selected_cmd:
                launch_info_cmd = GetWin31LaunchCommand(
                    prefix_dir = launch_save_dir,
                    is_wine_prefix = should_run_via_wine,
                    is_sandboxie_prefix = should_run_via_sandboxie,
                    start_program = selected_cmd,
                    start_letter = "c",
                    start_offset = selected_cwd,
                    fullscreen = fullscreen)
                launch_info_options = command.CommandOptions(
                    prefix_dir = launch_save_dir,
                    prefix_name = config.prefix_type_game,
                    prefix_winver = launch_info_winver,
                    prefix_cwd = launch_info_cwd,
                    is_wine_prefix = should_run_via_wine,
                    is_sandboxie_prefix = should_run_via_sandboxie)

        # Scumm launcher
        elif launch_info_is_scumm:
            launch_info_cmd = GetScummLaunchCommand(
                prefix_dir = launch_save_dir,
                is_wine_prefix = should_run_via_wine,
                is_sandboxie_prefix = should_run_via_sandboxie,
                fullscreen = fullscreen)
            launch_info_options = command.CommandOptions(
                prefix_dir = launch_save_dir,
                prefix_name = config.prefix_type_game,
                prefix_winver = launch_info_winver,
                prefix_cwd = launch_info_cwd,
                is_wine_prefix = should_run_via_wine,
                is_sandboxie_prefix = should_run_via_sandboxie)

        # Regular launcher
        else:
            launch_info_cmd_str, launch_info_cwd, launch_info_args = GetSelectedLaunchInfo(
                game_info = game_info,
                base_dir = prefix_c_drive,
                default_cwd = launch_general_save_dir,
                key_exe_list = config.json_key_main_game_exe,
                key_exe_cwd_dict = config.json_key_main_game_exe_cwd,
                key_exe_args_dict = config.json_key_main_game_exe_args)
            launch_info_cmd = [launch_info_cmd_str] + launch_info_args
            launch_program = command.GetStarterCommand(launch_info_cmd_str)
            blocking_processes = sandbox.GetBlockingProcesses(
                initial_processes = [launch_program],
                is_wine_prefix = should_run_via_wine,
                is_sandboxie_prefix = should_run_via_sandboxie)
            launch_info_options = command.CommandOptions(
                cwd = os.path.expanduser("~"),
                force_prefix = True,
                prefix_dir = launch_save_dir,
                prefix_name = config.prefix_type_game,
                prefix_winver = launch_info_winver,
                prefix_cwd = launch_info_cwd,
                is_wine_prefix = should_run_via_wine,
                is_sandboxie_prefix = should_run_via_sandboxie,
                wine_setup = launch_info_wine_setup,
                sandboxie_setup = launch_info_sandboxie_setup,
                is_32_bit = launch_info_is_32_bit,
                lnk_base_path = launch_cache_dir,
                blocking_processes = blocking_processes)

        # Check launch command
        if len(launch_info_cmd):

            # Restore game registry
            sandbox.RestoreRegistry(
                prefix_dir = launch_save_dir,
                prefix_name = config.prefix_type_game,
                is_wine_prefix = should_run_via_wine,
                is_sandboxie_prefix = should_run_via_sandboxie,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

            # Restore user data
            for sync_obj in sync_objs:
                system.SyncData(
                    data_src = sync_obj["stored"],
                    data_dest = sync_obj["live"],
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

            # Launch game
            command.RunGameCommand(
                game_info = game_info,
                cmd = launch_info_cmd,
                options = launch_info_options,
                capture_type = capture_type,
                verbose = verbose)

            # Move sandboxed data back
            if should_run_via_sandboxie:
                temp_cache_dir = os.path.join(user_profile_dir, "Cache")
                real_cache_dir = environment.GetLocalCacheRootDir()
                if system.DoesDirectoryContainFiles(temp_cache_dir):
                    system.MoveContents(
                        src = temp_cache_dir,
                        dest = real_cache_dir,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)

            # Clean dirs
            for dir_to_clear in dirs_to_clear:
                if os.path.exists(dir_to_clear):
                    system.RemoveDirectoryContents(
                        dir = dir_to_clear,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)

            # Backup user data
            for sync_obj in sync_objs:
                system.SyncData(
                    data_src = sync_obj["live"],
                    data_dest = sync_obj["stored"],
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

            # Backup game registry
            sandbox.BackupRegistry(
                prefix_dir = launch_save_dir,
                prefix_name = config.prefix_type_game,
                registry_keys = launch_info_registry_game_keys,
                is_wine_prefix = should_run_via_wine,
                is_sandboxie_prefix = should_run_via_sandboxie,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

            # Restore default screen resolution
            display.RestoreDefaultScreenResolution(
                verbose = verbose,
                exit_on_failure = exit_on_failure)
