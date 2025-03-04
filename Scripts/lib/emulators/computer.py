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
import containers

# Config files
config_files = {}
config_file_general_dos = """
[dosbox]
working directory default = EMULATOR_SETUP_ROOT
"""
config_file_general_win31 = """
[dosbox]
working directory default = EMULATOR_SETUP_ROOT
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

# Computer emulator
class Computer(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Computer"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.Platform.COMPUTER_AMAZON_GAMES,
            config.Platform.COMPUTER_DISC,
            config.Platform.COMPUTER_EPIC_GAMES,
            config.Platform.COMPUTER_GOG,
            config.Platform.COMPUTER_HUMBLE_BUNDLE,
            config.Platform.COMPUTER_ITCHIO,
            config.Platform.COMPUTER_LEGACY_GAMES,
            config.Platform.COMPUTER_PUPPET_COMBO,
            config.Platform.COMPUTER_RED_CANDLE,
            config.Platform.COMPUTER_SQUARE_ENIX,
            config.Platform.COMPUTER_STEAM,
            config.Platform.COMPUTER_ZOOM
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
            return config.SaveType.SANDBOXIE
        else:
            return config.SaveType.WINE

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
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

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
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup DosBoxX")
                return False
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
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ScummVM")
                return False

        # Build linux programs
        if programs.ShouldProgramBeInstalled("DosBoxX", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/DosboxX.git",
                output_file = "DOSBox-X-x86_64.AppImage",
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
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup DosBoxX")
                return False
        if programs.ShouldProgramBeInstalled("ScummVM", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/ScummVM.git",
                output_file = "ScummVM-x86_64.AppImage",
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
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ScummVM")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("DosBoxX", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("DosBoxX", "windows"),
                install_name = "DosBoxX",
                install_dir = programs.GetProgramInstallDir("DosBoxX", "windows"),
                search_file = "dosbox-x.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup DosBoxX")
                return False
        if programs.ShouldProgramBeInstalled("ScummVM", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("ScummVM", "windows"),
                install_name = "ScummVM",
                install_dir = programs.GetProgramInstallDir("ScummVM", "windows"),
                search_file = "scummvm.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ScummVM")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("DosBoxX", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("DosBoxX", "linux"),
                install_name = "DosBoxX",
                install_dir = programs.GetProgramInstallDir("DosBoxX", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup DosBoxX")
                return False
        if programs.ShouldProgramBeInstalled("ScummVM", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("ScummVM", "linux"),
                install_name = "ScummVM",
                install_dir = programs.GetProgramInstallDir("ScummVM", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ScummVM")
                return False
        return True

    # Configure
    def Configure(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = system.JoinPaths(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup DosBoxX/ScummVM config files")
                return False
        return True

    # Launch
    def Launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get launch options
        launch_options = command.CreateCommandOptions()

        # Get mount links
        mount_links = []
        for obj in system.GetDirectoryContents(game_info.get_local_cache_dir()):
            mount_links.append({
                "from": system.JoinPaths(game_info.get_local_cache_dir(), obj),
                "to": obj
            })

        # Create linked prefix
        def CreateGamePrefix():
            nonlocal launch_options
            return launch_options.create_prefix(
                is_wine_prefix = environment.IsLinuxPlatform(),
                is_sandboxie_prefix = environment.IsWindowsPlatform(),
                prefix_name = config.PrefixType.GAME,
                prefix_dir = game_info.get_save_dir(),
                general_prefix_dir = game_info.get_general_save_dir(),
                linked_prefix = True,
                other_links = mount_links,
                clean_existing = False,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        gui.DisplayLoadingWindow(
            title_text = "Creating game prefix",
            message_text = "Creating game prefix\n%s\n%s" % (game_info.get_name(), game_info.get_platform()),
            failure_text = "Unable to create game prefix",
            image_file = game_info.get_boxfront_asset(),
            run_func = CreateGamePrefix)

        # Get launch info
        launch_cmd = []

        # Dos installers
        if game_info.does_store_setup_have_dos_installers():
            selected_program = GetSelectedLaunchProgram(
                game_info = game_info,
                base_dir = launch_options.get_prefix_dos_c_drive(),
                default_cwd = launch_options.get_prefix_dos_c_drive())
            if selected_program:
                launch_cmd = GetDosLaunchCommand(
                    options = launch_options,
                    start_program = selected_program.get_cmd(),
                    start_letter = "c",
                    start_offset = selected_program.get_cwd(),
                    fullscreen = fullscreen)

        # Win31 installers
        elif game_info.does_store_setup_have_win31_installers():
            selected_program = GetSelectedLaunchProgram(
                game_info = game_info,
                base_dir = launch_options.get_prefix_dos_c_drive(),
                default_cwd = launch_options.get_prefix_dos_c_drive())
            if selected_program:
                launch_cmd = GetWin31LaunchCommand(
                    options = launch_options,
                    start_program = selected_program.get_cmd(),
                    start_letter = "c",
                    start_offset = selected_program.get_cwd(),
                    fullscreen = fullscreen)

        # Scumm installers
        elif game_info.does_store_setup_have_scumm_installers():
            launch_cmd = GetScummLaunchCommand(
                options = launch_options,
                fullscreen = fullscreen)

        # Regular installers
        else:
            selected_program = GetSelectedLaunchProgram(
                game_info = game_info,
                base_dir = launch_options.get_prefix_c_drive_real(),
                default_cwd = game_info.get_general_save_dir())
            if selected_program:
                launch_cmd = [selected_program.get_cmd()] + launch_program.get_args()
                blocking_processes = sandbox.GetBlockingProcesses(
                    options = launch_options,
                    initial_processes = [command.GetStarterCommand(selected_program.get_cmd())])
                launch_options.set_force_prefix(True)
                launch_options.set_cwd(os.path.expanduser("~"))
                launch_options.set_prefix_cwd(selected_program.get_cwd())
                launch_options.set_lnk_base_path(game_info.get_local_cache_dir())
                launch_options.set_blocking_processes(blocking_processes)

        # Check launch command
        if len(launch_cmd):

            # Launch game
            command.RunGameCommand(
                game_info = game_info,
                cmd = launch_cmd,
                options = launch_options,
                capture_type = capture_type,
                verbose = verbose)

            # Restore default screen resolution
            display.RestoreDefaultScreenResolution(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Should be successful
        return True
