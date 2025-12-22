# Imports
import os, os.path
import os.path
import sys

# Local imports
import config
import system
import environment
import logger
import command
import programs
import release
import sandbox
import emulatorbase
import computer
import gui
import ini

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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

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
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DosBoxX")
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
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ScummVM")
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
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DosBoxX")
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
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ScummVM")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("DosBoxX", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("DosBoxX", "windows"),
                install_name = "DosBoxX",
                install_dir = programs.GetProgramInstallDir("DosBoxX", "windows"),
                search_file = "dosbox-x.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DosBoxX")
                return False
        if programs.ShouldProgramBeInstalled("ScummVM", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("ScummVM", "windows"),
                install_name = "ScummVM",
                install_dir = programs.GetProgramInstallDir("ScummVM", "windows"),
                search_file = "scummvm.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ScummVM")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("DosBoxX", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("DosBoxX", "linux"),
                install_name = "DosBoxX",
                install_dir = programs.GetProgramInstallDir("DosBoxX", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DosBoxX")
                return False
        if programs.ShouldProgramBeInstalled("ScummVM", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("ScummVM", "linux"),
                install_name = "ScummVM",
                install_dir = programs.GetProgramInstallDir("ScummVM", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ScummVM")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = system.JoinPaths(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DosBoxX/ScummVM config files")
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

        # Launch game
        return computer.LaunchComputerGame(
            game_info = game_info,
            capture_type = capture_type,
            capture_file = capture_file,
            fullscreen = fullscreen,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
