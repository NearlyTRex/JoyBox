# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import programs
from joybox import release
from joybox import sourcebuild
from joybox import emulatorbase
from joybox import computer
from joybox import platform_info


# Computer emulator
class Computer(emulatorbase.EmulatorBase):

    NAME = "Computer"

    # Sandboxie on Windows, Wine elsewhere, since computer games save inside their sandbox
    def get_save_type(self):
        if platform_info.is_windows_platform():
            return config.SaveType.SANDBOXIE
        return config.SaveType.WINE

    # Always None: computer games have no single emulator config file
    def get_config_file(self, emulator_platform = None):
        return None

    # Always None: saves live in each game's sandbox, not an emulator dir
    def get_save_base_dir(self, emulator_platform = None):
        return None

    # Always None: there are no per-platform save subdirs
    def get_save_sub_dirs(self, emulator_platform = None):
        return None

    # Always None: saves live in each game's sandbox, not an emulator dir
    def get_save_dir(self, game_platform, emulator_platform = None):
        return None

    # Windows DOSBox-X from its GitHub release and ScummVM from scummvm.org;
    # Linux AppImages of both built from the NearlyTRex DosboxX and ScummVM forks
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows programs
        if programs.should_program_be_installed("DosBoxX", "windows"):
            success = release.download_github_release(
                github_user = "joncampbell123",
                github_repo = "dosbox-x",
                starts_with = "dosbox-x-mingw64",
                ends_with = ".zip",
                search_file = "dosbox-x.exe",
                install_name = "DosBoxX",
                install_dir = programs.get_program_install_dir("DosBoxX", "windows"),
                backups_dir = programs.get_program_backup_dir("DosBoxX", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DosBoxX")
                return False
        if programs.should_program_be_installed("ScummVM", "windows"):
            success = release.download_webpage_release(
                webpage_url = "https://www.scummvm.org/downloads",
                webpage_base_url = "https://www.scummvm.org",
                starts_with = "https://downloads.scummvm.org/frs/scummvm/",
                ends_with = "win32-x86_64.zip",
                search_file = "scummvm.exe",
                install_name = "ScummVM",
                install_dir = programs.get_program_install_dir("ScummVM", "windows"),
                backups_dir = programs.get_program_backup_dir("ScummVM", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ScummVM")
                return False

        # Build linux programs
        if programs.should_program_be_installed("DosBoxX", "linux"):
            success = sourcebuild.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/DosboxX.git",
                output_file = "DOSBox-X-x86_64.AppImage",
                install_name = "DosBoxX",
                install_dir = programs.get_program_install_dir("DosBoxX", "linux"),
                backups_dir = programs.get_program_backup_dir("DosBoxX", "linux"),
                build_cmd = [
                    "./build-sdl2"
                ],
                internal_copies = [
                    {"from": "Source/DosboxX/src/dosbox-x", "to": "AppImage/usr/bin/dosbox-x"},
                    {"from": "Source/DosboxX/CHANGELOG", "to": "AppImage/usr/share/dosbox-x/CHANGELOG"},
                    {"from": "Source/DosboxX/dosbox-x.reference.conf", "to": "AppImage/usr/share/dosbox-x/dosbox-x.reference.conf"},
                    {"from": "Source/DosboxX/dosbox-x.reference.full.conf", "to": "AppImage/usr/share/dosbox-x/dosbox-x.reference.full.conf"},
                    {"from": "Source/DosboxX/contrib/fonts/FREECG98.BMP", "to": "AppImage/usr/share/dosbox-x/FREECG98.BMP"},
                    {"from": "Source/DosboxX/contrib/fonts/Nouveau_IBM.ttf", "to": "AppImage/usr/share/dosbox-x/Nouveau_IBM.ttf"},
                    {"from": "Source/DosboxX/contrib/fonts/SarasaGothicFixed.ttf", "to": "AppImage/usr/share/dosbox-x/SarasaGothicFixed.ttf"},
                    {"from": "Source/DosboxX/contrib/fonts/wqy_11pt.bdf", "to": "AppImage/usr/share/dosbox-x/wqy_11pt.bdf"},
                    {"from": "Source/DosboxX/contrib/fonts/wqy_12pt.bdf", "to": "AppImage/usr/share/dosbox-x/wqy_12pt.bdf"},
                    {"from": "Source/DosboxX/contrib/windows/installer/drivez_readme.txt", "to": "AppImage/usr/share/dosbox-x/drivez/readme.txt"},
                    {"from": "Source/DosboxX/contrib/glshaders", "to": "AppImage/usr/share/dosbox-x/glshaders"},
                    {"from": "Source/DosboxX/contrib/translations/de/de_DE.lng", "to": "AppImage/usr/share/dosbox-x/languages/de_DE.lng"},
                    {"from": "Source/DosboxX/contrib/translations/en/en_US.lng", "to": "AppImage/usr/share/dosbox-x/languages/en_US.lng"},
                    {"from": "Source/DosboxX/contrib/translations/es/es_ES.lng", "to": "AppImage/usr/share/dosbox-x/languages/es_ES.lng"},
                    {"from": "Source/DosboxX/contrib/translations/fr/fr_FR.lng", "to": "AppImage/usr/share/dosbox-x/languages/fr_FR.lng"},
                    {"from": "Source/DosboxX/contrib/translations/ja/ja_JP.lng", "to": "AppImage/usr/share/dosbox-x/languages/ja_JP.lng"},
                    {"from": "Source/DosboxX/contrib/translations/ko/ko_KR.lng", "to": "AppImage/usr/share/dosbox-x/languages/ko_KR.lng"},
                    {"from": "Source/DosboxX/contrib/translations/nl/nl_NL.lng", "to": "AppImage/usr/share/dosbox-x/languages/nl_NL.lng"},
                    {"from": "Source/DosboxX/contrib/translations/pt/pt_BR.lng", "to": "AppImage/usr/share/dosbox-x/languages/pt_BR.lng"},
                    {"from": "Source/DosboxX/contrib/translations/tr/tr_TR.lng", "to": "AppImage/usr/share/dosbox-x/languages/tr_TR.lng"},
                    {"from": "Source/DosboxX/contrib/translations/zh/zh_CN.lng", "to": "AppImage/usr/share/dosbox-x/languages/zh_CN.lng"},
                    {"from": "Source/DosboxX/contrib/translations/zh/zh_TW.lng", "to": "AppImage/usr/share/dosbox-x/languages/zh_TW.lng"},
                    {"from": "Source/DosboxX/contrib/linux/com.dosbox_x.DOSBox-X.desktop", "to": "AppImage/app.desktop"},
                    {"from": "Source/DosboxX/contrib/icons/dosbox-x.png", "to": "AppImage/dosbox-x.png"}
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
        if programs.should_program_be_installed("ScummVM", "linux"):
            success = sourcebuild.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/ScummVM.git",
                output_file = "ScummVM-x86_64.AppImage",
                install_name = "ScummVM",
                install_dir = programs.get_program_install_dir("ScummVM", "linux"),
                backups_dir = programs.get_program_backup_dir("ScummVM", "linux"),
                build_cmd = [
                    "./configure",
                    "&&",
                    "make", "-j10"
                ],
                internal_copies = [
                    {"from": "Source/ScummVM/scummvm", "to": "AppImage/usr/bin/scummvm"},
                    {"from": "Source/ScummVM/gui/themes/*.dat", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/ScummVM/gui/themes/*.zip", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/ScummVM/dists/networking/wwwroot.zip", "to": "AppImage/usr/local/share/scummvm/wwwroot.zip"},
                    {"from": "Source/ScummVM/dists/engine-data/*.dat", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/ScummVM/dists/engine-data/*.zip", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/ScummVM/dists/engine-data/*.tbl", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/ScummVM/dists/engine-data/*.cpt", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/ScummVM/dists/engine-data/*.lab", "to": "AppImage/usr/local/share/scummvm"},
                    {"from": "Source/ScummVM/dists/pred.dic", "to": "AppImage/usr/local/share/scummvm/pred.dic"},
                    {"from": "Source/ScummVM/engines/grim/shaders/*.fragment", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/ScummVM/engines/grim/shaders/*.vertex", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/ScummVM/engines/stark/shaders/*.fragment", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/ScummVM/engines/stark/shaders/*.vertex", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/ScummVM/engines/wintermute/base/gfx/opengl/shaders/*.fragment", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/ScummVM/engines/wintermute/base/gfx/opengl/shaders/*.vertex", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/ScummVM/engines/freescape/shaders/*.fragment", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/ScummVM/engines/freescape/shaders/*.vertex", "to": "AppImage/usr/local/share/scummvm/shaders"},
                    {"from": "Source/ScummVM/dists/org.scummvm.scummvm.desktop", "to": "AppImage/org.scummvm.scummvm.desktop"},
                    {"from": "Source/ScummVM/icons/scummvm.svg", "to": "AppImage/org.scummvm.scummvm.svg"}
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

    # Install DOSBox-X and ScummVM for Windows and Linux from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("DosBoxX", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("DosBoxX", "windows"),
                install_name = "DosBoxX",
                install_dir = programs.get_program_install_dir("DosBoxX", "windows"),
                search_file = "dosbox-x.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DosBoxX")
                return False
        if programs.should_program_be_installed("ScummVM", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("ScummVM", "windows"),
                install_name = "ScummVM",
                install_dir = programs.get_program_install_dir("ScummVM", "windows"),
                search_file = "scummvm.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ScummVM")
                return False

        # Setup linux program
        if programs.should_program_be_installed("DosBoxX", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("DosBoxX", "linux"),
                install_name = "DosBoxX",
                install_dir = programs.get_program_install_dir("DosBoxX", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DosBoxX")
                return False
        if programs.should_program_be_installed("ScummVM", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("ScummVM", "linux"),
                install_name = "ScummVM",
                install_dir = programs.get_program_install_dir("ScummVM", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ScummVM")
                return False
        return True

    # Write the DOSBox-X and ScummVM config files under the emulators root
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in self.get_config_files().items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_emulators_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DosBoxX/ScummVM config files")
                return False
        return True

    # Hand the game to the computer launcher, which runs it inside a Wine prefix on Linux or Sandboxie on Windows
    def launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Launch game
        return computer.launch_computer_game(
            game_info = game_info,
            capture_type = capture_type,
            capture_file = capture_file,
            fullscreen = fullscreen,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
