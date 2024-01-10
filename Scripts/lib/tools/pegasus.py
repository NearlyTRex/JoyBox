# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import release
import programs
import environment
import toolbase

# Config files
config_files = {}
config_file_general = """
general.theme: themes/PegasusThemeGrid/
general.verify-files: false
general.input-mouse-support: true
general.fullscreen: true
providers.steam.enabled: false
providers.gog.enabled: false
providers.es2.enabled: false
providers.launchbox.enabled: false
providers.logiqx.enabled: false
providers.playnite.enabled: false
providers.skraper.enabled: false
keys.menu: F1,GamepadStart
keys.page-down: PgDown,GamepadR2
keys.prev-page: Q,A,GamepadL1
keys.next-page: E,D,GamepadR1
keys.filters: F,GamepadY
keys.details: I,GamepadX
keys.cancel: Esc,Backspace,GamepadB
keys.page-up: PgUp,GamepadL2
keys.accept: Return,Enter,GamepadA
"""
config_files["Pegasus/windows/portable.txt"] = ""
config_files["Pegasus/windows/config/game_dirs.txt"] = ""
config_files["Pegasus/windows/config/settings.txt"] = config_file_general
config_files["Pegasus/linux/portable.txt"] = ""
config_files["Pegasus/linux/config/game_dirs.txt"] = ""
config_files["Pegasus/linux/config/settings.txt"] = config_file_general

# Pegasus tool
class Pegasus(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Pegasus"

    # Get config
    def GetConfig(self):
        return {
            "Pegasus": {
                "program": {
                    "windows": "Pegasus/windows/pegasus-fe.exe",
                    "linux": "Pegasus/linux/pegasus-fe"
                },
                "themes_dir": {
                    "windows": "Pegasus/windows/config/themes",
                    "linux": "Pegasus/linux/config/themes"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Pegasus", "windows"):
            success = release.DownloadLatestGithubRelease(
                github_user = "mmatyas",
                github_repo = "pegasus-frontend",
                starts_with = "pegasus-fe",
                ends_with = "win-mingw-static.zip",
                search_file = "pegasus-fe.exe",
                install_name = "Pegasus",
                install_dir = programs.GetProgramInstallDir("Pegasus", "windows"),
                install_files = ["pegasus-fe.exe"],
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Pegasus")
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PegasusThemeGrid",
                output_dir = os.path.join(programs.GetToolPathConfigValue("Pegasus", "themes_dir", "windows"), "PegasusThemeGrid"),
                clean_first = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Pegasus theme")

        # Download linux program
        if programs.ShouldProgramBeInstalled("Pegasus", "linux"):
            success = release.DownloadLatestGithubRelease(
                github_user = "mmatyas",
                github_repo = "pegasus-frontend",
                starts_with = "pegasus-fe",
                ends_with = "x11-static.zip",
                search_file = "pegasus-fe",
                install_name = "Pegasus",
                install_dir = programs.GetProgramInstallDir("Pegasus", "linux"),
                install_files = ["pegasus-fe"],
                chmod_files = [
                    {
                        "file": "pegasus-fe",
                        "perms": 755
                    }
                ],
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Pegasus")
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PegasusThemeGrid",
                output_dir = os.path.join(programs.GetToolPathConfigValue("Pegasus", "themes_dir", "linux"), "PegasusThemeGrid"),
                clean_first = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Pegasus theme")

        # Generate game dirs
        game_dirs = []
        for pegasus_file in system.BuildFileListByExtensions(environment.GetPegasusMetadataRootDir(), extensions = [".txt"]):
            if pegasus_file.endswith("metadata.pegasus.txt"):
                game_dirs.append(system.GetFilenameDirectory(pegasus_file))

        # Update game dir files
        config_files["Pegasus/windows/config/game_dirs.txt"] = "\n".join(game_dirs)
        config_files["Pegasus/linux/config/game_dirs.txt"] = "\n".join(game_dirs)

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetToolsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Pegasus config files")
