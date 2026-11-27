# Imports

# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import release
from joybox import sourcebuild
from joybox import programs
from joybox import environment
from joybox import fileops
from joybox import toolbase
from joybox import platform_info


# Ghidra tool
class Ghidra(toolbase.ToolBase):

    NAME = "Ghidra"

    # Build Ghidra with Gradle from the dev-testing branch of the NearlyTRex/Ghidra fork
    # and install the dist zip into its lib dir
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Build library from source
        if programs.should_library_be_installed("Ghidra/lib"):

            # Get build command
            if platform_info.is_windows_platform():
                build_cmd = [
                    "gradlew.bat", "-I", "gradle/support/fetchDependencies.gradle",
                    "&&",
                    "gradlew.bat", "buildGhidra", "-x", "createJavadocs", "-x", "createJsondocs", "-x", "test"
                ]
            else:
                build_cmd = [
                    "./gradlew", "-I", "gradle/support/fetchDependencies.gradle",
                    "&&",
                    "./gradlew", "buildGhidra", "-x", "createJavadocs", "-x", "createJsondocs", "-x", "test"
                ]

            # Build Ghidra from source
            success = sourcebuild.build_binary_from_source(
                release_url = "https://github.com/NearlyTRex/Ghidra.git",
                release_branch = "dev-testing",
                output_file = ".zip",
                output_dir = "build/dist",
                search_file = "ghidraRun",
                install_name = "Ghidra",
                install_dir = programs.get_library_install_dir("Ghidra", "lib"),
                backups_dir = programs.get_library_backup_dir("Ghidra", "lib"),
                build_cmd = build_cmd,
                locker_type = setup_params.locker_type,
                skip_autobackup = setup_params.skip_autobackup,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ghidra")
                return False
        return True

    # Install the library from the build stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("Ghidra/lib"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("Ghidra", "lib"),
                install_name = "Ghidra",
                install_dir = programs.get_library_install_dir("Ghidra", "lib"),
                search_file = "ghidraRun",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ghidra")
                return False
        return True

    # Write its config files under the tools root
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for dest_path, contents in self.get_config_files().items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_tools_root_dir(), dest_path),
                contents = contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not create Ghidra config files")
                return False
        return True
