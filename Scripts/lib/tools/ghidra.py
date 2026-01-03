# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import paths
import release
import serialization
import programs
import environment
import fileops
import toolbase

# Extra files directory
extra_files_dir = os.path.join(os.path.dirname(__file__), "files", "ghidra")

# Config files
config_files = {
    "Ghidra/lib/Ghidra/Processors/x86/data/languages/x86watcom.cspec": "x86watcom.cspec",
    "Ghidra/lib/Ghidra/Processors/x86/data/languages/x86watcom.ldefs": "x86watcom.ldefs",
    "Ghidra/lib/Ghidra/Processors/x86/data/patterns/patternconstraints.xml": "patternconstraints.xml",
    "Ghidra/lib/Ghidra/Processors/x86/data/patterns/x86watcomcpp_patterns.xml": "x86watcomcpp_patterns.xml",
}

# Patch files
patch_files = [
    "ghidra.patch"
]

# Ghidra tool
class Ghidra(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Ghidra"

    # Get config
    def get_config(self):
        return {
            "Ghidra": {
                "program": {
                    "windows": "Ghidra/lib/ghidraRun.bat",
                    "linux": "Ghidra/lib/ghidraRun"
                },
                "package_dir": "Ghidra/lib/Ghidra/Features/PyGhidra/pypkg/src",
                "package_name": "pyghidra"
            },
            "GhidraHeadless": {
                "program": {
                    "windows": "Ghidra/lib/support/analyzeHeadless.bat",
                    "linux": "Ghidra/lib/support/analyzeHeadless"
                }
            },
            "GhidraSleigh": {
                "program": {
                    "windows": "Ghidra/lib/support/sleigh.bat",
                    "linux": "Ghidra/lib/support/sleigh"
                }
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Build library from source
        if programs.should_library_be_installed("Ghidra/lib"):

            # Get build command
            if environment.is_windows_platform():
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

            # Load patch files
            source_patches = []
            for patch_filename in patch_files:
                patch_path = os.path.join(extra_files_dir, patch_filename)
                patch_content = serialization.read_text_file(patch_path, exit_on_failure = setup_params.exit_on_failure)
                if patch_content is None:
                    logger.log_error("Could not read Ghidra patch file: %s" % patch_filename)
                    return False
                source_patches.append({
                    "file": patch_filename,
                    "content": patch_content,
                })

            # Build Ghidra from source
            success = release.build_binary_from_source(
                release_url = "https://github.com/NearlyTRex/Ghidra.git",
                output_file = ".zip",
                output_dir = "build/dist",
                search_file = "ghidraRun",
                install_name = "Ghidra",
                install_dir = programs.get_library_install_dir("Ghidra", "lib"),
                backups_dir = programs.get_library_backup_dir("Ghidra", "lib"),
                build_cmd = build_cmd,
                source_patches = source_patches,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ghidra")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("Ghidra/lib"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("Ghidra", "lib"),
                install_name = "Ghidra",
                install_dir = programs.get_library_install_dir("Ghidra", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ghidra")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for dest_path, src_filename in config_files.items():
            src_path = os.path.join(extra_files_dir, src_filename)
            contents = serialization.read_text_file(src_path, exit_on_failure = setup_params.exit_on_failure)
            if contents is None:
                logger.log_error("Could not read Ghidra config file: %s" % src_filename)
                return False
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
