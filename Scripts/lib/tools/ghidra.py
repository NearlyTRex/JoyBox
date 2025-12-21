# Imports
import os, os.path
import sys

# Local imports
import config
import system
import release
import programs
import environment
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
    "pcode_patching.patch",
]

# Ghidra tool
class Ghidra(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Ghidra"

    # Get config
    def GetConfig(self):
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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Build library from source
        if programs.ShouldLibraryBeInstalled("Ghidra/lib"):

            # Get build command
            if environment.IsWindowsPlatform():
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
                patch_content = system.ReadTextFile(patch_path, exit_on_failure = setup_params.exit_on_failure)
                if patch_content is None:
                    system.LogError("Could not read Ghidra patch file: %s" % patch_filename)
                    return False
                source_patches.append({
                    "file": patch_filename,
                    "content": patch_content,
                })

            # Build Ghidra from source
            success = release.BuildBinaryFromSource(
                release_url = "https://github.com/NearlyTRex/Ghidra.git",
                output_file = ".zip",
                output_dir = "build/dist",
                search_file = "ghidraRun",
                install_name = "Ghidra",
                install_dir = programs.GetLibraryInstallDir("Ghidra", "lib"),
                backups_dir = programs.GetLibraryBackupDir("Ghidra", "lib"),
                build_cmd = build_cmd,
                source_patches = source_patches,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Ghidra")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("Ghidra/lib"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("Ghidra", "lib"),
                install_name = "Ghidra",
                install_dir = programs.GetLibraryInstallDir("Ghidra", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Ghidra")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for dest_path, src_filename in config_files.items():
            src_path = os.path.join(extra_files_dir, src_filename)
            contents = system.ReadTextFile(src_path, exit_on_failure = setup_params.exit_on_failure)
            if contents is None:
                system.LogError("Could not read Ghidra config file: %s" % src_filename)
                return False
            success = system.TouchFile(
                src = system.JoinPaths(environment.GetToolsRootDir(), dest_path),
                contents = contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not create Ghidra config files")
                return False
        return True
