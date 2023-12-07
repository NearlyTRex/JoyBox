# Imports
import os, os.path
import sys
import getpass

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import command
import sandbox
import environment
import system
import archive
import network
import programs
import metadata

# Important Note:
# The following tools/emulators need periodic checks to get the latest
# Likely because their git-master doesn't build or the download link is not automatic
# Try to make these automatic if possible in the future
#
# Tools:
# - ExifTool
#
# Emulators
# - BasiliskII (windows)
# - BigPEmu (windows)
# - FS-UAE (linux)
# - PPSSPP (windows)

# These are tools to try to get native linux builds for in the future
# Or find a way to reduce the need for these
# - MameToolsChdman
# - NirCmd
# - PSVStrip
# - Wad2Bin
# - XCICutter

# Check requirements
def CheckRequirements():

    # Check python version
    if sys.version_info < config.minimum_python_version:
        print("Minimum required python version is %s.%s.%s" % config.minimum_python_version)
        print("Please upgrade your python version")
        sys.exit(1)

    # Check operating system
    is_windows = environment.IsWindowsPlatform()
    is_linux = environment.IsLinuxPlatform()
    if is_windows == False and is_linux == False:
        print("Only windows and linux are supported right now")
        sys.exit(1)

    # Check symlink support
    if not environment.AreSymlinksSupported():
        print("Symlinks are required, please enable them for your system")
        sys.exit(1)

    # Check system tools
    has_system_tools = environment.AreSystemToolsInstalled()
    if has_system_tools == False:
        print("System tools are required, please install them and make sure they are in the path")
        print("These include: %s" % ", ".join(environment.GetSystemTools()))
        sys.exit(1)

    # Check wine
    has_wine = sandbox.IsWineInstalled()
    if is_linux and has_wine == False:
        print("Wine (including winetricks) is required for linux environments, please install it and make sure it is in the path")
        sys.exit(1)

    # Check sandboxie
    has_sandboxie = sandbox.IsSandboxieInstalled()
    if is_windows and has_sandboxie == False:
        print("Sandboxie is required for windows environments, please install it and make sure it is in the path")
        sys.exit(1)

# Write required environment variables
def WriteRequiredEnvironmentVariables():
    environment.ClearEnvironmentVariables(verbose = config.default_flag_verbose, exit_on_failure = config.default_flag_exit_on_failure)
    environment.SetEnvironmentVariables(verbose = config.default_flag_verbose, exit_on_failure = config.default_flag_exit_on_failure)
    environment.SetEnvironmentPath(verbose = config.default_flag_verbose, exit_on_failure = config.default_flag_exit_on_failure)

# Install required python environment
def InstallRequiredPythonEnvironment():
    environment.SetupPythonEnvironment(verbose = config.default_flag_verbose)

# Install required python modules
def InstallRequiredPythonModules():
    environment.InstallPythonModules(
        modules = environment.GetRequiredPythonModules(),
        verbose = config.default_flag_verbose)

# Install required system packages
def InstallRequiredSystemPackages():
    environment.InstallSystemPackages(
        packages = environment.GetRequiredSystemPackages(),
        verbose = config.default_flag_verbose)

# Mount required network shares
def MountRequiredNetworkShares():

    # Storage share
    network.MountNetworkShare(
        mount_dir = environment.GetStorageRootDir(),
        base_location = environment.GetNetworkShareBaseLocation(),
        network_share = environment.GetNetworkShareStorageFolder(),
        username = environment.GetNetworkShareUsername(),
        password = environment.GetNetworkSharePassword(),
        verbose = config.default_flag_verbose)

    # Remote cache share
    network.MountNetworkShare(
        mount_dir = environment.GetRemoteCacheRootDir(),
        base_location = environment.GetNetworkShareBaseLocation(),
        network_share = environment.GetNetworkShareCacheFolder(),
        username = environment.GetNetworkShareUsername(),
        password = environment.GetNetworkSharePassword(),
        verbose = config.default_flag_verbose)

# Download required tools
def DownloadRequiredTools(force_downloads = False):
    for tool in programs.GetTools():
        tool.Download(force_downloads)

# Download required emulators
def DownloadRequiredEmulators(force_downloads = False):
    for emulator in programs.GetEmulators():
        emulator.Download(force_downloads)

# Download required libraries
def DownloadRequiredLibraries(force_downloads = False):
    for library in programs.GetThirdPartyLibraries():
        library.Download(force_downloads)

# Setup required emulators
def SetupRequiredEmulators():
    for emulator in programs.GetEmulators():
        emulator.Setup()

# Setup required metadata assets
def SetupRequiredMetadataAssets():
    for game_category in metadata.GetMetadataCategories():
        for game_subcategory in metadata.GetMetadataSubcategories(game_category):
            for asset_type in config.asset_types_all:
                source_dir = environment.GetSyncedGameAssetDir(game_category, game_subcategory, asset_type)
                dest_dir = environment.GetPegasusMetadataAssetDir(game_category, game_subcategory, asset_type)
                system.RemoveSymlink(
                    symlink = dest_dir,
                    verbose = config.default_flag_verbose,
                    exit_on_failure = config.default_flag_exit_on_failure)
                system.CreateSymlink(
                    src = source_dir,
                    dest = dest_dir,
                    cwd = system.GetDirectoryParent(dest_dir),
                    verbose = config.default_flag_verbose,
                    exit_on_failure = config.default_flag_exit_on_failure)
