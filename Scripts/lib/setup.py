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
import tools
import emulators
import programs
import metadata

# Important Note:
# The following emulators need periodic checks to get the latest
# Likely because their git-master doesn't build or the download link is not automatic
# Try to make these automatic if possible in the future
# - Ares (linux)
# - BigPEmu (windows)
# - PPSSPP (windows)

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

# Determine if program should be installed
def ShouldProgramBeInstalled(config, base_dir, app_name, platform):
    app_program = programs.GetProgram(config, base_dir, app_name, platform)
    if not app_program:
        return False
    if platform == "linux" and not environment.IsLinuxPlatform():
        return False
    if os.path.exists(app_program):
        return False
    return True

# Determine if library should be installed
def ShouldLibraryBeInstalled(base_dir):
    if not system.IsDirectoryEmpty(base_dir):
        return False
    return True

# Download required tools
def DownloadRequiredTools(force_downloads = False):

    # 3DSRomTool
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "3DSRomTool", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "NearlyTRex",
            github_repo = "3DSRomTool",
            starts_with = "rom_tool",
            ends_with = ".zip",
            search_file = "rom_tool.exe",
            install_name = "3DSRomTool",
            install_dir = os.path.join(tools.GetBaseDirectory(), "3DSRomTool", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["rom_tool.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "3DSRomTool", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/NearlyTRex/3DSRomTool.git",
            output_name = "3DSRomTool",
            output_dir = os.path.join(tools.GetBaseDirectory(), "3DSRomTool", "linux"),
            build_cmd = [
                "cd", "rom_tool",
                "&&",
                "make", "-j", "4"
            ],
            internal_copies = [
                {"from": "Source/rom_tool/rom_tool", "to": "AppImage/usr/bin/rom_tool"},
                {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/rom_tool", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # 7-Zip
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "7-Zip", "windows"):
        network.DownloadLatestWebpageRelease(
            webpage_url = "https://www.7-zip.org/download.html",
            starts_with = "https://www.7-zip.org/a/7z",
            ends_with = "-x64.exe",
            search_file = "7z.exe",
            install_name = "7-Zip",
            install_dir = os.path.join(tools.GetBaseDirectory(), "7-Zip", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            installer_type = config.installer_format_nsis,
            is_installer = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # 7-Zip-Standalone
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "7-Zip-Standalone", "windows"):
        network.DownloadLatestWebpageRelease(
            webpage_url = "https://www.7-zip.org/download.html",
            starts_with = "https://www.7-zip.org/a/7z",
            ends_with = "-extra.7z",
            search_file = "x64/7za.exe",
            install_name = "7-Zip",
            install_dir = os.path.join(tools.GetBaseDirectory(), "7-Zip", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["7za.dll", "7za.exe", "7zxa.dll"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # AppImageTool
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "AppImageTool", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "AppImage",
            github_repo = "AppImageKit",
            starts_with = "appimagetool-x86_64",
            ends_with = ".AppImage",
            search_file = "AppImageTool.AppImage",
            install_name = "AppImageTool",
            install_dir = os.path.join(tools.GetBaseDirectory(), "AppImageTool", "linux"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # CDecrypt
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "CDecrypt", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "VitaSmith",
            github_repo = "cdecrypt",
            starts_with = "cdecrypt",
            ends_with = ".zip",
            search_file = "cdecrypt.exe",
            install_name = "CDecrypt",
            install_dir = os.path.join(tools.GetBaseDirectory(), "CDecrypt", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["cdecrypt.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "CDecrypt", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/NearlyTRex/CDecrypt.git",
            output_name = "CDecrypt",
            output_dir = os.path.join(tools.GetBaseDirectory(), "CDecrypt", "linux"),
            build_cmd = [
                "make", "-j", "4"
            ],
            internal_copies = [
                {"from": "Source/cdecrypt", "to": "AppImage/usr/bin/cdecrypt"},
                {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/cdecrypt", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # CtrTool
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "CtrTool", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "3DSGuy",
            github_repo = "Project_CTR",
            starts_with = "ctrtool",
            ends_with = "win_x64.zip",
            search_file = "ctrtool.exe",
            install_name = "CtrTool",
            install_dir = os.path.join(tools.GetBaseDirectory(), "CtrTool", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["ctrtool.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # CtrToolMakeRom
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "CtrToolMakeRom", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "3DSGuy",
            github_repo = "Project_CTR",
            starts_with = "makerom",
            ends_with = "win_x86_64.zip",
            search_file = "makerom.exe",
            install_name = "CtrTool",
            install_dir = os.path.join(tools.GetBaseDirectory(), "CtrTool", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["makerom.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # ExifTool
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "ExifTool", "windows"):
        network.DownloadGeneralRelease(
            archive_url = "https://exiftool.org/exiftool-12.70.zip",
            search_file = "exiftool(-k).exe",
            install_name = "ExifTool",
            install_dir = os.path.join(tools.GetBaseDirectory(), "ExifTool", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            rename_files = [
                {
                    "from": "exiftool(-k).exe",
                    "to": "exiftool.exe"
                }
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "ExifTool", "linux"):
        network.DownloadGeneralRelease(
            archive_url = "https://exiftool.org/Image-ExifTool-12.70.tar.gz",
            search_file = "exiftool",
            install_name = "ExifTool",
            install_dir = os.path.join(tools.GetBaseDirectory(), "ExifTool", "linux"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # ExtractXIso
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "ExtractXIso", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "XboxDev",
            github_repo = "extract-xiso",
            starts_with = "extract-xiso",
            ends_with = "win32-release.zip",
            search_file = "extract-xiso.exe",
            install_name = "ExtractXIso",
            install_dir = os.path.join(tools.GetBaseDirectory(), "ExtractXIso", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["extract-xiso.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # FFMpeg
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "FFMpeg", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "BtbN",
            github_repo = "FFmpeg-Builds",
            starts_with = "ffmpeg-master-latest",
            ends_with = "win64-gpl.zip",
            search_file = "ffmpeg.exe",
            install_name = "FFMpeg",
            install_dir = os.path.join(tools.GetBaseDirectory(), "FFMpeg", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["ffmpeg.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "FFMpeg", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "BtbN",
            github_repo = "FFmpeg-Builds",
            starts_with = "ffmpeg-master-latest",
            ends_with = "linux64-gpl.tar.xz",
            search_file = "ffmpeg",
            install_name = "FFMpeg",
            install_dir = os.path.join(tools.GetBaseDirectory(), "FFMpeg", "linux"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["ffmpeg"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # GeckoDriver
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "GeckoDriver", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "mozilla",
            github_repo = "geckodriver",
            starts_with = "geckodriver",
            ends_with = "win32.zip",
            search_file = "geckodriver.exe",
            install_name = "GeckoDriver",
            install_dir = os.path.join(tools.GetBaseDirectory(), "GeckoDriver", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["geckodriver.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "GeckoDriver", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "mozilla",
            github_repo = "geckodriver",
            starts_with = "geckodriver",
            ends_with = "linux64.tar.gz",
            search_file = "geckodriver",
            install_name = "GeckoDriver",
            install_dir = os.path.join(tools.GetBaseDirectory(), "GeckoDriver", "linux"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["geckodriver"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # HacTool
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "HacTool", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "SciresM",
            github_repo = "hactool",
            starts_with = "hactool",
            ends_with = "win.zip",
            search_file = "hactool.exe",
            install_name = "HacTool",
            install_dir = os.path.join(tools.GetBaseDirectory(), "HacTool", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["hactool.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "HacTool", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/SciresM/hactool.git",
            output_name = "HacTool",
            output_dir = os.path.join(tools.GetBaseDirectory(), "HacTool", "linux"),
            build_cmd = [
                "cp", "config.mk.template", "config.mk",
                "&&",
                "make", "-j", "4"
            ],
            internal_copies = [
                {"from": "Source/hactool", "to": "AppImage/usr/bin/hactool"},
                {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/hactool", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Ludusavi
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "Ludusavi", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "mtkennerly",
            github_repo = "ludusavi",
            starts_with = "ludusavi",
            ends_with = "win64.zip",
            search_file = "ludusavi.exe",
            install_name = "Ludusavi",
            install_dir = os.path.join(tools.GetBaseDirectory(), "Ludusavi", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["ludusavi.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "Ludusavi", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "mtkennerly",
            github_repo = "ludusavi",
            starts_with = "ludusavi",
            ends_with = "linux.zip",
            search_file = "ludusavi",
            install_name = "Ludusavi",
            install_dir = os.path.join(tools.GetBaseDirectory(), "Ludusavi", "linux"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["ludusavi"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # MameToolsChdman
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "MameToolsChdman", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "mamedev",
            github_repo = "mame",
            starts_with = "mame",
            ends_with = "64bit.exe",
            search_file = "chdman.exe",
            install_name = "MameToolsChdman",
            install_dir = os.path.join(tools.GetBaseDirectory(), "MameTools", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["chdman.exe"],
            installer_type = config.installer_format_7zip,
            is_installer = False,
            is_archive = True,
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # NDecrypt
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "NDecrypt", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "SabreTools",
            github_repo = "NDecrypt",
            starts_with = "NDecrypt",
            ends_with = "win-x64.zip",
            search_file = "NDecrypt.exe",
            install_name = "NDecrypt",
            install_dir = os.path.join(tools.GetBaseDirectory(), "NDecrypt", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["NDecrypt.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "NDecrypt", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "SabreTools",
            github_repo = "NDecrypt",
            starts_with = "NDecrypt",
            ends_with = "linux-x64.zip",
            search_file = "NDecrypt",
            install_name = "NDecrypt",
            install_dir = os.path.join(tools.GetBaseDirectory(), "NDecrypt", "linux"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["NDecrypt"],
            chmod_files = [
                {
                    "file": "NDecrypt",
                    "perms": 755
                }
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # NirCmd
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "NirCmd", "windows"):
        network.DownloadGeneralRelease(
            archive_url = "https://www.nirsoft.net/utils/nircmd-x64.zip",
            search_file = "nircmdc.exe",
            install_name = "NirCmd",
            install_dir = os.path.join(tools.GetBaseDirectory(), "NirCmd", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Pegasus
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "Pegasus", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "mmatyas",
            github_repo = "pegasus-frontend",
            starts_with = "pegasus-fe",
            ends_with = "win-mingw-static.zip",
            search_file = "pegasus-fe.exe",
            install_name = "Pegasus",
            install_dir = os.path.join(tools.GetBaseDirectory(), "Pegasus", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["pegasus-fe.exe"],
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "Pegasus", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "mmatyas",
            github_repo = "pegasus-frontend",
            starts_with = "pegasus-fe",
            ends_with = "x11-static.zip",
            search_file = "pegasus-fe",
            install_name = "Pegasus",
            install_dir = os.path.join(tools.GetBaseDirectory(), "Pegasus", "linux"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["pegasus-fe"],
            chmod_files = [
                {
                    "file": "pegasus-fe",
                    "perms": 755
                }
            ],
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Pkg2AppImage
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "Pkg2AppImage", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "AppImageCommunity",
            github_repo = "pkg2appimage",
            starts_with = "pkg2appimage",
            ends_with = ".AppImage",
            search_file = "Pkg2AppImage.AppImage",
            install_name = "Pkg2AppImage",
            install_dir = os.path.join(tools.GetBaseDirectory(), "Pkg2AppImage", "linux"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # PS3Dec
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "PS3Dec", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "NearlyTRex",
            github_repo = "PS3Dec",
            starts_with = "PS3Dec",
            ends_with = ".zip",
            search_file = "PS3Dec.exe",
            install_name = "PS3Dec",
            install_dir = os.path.join(tools.GetBaseDirectory(), "PS3Dec", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["PS3Dec.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "PS3Dec", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/NearlyTRex/PS3Dec.git",
            output_name = "PS3Dec",
            output_dir = os.path.join(tools.GetBaseDirectory(), "PS3Dec", "linux"),
            build_cmd = [
                "cmake", "-G", "Ninja", "..",
                "&&",
                "ninja"
            ],
            build_dir = "Build",
            internal_copies = [
                {"from": "Source/Build/Release/PS3Dec", "to": "AppImage/usr/bin/PS3Dec"},
                {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/PS3Dec", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # PSVStrip
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "PSVStrip", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "Kippykip",
            github_repo = "PSVStrip",
            starts_with = "PSVStrip",
            ends_with = ".zip",
            search_file = "psvstrip.exe",
            install_name = "PSVStrip",
            install_dir = os.path.join(tools.GetBaseDirectory(), "PSVStrip", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["psvstrip.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # RClone
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "RClone", "windows"):
        network.DownloadGeneralRelease(
            archive_url = "https://downloads.rclone.org/rclone-current-windows-amd64.zip",
            search_file = "rclone.exe",
            install_name = "RClone",
            install_dir = os.path.join(tools.GetBaseDirectory(), "RClone", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "RClone", "linux"):
        network.DownloadGeneralRelease(
            archive_url = "https://downloads.rclone.org/rclone-current-linux-amd64.zip",
            search_file = "rclone",
            install_name = "RClone",
            install_dir = os.path.join(tools.GetBaseDirectory(), "RClone", "linux"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Sunshine
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "Sunshine", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "LizardByte",
            github_repo = "Sunshine",
            starts_with = "sunshine",
            ends_with = "windows.zip",
            search_file = "sunshine.exe",
            install_name = "Sunshine",
            install_dir = os.path.join(tools.GetBaseDirectory(), "Sunshine", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["sunshine.exe", "assets", "scripts", "tools"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "Sunshine", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "LizardByte",
            github_repo = "Sunshine",
            starts_with = "sunshine",
            ends_with = ".AppImage",
            search_file = "Sunshine.AppImage",
            install_name = "Sunshine",
            install_dir = os.path.join(tools.GetBaseDirectory(), "Sunshine", "linux"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Wad2Bin
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "Wad2Bin", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "DarkMatterCore",
            github_repo = "wad2bin",
            starts_with = "wad2bin",
            ends_with = ".exe",
            search_file = "wad2bin.exe",
            install_name = "Wad2Bin",
            install_dir = os.path.join(tools.GetBaseDirectory(), "Wad2Bin", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["wad2bin.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # XCICutter
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "XCICutter", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "Destiny1984",
            github_repo = "XCI-Cutter",
            starts_with = "XCI-Cutter",
            ends_with = ".exe",
            search_file = "XCI-Cutter.exe",
            install_name = "XCICutter",
            install_dir = os.path.join(tools.GetBaseDirectory(), "XCICutter", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["XCI-Cutter.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # XexTool
    if force_downloads or ShouldProgramBeInstalled(tools.GetConfig(), tools.GetBaseDirectory(), "XexTool", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "XboxChef",
            github_repo = "XexToolGUI",
            starts_with = "XeXGUI",
            ends_with = ".zip",
            search_file = "xextool.exe",
            install_name = "XexTool",
            install_dir = os.path.join(tools.GetBaseDirectory(), "XexTool", "windows"),
            prefix_dir = tools.GetPrefixDir(),
            prefix_name = tools.GetPrefixName(),
            install_files = ["xextool.exe"],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

# Download required emulators
def DownloadRequiredEmulators(force_downloads = False):

    # Ares
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Ares", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "ares-emulator",
            github_repo = "ares",
            starts_with = "ares",
            ends_with = "windows.zip",
            search_file = "ares.exe",
            install_name = "Ares",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Ares", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Ares", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/ares-emulator/ares.git",
            output_name = "Ares",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "Ares", "linux"),
            build_cmd = [
                "make", "-j4", "build=release"
            ],
            internal_copies = [
                {"from": "Source/desktop-ui/out/ares", "to": "AppImage/usr/bin/ares"},
                {"from": "Source/desktop-ui/resource/ares.desktop", "to": "AppImage/ares.desktop"},
                {"from": "Source/desktop-ui/resource/ares.png", "to": "AppImage/ares.svg"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/ares", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Atari800
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Atari800", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "atari800",
            github_repo = "atari800",
            starts_with = "atari800",
            ends_with = "win32-sdl.zip",
            search_file = "atari800.exe",
            install_name = "Atari800",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Atari800", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Atari800", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/atari800/atari800.git",
            output_name = "Atari800",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "Atari800", "linux"),
            build_cmd = [
                "./autogen.sh",
                "&&",
                "./configure",
                "&&",
                "make", "-j", "4"
            ],
            internal_copies = [
                {"from": "Source/act", "to": "AppImage/usr/bin"},
                {"from": "Source/src/atari800", "to": "AppImage/usr/bin/atari800"},
                {"from": "Source/debian/atari800.desktop", "to": "AppImage/atari800.desktop"},
                {"from": "Source/data/atari1.png", "to": "AppImage/atari800.png"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/atari800", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # BasiliskII
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "BasiliskII", "windows"):
        network.DownloadGeneralRelease(
            archive_url = "https://surfdrive.surf.nl/files/index.php/s/C7E6HIZKWuHHR1P/download",
            search_file = "BasiliskII.exe",
            install_name = "BasiliskII",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "BasiliskII", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "BasiliskII", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "Korkman",
            github_repo = "macemu-appimage-builder",
            starts_with = "BasiliskII-x86_64",
            ends_with = ".AppImage",
            search_file = "BasiliskII-x86_64.AppImage",
            install_name = "BasiliskII",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "BasiliskII", "linux"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # BigPEmu
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "BigPEmu", "windows"):
        network.DownloadGeneralRelease(
            archive_url = "https://www.richwhitehouse.com/jaguar/builds/BigPEmu_v1092.zip",
            search_file = "BigPEmu.exe",
            install_name = "BigPEmu",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "BigPEmu", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Cemu
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Cemu", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "cemu-project",
            github_repo = "Cemu",
            starts_with = "cemu",
            ends_with = "windows-x64.zip",
            search_file = "Cemu.exe",
            install_name = "Cemu",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Cemu", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Cemu", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "cemu-project",
            github_repo = "Cemu",
            starts_with = "Cemu",
            ends_with = ".AppImage",
            search_file = "Cemu.AppImage",
            install_name = "Cemu",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Cemu", "linux"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Citra
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Citra", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "citra-emu",
            github_repo = "citra-nightly",
            starts_with = "citra-windows-msvc",
            ends_with = ".7z",
            search_file = "citra-qt.exe",
            install_name = "Citra",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Citra", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Citra", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "citra-emu",
            github_repo = "citra-nightly",
            starts_with = "citra-linux-appimage",
            ends_with = ".tar.gz",
            search_file = "citra-qt.AppImage",
            install_name = "Citra",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Citra", "linux"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Dolphin
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Dolphin", "windows"):
        network.DownloadLatestWebpageRelease(
            webpage_url = "https://dolphin-emu.org/download/",
            starts_with = "https://dl.dolphin-emu.org/builds",
            ends_with = "x64.7z",
            search_file = "Dolphin.exe",
            install_name = "Dolphin",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Dolphin", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Dolphin", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/dolphin-emu/dolphin.git",
            output_name = "Dolphin",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "Dolphin", "linux"),
            build_cmd = [
                "cmake", "..", "-DLINUX_LOCAL_DEV=true", "-DCMAKE_BUILD_TYPE=Release",
                "&&",
                "make", "-j", "4"
            ],
            build_dir = "Build",
            internal_copies = [
                {"from": "Source/Build/Binaries/dolphin-emu", "to": "AppImage/usr/bin/dolphin-emu"},
                {"from": "Source/Build/Binaries/dolphin-tool", "to": "AppImage/usr/bin/dolphin-tool"},
                {"from": "Source/Data/Sys", "to": "AppImage/usr/bin/Sys"},
                {"from": "Source/Data/dolphin-emu.desktop", "to": "AppImage/dolphin-emu.desktop"},
                {"from": "Source/Data/dolphin-emu.png", "to": "AppImage/dolphin-emu.png"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/dolphin-emu", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # DosBoxX
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "DosBoxX", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "joncampbell123",
            github_repo = "dosbox-x",
            starts_with = "dosbox-x-vsbuild-win64",
            ends_with = ".zip",
            search_file = "dosbox-x.exe",
            install_name = "DosBoxX",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "DosBoxX", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "DosBoxX", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/joncampbell123/dosbox-x.git",
            output_name = "DosBoxX",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "DosBoxX", "linux"),
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
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # DuckStation
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "DuckStation", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "stenzek",
            github_repo = "duckstation",
            starts_with = "duckstation",
            ends_with = "windows-x64-release.zip",
            search_file = "duckstation-qt-x64-ReleaseLTCG.exe",
            install_name = "DuckStation",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "DuckStation", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "DuckStation", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "stenzek",
            github_repo = "duckstation",
            starts_with = "DuckStation",
            ends_with = ".AppImage",
            search_file = "DuckStation.AppImage",
            install_name = "DuckStation",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "DuckStation", "linux"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # EKA2L1
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "EKA2L1", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "EKA2L1",
            github_repo = "EKA2L1",
            starts_with = "windows-latest",
            ends_with = ".zip",
            search_file = "eka2l1_qt.exe",
            install_name = "EKA2L1",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "EKA2L1", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "EKA2L1", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "EKA2L1",
            github_repo = "EKA2L1",
            starts_with = "ubuntu-latest",
            ends_with = ".AppImage",
            search_file = "ubuntu-latest.AppImage",
            install_name = "EKA2L1",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "EKA2L1", "linux"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Flycast
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Flycast", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "flyinghead",
            github_repo = "flycast",
            starts_with = "flycast-win64",
            ends_with = ".zip",
            search_file = "flycast.exe",
            install_name = "Flycast",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Flycast", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Flycast", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/flyinghead/flycast.git",
            output_name = "Flycast",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "Flycast", "linux"),
            build_cmd = [
                "cmake", "..", "-DCMAKE_BUILD_TYPE=Release",
                "&&",
                "make", "-j", "4"
            ],
            build_dir = "Build",
            internal_copies = [
                {"from": "Source/Build/flycast", "to": "AppImage/usr/bin/flycast"},
                {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/flycast", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # FS-UAE
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "FS-UAE", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "FrodeSolheim",
            github_repo = "fs-uae",
            starts_with = "FS-UAE",
            ends_with = "Windows_x86-64.zip",
            search_file = "Plugin.ini",
            install_name = "FS-UAE",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "FS-UAE", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "FS-UAE", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://fs-uae.net/files/FS-UAE/Stable/3.1.66/fs-uae-3.1.66.tar.xz",
            output_name = "FS-UAE",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "FS-UAE", "linux"),
            build_cmd = [
                "cd", "fs-uae-3.1.66",
                "&&",
                "./configure",
                "&&",
                "make", "-j", "8"
            ],
            internal_copies = [
                {"from": "Source/fs-uae-3.1.66/fs-uae", "to": "AppImage/usr/bin/fs-uae"},
                {"from": "Source/fs-uae-3.1.66/share/applications/fs-uae.desktop", "to": "AppImage/app.desktop"},
                {"from": "Source/fs-uae-3.1.66/share/icons/hicolor/256x256/apps/fs-uae.png", "to": "AppImage/fs-uae.png"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/fs-uae", "to": "AppRun"}
            ],
            external_copies = [
                {"from": "Source/fs-uae-3.1.66/fs-uae.dat", "to": "fs-uae.dat"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Mame
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Mame", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "mamedev",
            github_repo = "mame",
            starts_with = "mame",
            ends_with = "64bit.exe",
            search_file = "mame.exe",
            install_name = "Mame",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Mame", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            installer_type = config.installer_format_7zip,
            is_installer = False,
            is_archive = True,
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Mame", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/mamedev/mame.git",
            output_name = "Mame",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "Mame", "linux"),
            build_cmd = [
                "make", "-j", "8"
            ],
            internal_copies = [
                {"from": "Source/mame", "to": "AppImage/usr/bin/mame"},
                {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/mame", "to": "AppRun"}
            ],
            external_copies = [
                {"from": "Source/uismall.bdf", "to": "Mame.AppImage.home/.mame/uismall.bdf"},
                {"from": "Source/artwork", "to": "Mame.AppImage.home/.mame/artwork"},
                {"from": "Source/bgfx", "to": "Mame.AppImage.home/.mame/bgfx"},
                {"from": "Source/ctrlr", "to": "Mame.AppImage.home/.mame/ctrlr"},
                {"from": "Source/docs", "to": "Mame.AppImage.home/.mame/docs"},
                {"from": "Source/hash", "to": "Mame.AppImage.home/.mame/hash"},
                {"from": "Source/hlsl", "to": "Mame.AppImage.home/.mame/hlsl"},
                {"from": "Source/ini", "to": "Mame.AppImage.home/.mame/ini"},
                {"from": "Source/language", "to": "Mame.AppImage.home/.mame/language"},
                {"from": "Source/plugins", "to": "Mame.AppImage.home/.mame/plugins"},
                {"from": "Source/roms", "to": "Mame.AppImage.home/.mame/roms"},
                {"from": "Source/samples", "to": "Mame.AppImage.home/.mame/samples"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Mednafen
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Mednafen", "windows"):
        network.DownloadLatestWebpageRelease(
            webpage_url = "https://mednafen.github.io/",
            starts_with = "https://mednafen.github.io/releases/files/mednafen",
            ends_with = "UNSTABLE-win64.zip",
            search_file = "mednafen.exe",
            install_name = "Mednafen",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Mednafen", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Mednafen", "linux"):
        network.BuildAppImageFromSource(
            webpage_url = "https://mednafen.github.io/",
            starts_with = "https://mednafen.github.io/releases/files/mednafen",
            ends_with = "UNSTABLE.tar.xz",
            output_name = "Mednafen",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "Mednafen", "linux"),
            build_cmd = [
                "cd", "mednafen",
                "&&",
                "./configure",
                "&&",
                "make", "-j", "4"
            ],
            internal_copies = [
                {"from": "Source/mednafen/src/mednafen", "to": "AppImage/usr/bin/mednafen"},
                {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/mednafen", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # melonDS
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "melonDS", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "melonDS-emu",
            github_repo = "melonDS",
            starts_with = "melonDS",
            ends_with = "win_x64.zip",
            search_file = "melonDS.exe",
            install_name = "melonDS",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "melonDS", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "melonDS", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/melonDS-emu/melonDS.git",
            output_name = "melonDS",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "melonDS", "linux"),
            build_cmd = [
                "cmake", "..", "-DCMAKE_BUILD_TYPE=Release",
                "&&",
                "make", "-j", "4"
            ],
            build_dir = "Build",
            internal_copies = [
                {"from": "Source/Build/melonDS", "to": "AppImage/usr/bin/melonDS"},
                {"from": "Source/res/net.kuribo64.melonDS.desktop", "to": "AppImage/net.kuribo64.melonDS.desktop"},
                {"from": "Source/res/icon/melon_256x256.png", "to": "AppImage/net.kuribo64.melonDS.png"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/melonDS", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # mGBA
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "mGBA", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "mgba-emu",
            github_repo = "mgba",
            starts_with = "mGBA",
            ends_with = "win64.7z",
            search_file = "mGBA.exe",
            install_name = "mGBA",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "mGBA", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "mGBA", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "mgba-emu",
            github_repo = "mgba",
            starts_with = "mGBA",
            ends_with = ".appimage",
            search_file = "mGBA.AppImage",
            install_name = "mGBA",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "mGBA", "linux"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # PCSX2
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "PCSX2", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "PCSX2",
            github_repo = "pcsx2",
            starts_with = "pcsx2",
            ends_with = "windows-x64-Qt.7z",
            search_file = "pcsx2-qt.exe",
            install_name = "PCSX2",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "PCSX2", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "PCSX2", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "PCSX2",
            github_repo = "pcsx2",
            starts_with = "pcsx2",
            ends_with = ".AppImage",
            search_file = "PCSX2.AppImage",
            install_name = "PCSX2",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "PCSX2", "linux"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # PPSSPP
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "PPSSPP", "windows"):
        network.DownloadGeneralRelease(
            archive_url = "https://www.ppsspp.org/files/1_16_6/ppsspp_win.zip",
            search_file = "PPSSPPWindows64.exe",
            install_name = "PPSSPP",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "PPSSPP", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "PPSSPP", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/hrydgard/ppsspp.git",
            output_name = "PPSSPP",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "PPSSPP", "linux"),
            build_cmd = [
                "cmake", "..", "-DLINUX_LOCAL_DEV=true", "-DCMAKE_BUILD_TYPE=Release",
                "&&",
                "make", "-j", "4"
            ],
            build_dir = "Build",
            internal_copies = [
                {"from": "Source/Build/PPSSPPSDL", "to": "AppImage/usr/bin/PPSSPPSDL"},
                {"from": "Source/Build/assets", "to": "AppImage/usr/bin/assets"},
                {"from": "Source/Build/ppsspp.desktop", "to": "AppImage/ppsspp.desktop"},
                {"from": "Source/icons/icon-512.svg", "to": "AppImage/ppsspp.svg"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/PPSSPPSDL", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # ScummVM
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "ScummVM", "windows"):
        network.DownloadGeneralRelease(
            archive_url = "https://downloads.scummvm.org/frs/scummvm/2.7.1/scummvm-2.7.1-win32-x86_64.zip",
            search_file = "scummvm.exe",
            install_name = "ScummVM",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "ScummVM", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "ScummVM", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/scummvm/scummvm.git",
            output_name = "ScummVM",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "ScummVM", "linux"),
            build_cmd = [
                "./configure",
                "&&",
                "make", "-j10"
            ],
            internal_copies = [
                {"from": "Source/scummvm", "to": "AppImage/usr/bin/scummvm"},
                {"from": "Source/gui/themes/*.dat", "to": "AppImage/usr/local/share/scummvm"},
                {"from": "Source/gui/themes/*.zip", "to": "AppImage/usr/local/share/scummvm"},
                {"from": "Source/dists/networking/wwwroot.zip", "to": "AppImage/usr/local/share/scummvm"},
                {"from": "Source/dists/engine-data/*.dat", "to": "AppImage/usr/local/share/scummvm"},
                {"from": "Source/dists/engine-data/*.zip", "to": "AppImage/usr/local/share/scummvm"},
                {"from": "Source/dists/engine-data/*.tbl", "to": "AppImage/usr/local/share/scummvm"},
                {"from": "Source/dists/engine-data/*.cpt", "to": "AppImage/usr/local/share/scummvm"},
                {"from": "Source/dists/engine-data/*.lab", "to": "AppImage/usr/local/share/scummvm"},
                {"from": "Source/dists/pred.dic", "to": "AppImage/usr/local/share/scummvm"},
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
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # RetroArch
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "RetroArch", "windows"):
        network.DownloadGeneralRelease(
            archive_url = "https://buildbot.libretro.com/nightly/windows/x86_64/RetroArch.7z",
            search_file = "retroarch.exe",
            install_name = "RetroArch",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "RetroArch", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
        network.DownloadGeneralRelease(
            archive_url = "https://buildbot.libretro.com/nightly/windows/x86_64/RetroArch_cores.7z",
            search_file = "snes9x_libretro.dll",
            install_name = "RetroArch",
            install_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "RetroArch", "linux"):
        network.DownloadGeneralRelease(
            archive_url = "https://buildbot.libretro.com/nightly/linux/x86_64/RetroArch.7z",
            search_file = "RetroArch-Linux-x86_64.AppImage",
            install_name = "RetroArch",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "RetroArch", "linux"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
        network.DownloadGeneralRelease(
            archive_url = "https://buildbot.libretro.com/nightly/linux/x86_64/RetroArch_cores.7z",
            search_file = "snes9x_libretro.so",
            install_name = "RetroArch",
            install_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir", "linux"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # RPCS3
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "RPCS3", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "RPCS3",
            github_repo = "rpcs3-binaries-win",
            starts_with = "rpcs3",
            ends_with = "win64.7z",
            search_file = "rpcs3.exe",
            install_name = "RPCS3",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "RPCS3", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "RPCS3", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "RPCS3",
            github_repo = "rpcs3-binaries-linux",
            starts_with = "rpcs3",
            ends_with = ".AppImage",
            search_file = "RPCS3.AppImage",
            install_name = "RPCS3",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "RPCS3", "linux"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # VICE-C64
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "VICE-C64", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "VICE-Team",
            github_repo = "svn-mirror",
            starts_with = "SDL2VICE",
            ends_with = "win64.zip",
            search_file = "x64sc.exe",
            install_name = "VICE-C64",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "VICE-C64", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "VICE-C64", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/VICE-Team/svn-mirror.git",
            output_name = "VICE-C64",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "VICE-C64", "linux"),
            build_cmd = [
                "cd", "vice",
                "&&",
                "./autogen.sh",
                "&&",
                "./configure", "--disable-html-docs", "--enable-pdf-docs=no",
                "&&",
                "make", "-j", "4"
            ],
            internal_copies = [
                {"from": "Source/vice/data", "to": "AppImage/usr/bin"},
                {"from": "Source/vice/src/x64sc", "to": "AppImage/usr/bin/x64sc"},
                {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/x64sc", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Vita3K
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Vita3K", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "Vita3K",
            github_repo = "Vita3K",
            starts_with = "windows-latest",
            ends_with = ".zip",
            search_file = "Vita3K.exe",
            install_name = "Vita3K",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Vita3K", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Vita3K", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "Vita3K",
            github_repo = "Vita3K",
            starts_with = "Vita3K-x86_64",
            ends_with = ".AppImage",
            search_file = "Vita3K-x86_64.AppImage",
            install_name = "Vita3K",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Vita3K", "linux"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Xemu
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Xemu", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "mborgerson",
            github_repo = "xemu",
            starts_with = "xemu",
            ends_with = "win-release.zip",
            search_file = "xemu.exe",
            install_name = "Xemu",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Xemu", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Xemu", "linux"):
        network.BuildAppImageFromSource(
            release_url = "https://github.com/mborgerson/xemu.git",
            output_name = "Xemu",
            output_dir = os.path.join(emulators.GetBaseDirectory(), "Xemu", "linux"),
            build_cmd = [
                "./build.sh"
            ],
            internal_copies = [
                {"from": "Source/dist/xemu", "to": "AppImage/usr/bin/xemu"},
                {"from": "Source/ui/xemu.desktop", "to": "AppImage/xemu.desktop"},
                {"from": "Source/ui/icons/xemu.svg", "to": "AppImage/xemu.svg"}
            ],
            internal_symlinks = [
                {"from": "usr/bin/xemu", "to": "AppRun"}
            ],
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Xenia
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Xenia", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "xenia-project",
            github_repo = "release-builds-windows",
            starts_with = "xenia_master",
            ends_with = "master.zip",
            search_file = "xenia.exe",
            install_name = "Xenia",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Xenia", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Yuzu
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Yuzu", "windows"):
        network.DownloadLatestGithubRelease(
            github_user = "yuzu-emu",
            github_repo = "yuzu-mainline",
            starts_with = "yuzu-windows-msvc",
            ends_with = ".7z",
            search_file = "yuzu.exe",
            install_name = "Yuzu",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Yuzu", "windows"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
    if force_downloads or ShouldProgramBeInstalled(emulators.GetConfig(), emulators.GetBaseDirectory(), "Yuzu", "linux"):
        network.DownloadLatestGithubRelease(
            github_user = "yuzu-emu",
            github_repo = "yuzu-mainline",
            starts_with = "yuzu-mainline",
            ends_with = ".AppImage",
            search_file = "Yuzu.AppImage",
            install_name = "Yuzu",
            install_dir = os.path.join(emulators.GetBaseDirectory(), "Yuzu", "linux"),
            prefix_dir = emulators.GetPrefixDir(),
            prefix_name = emulators.GetPrefixName(),
            get_latest = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

# Setup required emulators
def SetupRequiredEmulators():

    # Ares
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("Ares"),
        dest = programs.GetEmulatorPathConfigValue("Ares", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("Ares"),
        dest = programs.GetEmulatorPathConfigValue("Ares", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # BasiliskII
    system.CopyContents(
        src = os.path.join(environment.GetSyncedGameEmulatorSetupDir("BasiliskII"), "bios"),
        dest = programs.GetEmulatorPathConfigValue("BasiliskII", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = os.path.join(environment.GetSyncedGameEmulatorSetupDir("BasiliskII"), "bios"),
        dest = programs.GetEmulatorPathConfigValue("BasiliskII", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # Cemu
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("Cemu"),
        dest = programs.GetEmulatorPathConfigValue("Cemu", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("Cemu"),
        dest = programs.GetEmulatorPathConfigValue("Cemu", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # Citra
    for obj in ["nand", "sysdata"]:
        if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("Citra", "setup_dir", "linux"), obj)):
            archive.ExtractArchive(
                archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Citra"), obj + ".zip"),
                extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Citra", "setup_dir", "linux"), obj),
                skip_existing = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("Citra", "setup_dir", "windows"), obj)):
            archive.ExtractArchive(
                archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Citra"), obj + ".zip"),
                extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Citra", "setup_dir", "windows"), obj),
                skip_existing = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Dolphin
    for obj in ["Wii"]:
        if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("Dolphin", "setup_dir", "linux"), obj)):
            archive.ExtractArchive(
                archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Dolphin"), obj + ".zip"),
                extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Dolphin", "setup_dir", "linux"), obj),
                skip_existing = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("Dolphin", "setup_dir", "windows"), obj)):
            archive.ExtractArchive(
                archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Dolphin"), obj + ".zip"),
                extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Dolphin", "setup_dir", "windows"), obj),
                skip_existing = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # DuckStation
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("DuckStation"),
        dest = programs.GetEmulatorPathConfigValue("DuckStation", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("DuckStation"),
        dest = programs.GetEmulatorPathConfigValue("DuckStation", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # FS-UAE
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("FS-UAE"),
        dest = programs.GetEmulatorPathConfigValue("FS-UAE", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("FS-UAE"),
        dest = programs.GetEmulatorPathConfigValue("FS-UAE", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # Mame
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("Mame"),
        dest = programs.GetEmulatorPathConfigValue("Mame", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("Mame"),
        dest = programs.GetEmulatorPathConfigValue("Mame", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # Mednafen
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("Mednafen"),
        dest = programs.GetEmulatorPathConfigValue("Mednafen", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("Mednafen"),
        dest = programs.GetEmulatorPathConfigValue("Mednafen", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # melonDS
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("melonDS"),
        dest = programs.GetEmulatorPathConfigValue("melonDS", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("melonDS"),
        dest = programs.GetEmulatorPathConfigValue("melonDS", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # mGBA
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("mGBA"),
        dest = programs.GetEmulatorPathConfigValue("mGBA", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("mGBA"),
        dest = programs.GetEmulatorPathConfigValue("mGBA", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # PCSX2
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("PCSX2"),
        dest = programs.GetEmulatorPathConfigValue("PCSX2", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("PCSX2"),
        dest = programs.GetEmulatorPathConfigValue("PCSX2", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # RetroArch
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("RetroArch"),
        dest = programs.GetEmulatorPathConfigValue("RetroArch", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("RetroArch"),
        dest = programs.GetEmulatorPathConfigValue("RetroArch", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # RPCS3
    for obj in ["dev_flash"]:
        if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("RPCS3", "setup_dir", "linux"), obj)):
            archive.ExtractArchive(
                archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("RPCS3"), obj + ".zip"),
                extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("RPCS3", "setup_dir", "linux"), obj),
                skip_existing = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("RPCS3", "setup_dir", "windows"), obj)):
            archive.ExtractArchive(
                archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("RPCS3"), obj + ".zip"),
                extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("RPCS3", "setup_dir", "windows"), obj),
                skip_existing = True,
                verbose = False,
                exit_on_failure = False)

    # Vita3K
    for obj in ["os0", "sa0", "vs0"]:
        if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("Vita3K", "setup_dir", "linux"), obj)):
            archive.ExtractArchive(
                archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Vita3K"), obj + ".zip"),
                extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Vita3K", "setup_dir", "linux"), obj),
                skip_existing = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("Vita3K", "setup_dir", "windows"), obj)):
            archive.ExtractArchive(
                archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Vita3K"), obj + ".zip"),
                extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Vita3K", "setup_dir", "windows"), obj),
                skip_existing = True,
                verbose = False,
                exit_on_failure = False)

    # Xemu
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("Xemu"),
        dest = programs.GetEmulatorPathConfigValue("Xemu", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("Xemu"),
        dest = programs.GetEmulatorPathConfigValue("Xemu", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # Yuzu
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("Yuzu"),
        dest = programs.GetEmulatorPathConfigValue("Yuzu", "setup_dir", "linux"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)
    system.CopyContents(
        src = environment.GetSyncedGameEmulatorSetupDir("Yuzu"),
        dest = programs.GetEmulatorPathConfigValue("Yuzu", "setup_dir", "windows"),
        skip_existing = True,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

# Download required libraries
def DownloadRequiredLibraries(force_downloads = False):

    # DXVK
    if force_downloads or ShouldLibraryBeInstalled(os.path.join(environment.GetScriptsThirdPartyLibDir(), "DXVK")):
        network.DownloadLatestGithubRelease(
            github_user = "doitsujin",
            github_repo = "dxvk",
            starts_with = "dxvk-2.2",
            ends_with = ".tar.gz",
            search_file = "x64/d3d9.dll",
            install_name = "DXVK",
            install_dir = os.path.join(environment.GetScriptsThirdPartyLibDir(), "DXVK"),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # VKD3D-Proton
    if force_downloads or ShouldLibraryBeInstalled(os.path.join(environment.GetScriptsThirdPartyLibDir(), "VKD3D-Proton")):
        network.DownloadLatestGithubRelease(
            github_user = "HansKristian-Work",
            github_repo = "vkd3d-proton",
            starts_with = "vkd3d-proton",
            ends_with = ".tar.zst",
            search_file = "x64/d3d12.dll",
            install_name = "VKD3D-Proton",
            install_dir = os.path.join(environment.GetScriptsThirdPartyLibDir(), "VKD3D-Proton"),
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

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
