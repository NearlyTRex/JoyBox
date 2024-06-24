# Imports
import os
import sys

# Local imports
import environment

###########################################################
# Ini defaults
###########################################################
ini_defaults = {}

# UserData.Dirs
ini_defaults["UserData.Dirs"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["UserData.Dirs"]["tools_dir"] = "%USERPROFILE%\\Tools"
    ini_defaults["UserData.Dirs"]["emulators_dir"] = "%USERPROFILE%\\Emulators"
    ini_defaults["UserData.Dirs"]["sync_dir"] = "%USERPROFILE%\\Sync"
    ini_defaults["UserData.Dirs"]["local_cache_dir"] = "%USERPROFILE%\\Cache"
    ini_defaults["UserData.Dirs"]["remote_cache_dir"] = "Y:\\"
    ini_defaults["UserData.Dirs"]["storage_dir"] = "X:\\"
    ini_defaults["UserData.Dirs"]["metadata_dir"] = "C:\\Repositories\\GameMetadata"
    ini_defaults["UserData.Dirs"]["scripts_dir"] = "C:\\Repositories\\JoyBox\\Scripts"
else:
    ini_defaults["UserData.Dirs"]["tools_dir"] = "$HOME/Tools"
    ini_defaults["UserData.Dirs"]["emulators_dir"] = "$HOME/Emulators"
    ini_defaults["UserData.Dirs"]["sync_dir"] = "$HOME/Sync"
    ini_defaults["UserData.Dirs"]["local_cache_dir"] = "$HOME/Cache"
    ini_defaults["UserData.Dirs"]["remote_cache_dir"] = "/mnt/Cache"
    ini_defaults["UserData.Dirs"]["storage_dir"] = "/mnt/Storage"
    ini_defaults["UserData.Dirs"]["metadata_dir"] = "$HOME/Repositories/GameMetadata"
    ini_defaults["UserData.Dirs"]["scripts_dir"] = "$HOME/Repositories/JoyBox/Scripts"

# UserData.Protection
ini_defaults["UserData.Protection"] = {}
ini_defaults["UserData.Protection"]["general_passphrase"] = ""
ini_defaults["UserData.Protection"]["sync_passphrase"] = ""
ini_defaults["UserData.Protection"]["storage_passphrase"] = ""

# UserData.NAS
ini_defaults["UserData.NAS"] = {}
ini_defaults["UserData.NAS"]["nas_base_location"] = ""
ini_defaults["UserData.NAS"]["nas_storage_folder"] = ""
ini_defaults["UserData.NAS"]["nas_cache_folder"] = ""
ini_defaults["UserData.NAS"]["nas_username"] = ""
ini_defaults["UserData.NAS"]["nas_password"] = ""

# UserData.Resolution
ini_defaults["UserData.Resolution"] = {}
ini_defaults["UserData.Resolution"]["screen_resolution_w"] = "1920"
ini_defaults["UserData.Resolution"]["screen_resolution_h"] = "1080"
ini_defaults["UserData.Resolution"]["screen_resolution_c"] = "32"

# UserData.Capture
ini_defaults["UserData.Capture"] = {}
ini_defaults["UserData.Capture"]["capture_duration"] = "300"
ini_defaults["UserData.Capture"]["capture_interval"] = "1"
ini_defaults["UserData.Capture"]["capture_origin_x"] = "0"
ini_defaults["UserData.Capture"]["capture_origin_y"] = "0"
ini_defaults["UserData.Capture"]["capture_resolution_w"] = "1920"
ini_defaults["UserData.Capture"]["capture_resolution_h"] = "1080"
ini_defaults["UserData.Capture"]["capture_framerate"] = "30"
ini_defaults["UserData.Capture"]["overwrite_screenshots"] = "False"
ini_defaults["UserData.Capture"]["overwrite_videos"] = "False"

# UserData.GitHub
ini_defaults["UserData.GitHub"] = {}
ini_defaults["UserData.GitHub"]["github_username"] = "NearlyTRex"
ini_defaults["UserData.GitHub"]["github_access_token"] = ""

# UserData.Steam
ini_defaults["UserData.Steam"] = {}
ini_defaults["UserData.Steam"]["steam_username"] = "SemiDiabolicalParka"
ini_defaults["UserData.Steam"]["steam_userid"] = "76561198286525102"

# UserData.Switch
ini_defaults["UserData.Switch"] = {}
ini_defaults["UserData.Switch"]["profile_user_id"] = "F6F389D41D6BC0BDD6BD928C526AE556"
ini_defaults["UserData.Switch"]["profile_account_name"] = "yuzu"

# Tools.WinGet/Apt
if environment.IsWindowsPlatform():
    ini_defaults["Tools.WinGet"] = {}
    ini_defaults["Tools.WinGet"]["winget_exe"] = "winget.exe"
    ini_defaults["Tools.WinGet"]["winget_install_dir"] = "%USERPROFILE%\\AppData\\Local\\Microsoft\\WindowsApps"
else:
    ini_defaults["Tools.Apt"] = {}
    ini_defaults["Tools.Apt"]["apt_exe"] = "apt"
    ini_defaults["Tools.Apt"]["apt_install_dir"] = "/usr/bin"
    ini_defaults["Tools.Snap"] = {}
    ini_defaults["Tools.Snap"]["snap_exe"] = "snap"
    ini_defaults["Tools.Snap"]["snap_install_dir"] = "/usr/bin"
    ini_defaults["Tools.Flatpak"] = {}
    ini_defaults["Tools.Flatpak"]["flatpak_exe"] = "flatpak"
    ini_defaults["Tools.Flatpak"]["flatpak_install_dir"] = "/usr/bin"

# Tools.Python
ini_defaults["Tools.Python"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["Tools.Python"]["python_exe"] = "python.exe"
    ini_defaults["Tools.Python"]["python_pip_exe"] = "pip.exe"
    ini_defaults["Tools.Python"]["python_install_dir"] = "C:\\Python311"
    ini_defaults["Tools.Python"]["python_venv_dir"] = "%USERPROFILE%\\.venv"
else:
    ini_defaults["Tools.Python"]["python_exe"] = "python3"
    ini_defaults["Tools.Python"]["python_pip_exe"] = "pip3"
    ini_defaults["Tools.Python"]["python_install_dir"] = "/usr/bin"
    ini_defaults["Tools.Python"]["python_venv_dir"] = "$HOME/.venv"

# Tools.Perl
ini_defaults["Tools.Perl"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["Tools.Perl"]["perl_exe"] = "perl.exe"
    ini_defaults["Tools.Perl"]["perl_install_dir"] = "C:\\Strawberry\\perl\\bin"
else:
    ini_defaults["Tools.Perl"]["perl_exe"] = "perl"
    ini_defaults["Tools.Perl"]["perl_install_dir"] = "/usr/bin"

# Tools.Steam
ini_defaults["Tools.Steam"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["Tools.Steam"]["steamcmd_exe"] = "steamcmd.exe"
    ini_defaults["Tools.Steam"]["steamcmd_install_dir"] = "C:\\SteamCMD"
else:
    ini_defaults["Tools.Steam"]["steamcmd_exe"] = "steamcmd"
    ini_defaults["Tools.Steam"]["steamcmd_install_dir"] = "/usr/games"

# Tools.Sandboxie/Wine
if environment.IsWindowsPlatform():
    ini_defaults["Tools.Sandboxie"] = {}
    ini_defaults["Tools.Sandboxie"]["sandboxie_exe"] = "Start.exe"
    ini_defaults["Tools.Sandboxie"]["sandboxie_ini_exe"] = "SbieIni.exe"
    ini_defaults["Tools.Sandboxie"]["sandboxie_rpcss_exe"] = "SandboxieRpcSs.exe"
    ini_defaults["Tools.Sandboxie"]["sandboxie_dcomlaunch_exe"] = "SandboxieDcomLaunch.exe"
    ini_defaults["Tools.Sandboxie"]["sandboxie_install_dir"] = "%ProgramFiles%\\Sandboxie-Plus"
    ini_defaults["Tools.Sandboxie"]["sandboxie_sandbox_dir"] = "%USERPROFILE%\\Sandbox\\%USERNAME%"
else:
    ini_defaults["Tools.Wine"] = {}
    ini_defaults["Tools.Wine"]["wine_exe"] = "wine"
    ini_defaults["Tools.Wine"]["wine_boot_exe"] = "wineboot"
    ini_defaults["Tools.Wine"]["wine_server_exe"] = "wineserver"
    ini_defaults["Tools.Wine"]["wine_tricks_exe"] = "winetricks"
    ini_defaults["Tools.Wine"]["wine_install_dir"] = "/usr/bin"
    ini_defaults["Tools.Wine"]["wine_sandbox_dir"] = "$HOME/Sandbox"

# Tools.Curl
ini_defaults["Tools.Curl"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["Tools.Curl"]["curl_exe"] = "curl.exe"
    ini_defaults["Tools.Curl"]["curl_install_dir"] = "C:\\Windows\\System32"
else:
    ini_defaults["Tools.Curl"]["curl_exe"] = "curl"
    ini_defaults["Tools.Curl"]["curl_install_dir"] = "/usr/bin"

# Tools.Tar
ini_defaults["Tools.Tar"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["Tools.Tar"]["tar_exe"] = "tar.exe"
    ini_defaults["Tools.Tar"]["tar_install_dir"] = "C:\\Windows\\System32"
else:
    ini_defaults["Tools.Tar"]["tar_exe"] = "tar"
    ini_defaults["Tools.Tar"]["tar_install_dir"] = "/usr/bin"

# Tools.Git
ini_defaults["Tools.Git"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["Tools.Git"]["git_exe"] = "git.exe"
    ini_defaults["Tools.Git"]["git_install_dir"] = "%ProgramFiles%\\Git\\bin"
else:
    ini_defaults["Tools.Git"]["git_exe"] = "git"
    ini_defaults["Tools.Git"]["git_install_dir"] = "/usr/bin"

# Tools.Gpg
ini_defaults["Tools.Gpg"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["Tools.Gpg"]["gpg_exe"] = "gpg.exe"
    ini_defaults["Tools.Gpg"]["gpg_install_dir"] = "%ProgramFiles(x86)%\\gnupg\\bin"
else:
    ini_defaults["Tools.Gpg"]["gpg_exe"] = "gpg"
    ini_defaults["Tools.Gpg"]["gpg_install_dir"] = "/usr/bin"

# Tools.7Zip
ini_defaults["Tools.7Zip"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["Tools.7Zip"]["7z_exe"] = "7z.exe"
    ini_defaults["Tools.7Zip"]["7z_install_dir"] = "%ProgramFiles%\\7-Zip-Zstandard"
else:
    ini_defaults["Tools.7Zip"]["7z_exe"] = "7zz"
    ini_defaults["Tools.7Zip"]["7z_install_dir"] = "/usr/bin"

# Tools.Firefox
ini_defaults["Tools.Firefox"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["Tools.Firefox"]["firefox_exe"] = "firefox.exe"
    ini_defaults["Tools.Firefox"]["firefox_install_dir"] = "%ProgramFiles%\\Mozilla Firefox"
else:
    ini_defaults["Tools.Firefox"]["firefox_exe"] = "firefox"
    ini_defaults["Tools.Firefox"]["firefox_install_dir"] = "/usr/bin"
