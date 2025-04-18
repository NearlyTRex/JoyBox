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
    ini_defaults["UserData.Dirs"]["local_locker_dir"] = "%USERPROFILE%\\Locker"
    ini_defaults["UserData.Dirs"]["remote_locker_dir"] = "%USERPROFILE%\\LockerRemote"
    ini_defaults["UserData.Dirs"]["cache_dir"] = "%USERPROFILE%\\Cache"
    ini_defaults["UserData.Dirs"]["metadata_dir"] = "C:\\Repositories\\GameMetadata"
    ini_defaults["UserData.Dirs"]["scripts_dir"] = "C:\\Repositories\\JoyBox\\Scripts"
else:
    ini_defaults["UserData.Dirs"]["tools_dir"] = "$HOME/Tools"
    ini_defaults["UserData.Dirs"]["emulators_dir"] = "$HOME/Emulators"
    ini_defaults["UserData.Dirs"]["local_locker_dir"] = "$HOME/Locker"
    ini_defaults["UserData.Dirs"]["remote_locker_dir"] = "$HOME/LockerRemote"
    ini_defaults["UserData.Dirs"]["cache_dir"] = "$HOME/Cache"
    ini_defaults["UserData.Dirs"]["metadata_dir"] = "$HOME/Repositories/GameMetadata"
    ini_defaults["UserData.Dirs"]["scripts_dir"] = "$HOME/Repositories/JoyBox/Scripts"

# UserData.Protection
ini_defaults["UserData.Protection"] = {}
ini_defaults["UserData.Protection"]["general_passphrase"] = ""
ini_defaults["UserData.Protection"]["locker_passphrase"] = ""

# UserData.Share
ini_defaults["UserData.Share"] = {}
ini_defaults["UserData.Share"]["locker_remote_type"] = ""
ini_defaults["UserData.Share"]["locker_remote_name"] = ""
ini_defaults["UserData.Share"]["locker_remote_path"] = "/"
ini_defaults["UserData.Share"]["locker_remote_token"] = ""
ini_defaults["UserData.Share"]["locker_remote_config"] = ""
ini_defaults["UserData.Share"]["locker_remote_mount_flags"] = "no_checksum,no_modtime"
if environment.IsWindowsPlatform():
    ini_defaults["UserData.Share"]["locker_remote_mount_path"] = "%USERPROFILE%\\LockerRemote"
    ini_defaults["UserData.Share"]["locker_local_path"] = "%USERPROFILE%\\Locker"
else:
    ini_defaults["UserData.Share"]["locker_remote_mount_path"] = "$HOME/LockerRemote"
    ini_defaults["UserData.Share"]["locker_local_path"] = "$HOME/Locker"

# UserData.Scraping
ini_defaults["UserData.Scraping"] = {}
ini_defaults["UserData.Scraping"]["web_driver_type"] = "brave"
ini_defaults["UserData.Scraping"]["steamgriddb_api_key"] = ""
ini_defaults["UserData.Scraping"]["google_search_engine_id"] = ""
ini_defaults["UserData.Scraping"]["google_search_engine_api_key"] = ""

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
ini_defaults["UserData.GitHub"]["github_username"] = ""
ini_defaults["UserData.GitHub"]["github_access_token"] = ""

# UserData.Amazon
ini_defaults["UserData.Amazon"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["UserData.Amazon"]["amazon_install_dir"] = "C:\\Program Files (x86)\\Amazon Games"
else:
    ini_defaults["UserData.Amazon"]["amazon_install_dir"] = "$HOME/Games/Amazon"

# UserData.Disc
ini_defaults["UserData.Disc"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["UserData.Disc"]["disc_install_dir"] = "C:\\Games\\Disc"
else:
    ini_defaults["UserData.Disc"]["disc_install_dir"] = "$HOME/Games/Disc"

# UserData.Epic
ini_defaults["UserData.Epic"] = {}
ini_defaults["UserData.Epic"]["epic_username"] = ""
if environment.IsWindowsPlatform():
    ini_defaults["UserData.Epic"]["epic_install_dir"] = "C:\\Program Files\\Epic Games"
else:
    ini_defaults["UserData.Epic"]["epic_install_dir"] = "$HOME/Games/Epic"

# UserData.GOG
ini_defaults["UserData.GOG"] = {}
ini_defaults["UserData.GOG"]["gog_username"] = ""
ini_defaults["UserData.GOG"]["gog_email"] = ""
ini_defaults["UserData.GOG"]["gog_platform"] = "windows"
ini_defaults["UserData.GOG"]["gog_includes"] = "i,e"
ini_defaults["UserData.GOG"]["gog_excludes"] = ""
if environment.IsWindowsPlatform():
    ini_defaults["UserData.GOG"]["gog_install_dir"] = "C:\\GOG Games"
else:
    ini_defaults["UserData.GOG"]["gog_install_dir"] = "$HOME/Games/GOG"

# UserData.HumbleBundle
ini_defaults["UserData.HumbleBundle"] = {}
ini_defaults["UserData.HumbleBundle"]["humblebundle_email"] = ""
ini_defaults["UserData.HumbleBundle"]["humblebundle_platform"] = "windows"
ini_defaults["UserData.HumbleBundle"]["humblebundle_auth_token"] = ""
if environment.IsWindowsPlatform():
    ini_defaults["UserData.HumbleBundle"]["humblebundle_install_dir"] = "C:\\Program Files (x86)\\Humble Bundle"
else:
    ini_defaults["UserData.HumbleBundle"]["humblebundle_install_dir"] = "$HOME/Games/Humble"

# UserData.Itchio
ini_defaults["UserData.Itchio"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["UserData.Itchio"]["itchio_install_dir"] = "%USERPROFILE%\\AppData\\Local\\itch\\apps"
else:
    ini_defaults["UserData.Itchio"]["itchio_install_dir"] = "$HOME/Games/Itchio"

# UserData.Legacy
ini_defaults["UserData.Legacy"] = {}
ini_defaults["UserData.Legacy"]["legacy_username"] = ""
if environment.IsWindowsPlatform():
    ini_defaults["UserData.Legacy"]["legacy_install_dir"] = "C:\\Program Files (x86)\\Legacy Games"
else:
    ini_defaults["UserData.Legacy"]["legacy_install_dir"] = "$HOME/Games/Legacy"

# UserData.PuppetCombo
ini_defaults["UserData.PuppetCombo"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["UserData.PuppetCombo"]["puppetcombo_install_dir"] = "C:\\Games\\PuppetCombo"
else:
    ini_defaults["UserData.PuppetCombo"]["puppetcombo_install_dir"] = "$HOME/Games/PuppetCombo"

# UserData.RedCandle
ini_defaults["UserData.RedCandle"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["UserData.RedCandle"]["redcandle_install_dir"] = "C:\Program Files (x86)\Red Candle Games"
else:
    ini_defaults["UserData.RedCandle"]["redcandle_install_dir"] = "$HOME/Games/RedCandle"

# UserData.SquareEnix
ini_defaults["UserData.SquareEnix"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["UserData.SquareEnix"]["squareenix_install_dir"] = "C:\\Program Files (x86)\\Square Enix"
else:
    ini_defaults["UserData.SquareEnix"]["squareenix_install_dir"] = "$HOME/Games/SquareEnix"

# UserData.Steam
ini_defaults["UserData.Steam"] = {}
ini_defaults["UserData.Steam"]["steam_accountname"] = ""
ini_defaults["UserData.Steam"]["steam_username"] = ""
ini_defaults["UserData.Steam"]["steam_userid"] = ""
ini_defaults["UserData.Steam"]["steam_web_api_key"] = ""
ini_defaults["UserData.Steam"]["steam_platform"] = "windows"
ini_defaults["UserData.Steam"]["steam_arch"] = "64"
if environment.IsWindowsPlatform():
    ini_defaults["UserData.Steam"]["steam_install_dir"] = "C:\\Program Files (x86)\\Steam"
else:
    ini_defaults["UserData.Steam"]["steam_install_dir"] = "$HOME/.steam/steam"

# UserData.Zoom
ini_defaults["UserData.Zoom"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["UserData.Zoom"]["zoom_install_dir"] = "C:\\Program Files (x86)\\Zoom Platform"
else:
    ini_defaults["UserData.Zoom"]["zoom_install_dir"] = "$HOME/Games/Zoom"

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
    ini_defaults["Tools.Steam"]["steam_exe"] = "steam.exe"
    ini_defaults["Tools.Steam"]["steam_install_dir"] = "C:\\Program Files (x86)\\Steam"
    ini_defaults["Tools.Steam"]["steamcmd_exe"] = "steamcmd.exe"
    ini_defaults["Tools.Steam"]["steamcmd_install_dir"] = "C:\\SteamCMD"
else:
    ini_defaults["Tools.Steam"]["steam_exe"] = "steam"
    ini_defaults["Tools.Steam"]["steam_install_dir"] = "/usr/games"
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

# Tools.FuseISO
if environment.IsLinuxPlatform():
    ini_defaults["Tools.FuseISO"] = {}
    ini_defaults["Tools.FuseISO"]["fuseiso_exe"] = "fuseiso"
    ini_defaults["Tools.FuseISO"]["fuseiso_install_dir"] = "/usr/bin"
    ini_defaults["Tools.FuseISO"]["fusermount_exe"] = "fusermount"
    ini_defaults["Tools.FuseISO"]["fusermount_install_dir"] = "/usr/bin"

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
    ini_defaults["Tools.Firefox"]["firefox_download_dir"] = "%USERPROFILE%\\Downloads"
else:
    ini_defaults["Tools.Firefox"]["firefox_exe"] = "firefox"
    ini_defaults["Tools.Firefox"]["firefox_install_dir"] = "/usr/bin"
    ini_defaults["Tools.Firefox"]["firefox_download_dir"] = "$HOME/Downloads"
ini_defaults["Tools.Firefox"]["firefox_profile_dir"] = ""

# Tools.Chrome
ini_defaults["Tools.Chrome"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["Tools.Chrome"]["chrome_exe"] = "chrome.exe"
    ini_defaults["Tools.Chrome"]["chrome_install_dir"] = "%ProgramFiles%\\Google\\Chrome\\Application"
    ini_defaults["Tools.Chrome"]["chrome_download_dir"] = "%USERPROFILE%\\Downloads"
else:
    ini_defaults["Tools.Chrome"]["chrome_exe"] = "google-chrome"
    ini_defaults["Tools.Chrome"]["chrome_install_dir"] = "/usr/bin"
    ini_defaults["Tools.Chrome"]["chrome_download_dir"] = "$HOME/Downloads"

# Tools.Brave
ini_defaults["Tools.Brave"] = {}
if environment.IsWindowsPlatform():
    ini_defaults["Tools.Brave"]["brave_exe"] = "brave.exe"
    ini_defaults["Tools.Brave"]["brave_install_dir"] = "%ProgramFiles%\\BraveSoftware\\Brave-Browser\\Application"
    ini_defaults["Tools.Brave"]["brave_download_dir"] = "%USERPROFILE%\\Downloads"
else:
    ini_defaults["Tools.Brave"]["brave_exe"] = "brave-browser"
    ini_defaults["Tools.Brave"]["brave_install_dir"] = "/usr/bin"
    ini_defaults["Tools.Brave"]["brave_download_dir"] = "$HOME/Downloads"
