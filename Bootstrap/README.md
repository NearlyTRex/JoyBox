# JoyBox Bootstrap

Automated setup for my home system and web server. Instead of manually remembering and installing all my software, this handles everything in one command.

## Home System Setup

Fresh Ubuntu/Pop!_OS install? Run this:

```bash
cd /path/to/JoyBox

# First run - creates JoyBox.ini config, prompts for any needed values
python3 bootstrap.py -a setup -t local_ubuntu
```

This installs:
- **Dev tools**: build-essential, cmake, git, golang, nodejs, dotnet, python tools, Qt dev packages
- **Editors/IDEs**: VSCodium, GitKraken
- **Browsers**: Chrome, Brave, Firefox
- **Apps**: 1Password, GIMP, VLC, Handbrake, Audacity, OBS alternatives
- **Gaming**: Steam, SteamCMD, DXVK, Wine
- **Virtualization**: VirtualBox, QEMU/KVM, virt-manager
- **Utilities**: KDiff3, Meld, Okular, Remmina, and many more
- **Flatpaks**: Discord, Signal, Telegram, IntelliJ, Heroic Launcher, etc.
- **Python packages**: All my commonly used pip packages

### Install Specific Components Only

```bash
# Just browsers and dev tools
python3 bootstrap.py -a setup -t local_ubuntu --components aptget chrome brave vscodium gitkraken

# See what's available
python3 bootstrap.py -t local_ubuntu --list-components
```

### Available Components (Home)

| Component | What it does |
|-----------|--------------|
| `aptget` | All APT packages (dev tools, libs, apps) |
| `flatpak` | Flatpak apps (Discord, Signal, etc.) |
| `chrome` | Google Chrome (adds repo) |
| `brave` | Brave Browser (adds repo) |
| `gitkraken` | GitKraken (downloads latest .deb) |
| `onepassword` | 1Password (adds repo) |
| `vscodium` | VSCodium (adds repo) |
| `wine` | Wine + dependencies |

## Web Server Setup

For setting up my website on a fresh Ubuntu server:

```bash
# Requires server settings in JoyBox.ini (host, user, password)
python3 bootstrap.py -a setup -t remote_ubuntu -s 0
```

Or specific services:

```bash
# Just web server + SSL + management UI
python3 bootstrap.py -a setup -t remote_ubuntu -s 0 --components nginx certbot cockpit

# Add WordPress site
python3 bootstrap.py -a setup -t remote_ubuntu -s 0 --components wordpress
```

### Available Components (Server)

| Component | What it does |
|-----------|--------------|
| `nginx` | Nginx with config templates |
| `certbot` | Let's Encrypt SSL certs |
| `cockpit` | Server management web UI |
| `wordpress` | WordPress via Docker |
| `audiobookshelf` | Audiobook streaming |
| `navidrome` | Music streaming |
| `filebrowser` | Web file manager |
| `jenkins` | CI/CD server |
| `kanboard` | Project management |
| `ghidra` | Reverse engineering tools |

## Configuration

First run creates `JoyBox.ini`. Key settings:

```ini
[UserData.Servers]
server_0_host = myserver.com
server_0_port = 22
server_0_user = myuser
server_0_pass = ...

[UserData.Wordpress]
wordpress_subdomain = blog
wordpress_port = 8080

[UserData.Cockpit]
cockpit_subdomain = manage
cockpit_port = 9090
```

## Common Commands

```bash
# Check what's installed
python3 bootstrap.py -a status -t local_ubuntu

# Check specific components
python3 bootstrap.py -a status -t local_ubuntu --components chrome brave vscodium

# Dry run - see what would happen
python3 bootstrap.py -a setup -t local_ubuntu -p -v

# Force reinstall a component
python3 bootstrap.py -a setup -t local_ubuntu --components brave -f

# Uninstall everything
python3 bootstrap.py -a teardown -t local_ubuntu

# Verbose output
python3 bootstrap.py -a setup -t local_ubuntu -v
```

## Adding New Software

### APT Packages

Edit `packages/aptget.py`:
```python
aptget[constants.EnvironmentType.LOCAL_UBUNTU] += [
    ...
    "new-package",
]
```

### Flatpak Apps

Edit `packages/flatpak.py`:
```python
flatpak[constants.EnvironmentType.LOCAL_UBUNTU] += [
    {"repository": "flathub", "name": "com.example.App"},
]
```

### Python Packages

Edit `packages/python.py`:
```python
python[constants.EnvironmentType.LOCAL_UBUNTU] += [
    "new-pip-package",
]
```

### Custom Installers (for non-trivial installs)

For apps that need external repos, GPG keys, or special setup (not just `apt install`), create a custom installer.

1. Create `installers/installer_myapp.py`:

```python
import util
from . import installer

class MyApp(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        # Setup URLs, paths, etc.
        self.gpg_url = "https://example.com/key.gpg"
        self.repo_url = "https://example.com/repo"
        self.archive_key = "myapp-archive-keyring.gpg"
        self.sources_list = "myapp.list"
        self.archive_key_path = f"/usr/share/keyrings/{self.archive_key}"
        self.sources_list_path = f"/etc/apt/sources.list.d/{self.sources_list}"

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/myapp")

    def install(self):
        util.log_info("Installing MyApp")
        # Download and install GPG key
        self.connection.download_file(self.gpg_url, "/tmp/myapp.gpg")
        self.connection.run_checked(
            [self.gpg_tool, "--dearmor", "-o", self.archive_key_path, "/tmp/myapp.gpg"],
            sudo = True)
        self.connection.remove_file_or_directory("/tmp/myapp.gpg")
        # Add apt source
        self.connection.write_file(
            f"/tmp/{self.sources_list}",
            f"deb [signed-by={self.archive_key_path}] {self.repo_url} stable main\n")
        self.connection.move_file_or_directory(
            f"/tmp/{self.sources_list}", self.sources_list_path, sudo = True)
        # Install
        self.connection.run_checked([self.aptget_tool, "update"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "myapp"], sudo = True)
        return True

    def uninstall(self):
        util.log_info("Uninstalling MyApp")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "myapp"], sudo = True)
        self.connection.remove_file_or_directory(self.sources_list_path, sudo = True)
        self.connection.remove_file_or_directory(self.archive_key_path, sudo = True)
        return True
```

For apps that just download a .deb directly (no repo):

```python
class MyApp(installer.Installer):
    def __init__(self, config, connection, flags = util.RunFlags(), options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.download_url = "https://example.com/myapp-amd64.deb"
        self.deb_path = "/tmp/myapp-amd64.deb"

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/myapp")

    def install(self):
        util.log_info("Installing MyApp")
        self.connection.download_file(self.download_url, self.deb_path)
        self.connection.run_checked([self.aptget_tool, "install", "-y", self.deb_path], sudo = True)
        self.connection.remove_file_or_directory(self.deb_path)
        return True

    def uninstall(self):
        util.log_info("Uninstalling MyApp")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "myapp"], sudo = True)
        return True
```

2. Add import to `installers/__init__.py`:
```python
from installers.installer_myapp import *
```

3. Register in `environments/env_local_ubuntu.py`:
```python
self.available_components = {
    ...
    "myapp": installers.MyApp(**self.installer_options),
}

self.installer_myapp = self.available_components["myapp"]
```

See existing installers for more examples:
- `installer_brave.py` - APT repo with GPG key
- `installer_gitkraken.py` - Direct .deb download
- `installer_onepassword.py` - APT repo with debsig policy
- `installer_wordpress.py` - Docker Compose service

## File Structure

```
Bootstrap/
├── packages/           # What to install
│   ├── aptget.py       # APT packages
│   ├── flatpak.py      # Flatpak apps
│   └── python.py       # Pip packages
├── installers/         # How to install special apps
│   ├── installer_brave.py
│   ├── installer_chrome.py
│   ├── installer_gitkraken.py
│   ├── installer_vscodium.py
│   ├── installer_wordpress.py
│   └── ...
├── environments/       # Local vs remote setup
│   ├── env_local_ubuntu.py
│   └── env_remote_ubuntu.py
└── connection/         # Command execution (local/SSH)
```

## Notes

- Components are installed in order, uninstalled in reverse order
- Already-installed components are skipped (use `-f` to force)
- Server components use Docker Compose for isolation
- APT repos are properly configured with GPG keys (auto-updates work)
