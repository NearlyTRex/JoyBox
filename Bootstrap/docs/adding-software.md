# Adding Software

[← Docs index](README.md)

How to add new packages and write custom installers.

## APT Packages

Edit `packages/aptget.py`:
```python
aptget[constants.EnvironmentType.LOCAL_UBUNTU] += [
    ...
    "new-package",
]
```

## Flatpak Apps

Edit `packages/flatpak.py`:
```python
flatpak[constants.EnvironmentType.LOCAL_UBUNTU] += [
    {"repository": "flathub", "name": "com.example.App"},
]
```

## Python Packages

Edit `packages/python.py`:
```python
python[constants.EnvironmentType.LOCAL_UBUNTU] += [
    "new-pip-package",
]
```

## Custom Installers (for non-trivial installs)

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

- Components are installed in order, uninstalled in reverse order.
- Already-installed components are skipped (use `-f` to force).
- Server components use Docker Compose for isolation.
- APT repos are properly configured with GPG keys (auto-updates work).
