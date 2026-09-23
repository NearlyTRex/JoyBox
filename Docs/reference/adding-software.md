# Adding Software

[← Docs index](../README.md)

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

## Docker Compose Apps

Server apps that run as containers subclass `DockerAppInstaller`
(`installers/installer_dockerapp.py`), which owns the whole lifecycle: directories, staging the
compose and env files, nginx wiring, the compose lifecycle, backup and restore. A subclass
declares data, not steps.

```python
from joybox import settings
from joybox import runoptions
from . import installer_dockerapp

# Docker compose template
docker_compose_template = """
services:
  myapp:
    image: ${MYAPP_IMAGE}
    container_name: myapp
    restart: always
    ports:
      - "${MYAPP_PORT_HTTP}:80"
    volumes:
      - config_data:/config

volumes:
  config_data:
"""

# .env template
env_template = """
MYAPP_PORT_HTTP={port_http}
"""

# MyApp Installer
class MyApp(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "myapp"
        self.nginx_config_values = {
            "domain": settings.get_value("UserData.Servers", "domain_name"),
            "subdomain": settings.get_value("UserData.MyApp", "myapp_subdomain"),
            "port_http": settings.get_value("UserData.MyApp", "myapp_port_http")
        }
        self.env_values = {
            "port_http": settings.get_value("UserData.MyApp", "myapp_port_http")
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http"]

        # Backup
        self.backup_label = "MyApp"
        self.backup_volumes = ["config_data"]
```

Things worth knowing:

- **Never write an image tag into the compose template.** Add the pin to
  `packages/images.py` under the app name and reference it as `${MYAPP_IMAGE}`; the base class
  appends it to the app's `.env`. The compose template is written verbatim, so the only
  substitution mechanism is the env file.
- **`required_settings`** names the keys that must be present. A key missing from `JoyBox.ini`
  resolves to `None` and would otherwise be formatted into your config as the string `"None"`.
- **Paths**: use `self.get_app_dir()`, never a literal `"$HOME/..."` string — command arguments
  are shell-quoted, so `$HOME` in a list argument is not expanded.
- **Backup**: declare `backup_database` (a compose service name), `backup_volumes` (compose-local
  volume names) and/or `backup_dirs` (subdirectories of the app dir). Declaring nothing means the
  app is skipped by `-a backup`.
- **Override points**: `post_install()` runs after the containers are up;
  `install_nginx_config()` / `uninstall_nginx_config()` replace the default vhost wiring
  (WordPress uses these to own the apex domain).
- For a websocket app set
  `self.nginx_config_template = installer_dockerapp.nginx_http_websocket_config_template`.

Then register it in `installers/__init__.py` and in the environment's component dict
(`environments/env_remote_ubuntu.py`), and add its subdomain to the certbot SAN list in
`installers/installer_certbot.py`.

## Custom Installers (for non-trivial installs)

For apps that need external repos, GPG keys, or special setup (not just `apt install`), create a custom installer.

1. Create `installers/installer_myapp.py`:

```python
from joybox import runoptions
from joybox import logger
from . import installer

class MyApp(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
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
        logger.log_info("Installing MyApp")
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
        logger.log_info("Uninstalling MyApp")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "myapp"], sudo = True)
        self.connection.remove_file_or_directory(self.sources_list_path, sudo = True)
        self.connection.remove_file_or_directory(self.archive_key_path, sudo = True)
        return True
```

For apps that just download a .deb directly (no repo):

```python
class MyApp(installer.Installer):
    def __init__(self, connection, flags = runoptions.RunFlags(), options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.download_url = "https://example.com/myapp-amd64.deb"
        self.deb_path = "/tmp/myapp-amd64.deb"

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/myapp")

    def install(self):
        logger.log_info("Installing MyApp")
        self.connection.download_file(self.download_url, self.deb_path)
        self.connection.run_checked([self.aptget_tool, "install", "-y", self.deb_path], sudo = True)
        self.connection.remove_file_or_directory(self.deb_path)
        return True

    def uninstall(self):
        logger.log_info("Uninstalling MyApp")
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
