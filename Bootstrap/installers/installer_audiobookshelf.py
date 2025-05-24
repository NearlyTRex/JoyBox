# Imports
import os
import sys

# Local imports
import util
from . import installer

# Nginx config template
nginx_config_template = """
server {{
    listen 80;
    server_name {subdomain}.{domain};

    location / {{
        return 301 https://{subdomain}.{domain}$request_uri;
    }}
}}

server {{
    listen 443 ssl;
    server_name {subdomain}.{domain};

    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    location / {{
        proxy_pass http://localhost:{port_http};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Cookie $http_cookie;
    }}
}}
"""

# Docker compose template
docker_compose_template = """
version: '3.8'
services:
  audiobookshelf:
    image: advplyr/audiobookshelf:latest
    container_name: audiobookshelf
    restart: always
    user: "${AUDIOBOOKSHELF_UID}:${AUDIOBOOKSHELF_GID}"
    ports:
      - "${AUDIOBOOKSHELF_PORT_HTTP}:13378"
    volumes:
      - ${AUDIOBOOKSHELF_AUDIO_DIR}:/audiobooks:ro
      - ./config:/config
    environment:
      - AUDIOBOOKSHELF_USERNAME=${AUDIOBOOKSHELF_ADMIN_USER}
      - AUDIOBOOKSHELF_PASSWORD=${AUDIOBOOKSHELF_ADMIN_PASS}
      - AUDIOBOOKSHELF_BIND=:13378
"""

# .env template
env_template = """
AUDIOBOOKSHELF_PORT_HTTP={port_http}
AUDIOBOOKSHELF_UID={user_uid}
AUDIOBOOKSHELF_GID={user_gid}
AUDIOBOOKSHELF_AUDIO_DIR={audio_dir}
AUDIOBOOKSHELF_ADMIN_USER={admin_user}
AUDIOBOOKSHELF_ADMIN_PASS={admin_pass}
"""

# Audiobookshelf Installer
class Audiobookshelf(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.app_name = "audiobookshelf"
        self.app_dir = f"$HOME/apps/{self.app_name}"
        self.nginx_config_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.Audiobookshelf", "audiobookshelf_subdomain"),
            "port_http": self.config.GetValue("UserData.Audiobookshelf", "audiobookshelf_port_http")
        }
        self.env_values = {
            "port_http": self.config.GetValue("UserData.Audiobookshelf", "audiobookshelf_port_http"),
            "user_uid": self.config.GetValue("UserData.Audiobookshelf", "audiobookshelf_user_uid"),
            "user_gid": self.config.GetValue("UserData.Audiobookshelf", "audiobookshelf_user_gid"),
            "audio_dir": self.config.GetValue("UserData.Audiobookshelf", "audiobookshelf_audio_dir"),
            "admin_user": self.config.GetValue("UserData.Audiobookshelf", "audiobookshelf_admin_user"),
            "admin_pass": self.config.GetValue("UserData.Audiobookshelf", "audiobookshelf_admin_pass")
        }

    def IsInstalled(self):
        containers = self.connection.RunOutput("docker ps -a --format '{{.Names}}'")
        return any(self.app_name in name for name in containers.splitlines())

    def Install(self):

        # Create directories
        util.LogInfo("Creating directories")
        self.connection.MakeDirectory(self.app_dir)
        self.connection.MakeDirectory(f"{self.app_dir}/config")

        # Write docker compose
        util.LogInfo("Writing docker compose")
        if self.connection.WriteFile("/tmp/docker-compose.yml", docker_compose_template):
            self.connection.MoveFileOrDirectory("/tmp/docker-compose.yml", f"{self.app_dir}/docker-compose.yml")

        # Write docker env
        util.LogInfo("Writing docker env")
        if self.connection.WriteFile("/tmp/.env", env_template.format(**self.env_values)):
            self.connection.MoveFileOrDirectory("/tmp/.env", f"{self.app_dir}/.env")

        # Create Nginx entry
        util.LogInfo("Creating Nginx entry")
        if self.connection.WriteFile(f"/tmp/{self.app_name}.conf", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_conf", f"/tmp/{self.app_name}.conf"], sudo = True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.RemoveFileOrDirectory(f"/tmp/{self.app_name}.conf")

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)

        # Start docker
        util.LogInfo("Starting docker")
        self.connection.GetOptions().SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "up", "-d", "--build"])
        return True

    def Uninstall(self):

        # Stop docker
        util.LogInfo("Stopping docker")
        self.connection.GetOptions().SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "down", "-v"])

        # Remove directory
        util.LogInfo("Removing directory")
        self.connection.RemoveFileOrDirectory(self.app_dir)

        # Remove Nginx entry
        util.LogInfo("Removing Nginx entry")
        self.connection.RunChecked([self.nginx_manager_tool, "remove_conf", f"{self.app_name}.conf"], sudo = True)

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True
