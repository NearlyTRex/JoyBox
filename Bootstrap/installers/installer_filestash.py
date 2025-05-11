# Imports
import os
import sys
import re

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
    include /etc/nginx/authelia/auth_server.conf;

    location / {{
        auth_request /authelia;
        error_page 401 = @error401;
        include /etc/nginx/authelia/auth_location.conf;

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
  filestash:
    image: machines/filestash
    container_name: filestash
    restart: always
    environment:
      ADMIN_USERNAME: ${FILESTASH_ADMIN_USERNAME}
      ADMIN_PASSWORD: ${FILESTASH_ADMIN_PASSWORD}
      APPLICATION_TITLE: ${FILESTASH_APPLICATION_TITLE}
      APPLICATION_URL: ${FILESTASH_APPLICATION_URL}
    ports:
      - "${FILESTASH_PORT_HTTP}:8334"
    volumes:
      - filestash:/app/data/state

volumes:
  filestash: {}
"""

# .env template
env_template = """
FILESTASH_ADMIN_USERNAME={admin_username}
FILESTASH_ADMIN_PASSWORD={admin_password_hash}
FILESTASH_PORT_HTTP={port_http}
FILESTASH_APPLICATION_TITLE=My Storage
FILESTASH_APPLICATION_URL=
"""

# Filestash Installer
class Filestash(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.app_name = "filestash"
        self.app_dir = f"$HOME/apps/{self.app_name}"
        self.nginx_config_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.Filestash", "filestash_subdomain"),
            "port_http": self.config.GetValue("UserData.Filestash", "filestash_port_http")
        }
        self.env_values = {
            "admin_username": self.config.GetValue("UserData.Filestash", "filestash_admin_username"),
            "admin_password_hash": self.GeneratePasswordHash(
                self.config.GetValue("UserData.Filestash", "filestash_admin_username"),
                self.config.GetValue("UserData.Filestash", "filestash_admin_password")),
            "port_http": self.config.GetValue("UserData.Filestash", "filestash_port_http")
        }
        if not self.env_values.get("admin_password_hash"):
            raise Exception("Unable to generate password hash")

    def IsInstalled(self):
        containers = self.connection.RunOutput("docker ps -a --format '{{.Names}}'")
        return any(self.app_name in name for name in containers.splitlines())

    def Install(self):

        # Create directory
        util.LogInfo("Creating directory")
        self.connection.MakeDirectory(self.app_dir)

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

    def GeneratePasswordHash(self, username, password):

        # Generate password hash
        result = self.connection.RunOutput([
            self.docker_tool,
            "run",
            "--rm",
            "httpd:alpine",
            "htpasswd",
            "-nbB", username,
            password
        ])

        # Search for password hash
        match = re.search(rf'^{re.escape(username)}:(.+)$', result.strip())
        if match:
            return match.group(1)
        return None
