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
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }}
}}
"""

# Docker compose template
docker_compose_template = """
version: '3.8'
services:
  wekan:
    image: wekan/wekan:latest
    container_name: wekan
    restart: always
    environment:
      - ROOT_URL=https://{subdomain}.{domain}
      - MONGO_URL=mongodb://mongo:27017/wekan
      - MONGO_OPLOG_URL=mongodb://mongo:27017/local
    ports:
      - "{port_http}:8080"
    depends_on:
      - mongo
    volumes:
      - wekan_data:/data

  mongo:
    image: mongo:5.0
    container_name: wekan_mongo
    restart: always
    volumes:
      - mongo_data:/data/db

volumes:
  wekan_data:
  mongo_data:
"""

# .env template
env_template = """
PORT_HTTP={port_http}
SUBDOMAIN={subdomain}
DOMAIN={domain}
"""

# Wekan Installer
class Wekan(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.app_name = "wekan"
        self.app_dir = f"$HOME/apps/{self.app_name}"
        self.nginx_config_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.Wekan", "wekan_subdomain"),
            "port_http": self.config.GetValue("UserData.Wekan", "wekan_port_http")
        }
        self.env_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.Wekan", "wekan_subdomain"),
            "port_http": self.config.GetValue("UserData.Wekan", "wekan_port_http")
        }

    def IsInstalled(self):
        containers = self.connection.RunOutput("docker ps -a --format '{{.Names}}'")
        return any(self.app_name in name for name in containers.splitlines())

    def Install(self):

        # Create directories
        util.LogInfo("Creating directories")
        self.connection.MakeDirectory(self.app_dir)

        # Write docker compose
        util.LogInfo("Writing docker compose")
        docker_compose_content = docker_compose_template.format(**self.nginx_config_values, **self.env_values)
        if self.connection.WriteFile("/tmp/docker-compose.yml", docker_compose_content):
            self.connection.MoveFileOrDirectory("/tmp/docker-compose.yml", f"{self.app_dir}/docker-compose.yml")

        # Write docker env
        util.LogInfo("Writing docker env")
        env_content = env_template.format(**self.env_values)
        if self.connection.WriteFile("/tmp/.env", env_content):
            self.connection.MoveFileOrDirectory("/tmp/.env", f"{self.app_dir}/.env")

        # Create Nginx entry
        util.LogInfo("Creating Nginx entry")
        nginx_conf_content = nginx_config_template.format(**self.nginx_config_values)
        if self.connection.WriteFile(f"/tmp/{self.app_name}.conf", nginx_conf_content):
            self.connection.RunChecked([self.nginx_manager_tool, "install_conf", f"/tmp/{self.app_name}.conf"], sudo=True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_conf", f"{self.app_name}.conf"], sudo=True)
            self.connection.RemoveFileOrDirectory(f"/tmp/{self.app_name}.conf")

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo=True)

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
        self.connection.RunChecked([self.nginx_manager_tool, "remove_conf", f"{self.app_name}.conf"], sudo=True)

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo=True)
        return True
