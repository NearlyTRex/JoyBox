# Imports
import os
import sys

# Local imports
import util
from . import installer

# Nginx stream config template
nginx_stream_config_template = """
upstream ghidra_backend {{
    server localhost:{port_http};
}}

server {{
    listen {subdomain}.{domain}:13100;
    proxy_pass ghidra_backend;
    proxy_timeout 1s;
    proxy_responses 1;
    error_log /var/log/nginx/ghidra_stream.log;
}}
"""

# Docker compose template
docker_compose_template = """
version: '3.8'
services:
  ghidra-server:
    image: blacktop/ghidra:latest
    container_name: ghidra-server
    restart: always
    ports:
      - "${GHIDRA_PORT}:13100"
    volumes:
      - ghidra_repos:/repos
    command: ["ghidraRun", "/ghidra/server/ghidraSvr", "console"]
volumes:
  ghidra_repos: {}
"""

# .env template
env_template = """
GHIDRA_PORT={port_http}
GHIDRA_ADMIN_USER={admin_user}
GHIDRA_ADMIN_PASS={admin_pass}
"""

# Ghidra Installer
class Ghidra(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.app_name = "ghidra"
        self.app_dir = f"$HOME/apps/{self.app_name}"
        self.app_port = self.config.GetValue("UserData.Ghidra", "ghidra_port")
        self.nginx_stream_config_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.Ghidra", "ghidra_subdomain"),
            "port_http": self.config.GetValue("UserData.Ghidra", "ghidra_port")
        }
        self.env_values = {
            "port_http": self.config.GetValue("UserData.Ghidra", "ghidra_port"),
            "admin_user": self.config.GetValue("UserData.Ghidra", "ghidra_admin_user"),
            "admin_pass": self.config.GetValue("UserData.Ghidra", "ghidra_admin_pass")
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
        if self.connection.WriteFile("/tmp/docker-compose.yml", docker_compose_template):
            self.connection.MoveFileOrDirectory("/tmp/docker-compose.yml", f"{self.app_dir}/docker-compose.yml")

        # Write docker env
        util.LogInfo("Writing docker env")
        if self.connection.WriteFile("/tmp/.env", env_template.format(**self.env_values)):
            self.connection.MoveFileOrDirectory("/tmp/.env", f"{self.app_dir}/.env")

        # Create nginx stream entry
        util.LogInfo("Creating nginx stream entry")
        if self.connection.WriteFile(f"/tmp/{self.app_name}.conf", nginx_stream_config_template.format(**self.nginx_stream_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_stream_conf", f"/tmp/{self.app_name}.conf"], sudo = True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_stream_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.RemoveFileOrDirectory(f"/tmp/{self.app_name}.conf")

        # Open firewall port
        util.LogInfo("Opening firewall port")
        self.connection.RunChecked([self.nginx_manager_tool, "open_port", self.app_port], sudo = True)

        # Start docker
        util.LogInfo("Starting docker")
        self.connection.SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "up", "-d"])
        return True

    def Uninstall(self):

        # Stop docker
        util.LogInfo("Stopping docker")
        self.connection.SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "down", "-v"])
        self.connection.SetCurrentWorkingDirectory(None)

        # Remove directory
        util.LogInfo("Removing directory")
        self.connection.RemoveFileOrDirectory(self.app_dir)

        # Remove nginx stream entry
        util.LogInfo("Removing nginx stream entry")
        self.connection.RunChecked([self.nginx_manager_tool, "remove_stream_conf", f"{self.app_name}.conf"], sudo = True)

        # Close firewall port
        util.LogInfo("Closing firewall port")
        self.connection.RunChecked([self.nginx_manager_tool, "close_port", self.app_port], sudo = True)
        return True
