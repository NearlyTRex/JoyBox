# Imports
import os
import sys

# Local imports
import constants
from joybox import settings
from . import installer
from joybox import runoptions
from joybox import logger

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
        proxy_pass https://localhost:{port_http};
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}
"""

class Cockpit(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "cockpit"
        self.nginx_config_values = {
            "domain": settings.get_value("UserData.Servers", "domain_name"),
            "subdomain": settings.get_value("UserData.Cockpit", "cockpit_subdomain"),
            "port_http": settings.get_value("UserData.Cockpit", "cockpit_port_http")
        }

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def is_installed(self):
        output = self.connection.run_output("systemctl is-enabled cockpit.socket")
        return "enabled" in output

    def install(self):

        # Install Cockpit
        logger.log_info("Installing Cockpit")
        self.connection.run_checked([self.cockpit_manager_tool, "install"], sudo = True)

        # Create Nginx config
        logger.log_info("Creating Nginx config")
        if self.connection.write_file(f"/tmp/{self.app_name}.conf", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.run_checked([self.nginx_manager_tool, "install_conf", f"/tmp/{self.app_name}.conf"], sudo = True)
            self.connection.run_checked([self.nginx_manager_tool, "link_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.remove_file_or_directory(f"/tmp/{self.app_name}.conf")

        # Restart Nginx
        logger.log_info("Restarting Nginx")
        self.connection.run_checked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True

    def uninstall(self):

        # Remove Nginx config
        logger.log_info("Removing Nginx config")
        self.connection.run_checked([self.nginx_manager_tool, "remove_conf", f"{self.app_name}.conf"], sudo = True)

        # Restart Nginx
        logger.log_info("Restarting Nginx")
        self.connection.run_checked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)

        # Uninstall Cockpit
        logger.log_info("Uninstalling Cockpit")
        self.connection.run_checked([self.cockpit_manager_tool, "uninstall"], sudo = True)
        return True
