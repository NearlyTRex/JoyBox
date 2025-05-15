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
        proxy_pass https://localhost:9090;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Cookie $http_cookie;
    }}
}}
"""

class Cockpit(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.app_name = "cockpit"
        self.nginx_config_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.Cockpit", "cockpit_subdomain"),
        }

    def IsInstalled(self):
        output = self.connection.RunOutput("systemctl is-enabled cockpit.socket")
        return "enabled" in output

    def Install(self):

        # Install Cockpit
        util.LogInfo("Installing Cockpit")
        self.connection.RunChecked([self.aptget_tool, "update"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "install", "-y", "cockpit"], sudo = True)
        self.connection.RunChecked([self.cockpit_manager_tool, "systemctl", "enable"], sudo = True)

        # Create Nginx config
        util.LogInfo("Creating Nginx config")
        if self.connection.WriteFile(f"/tmp/{self.app_name}.conf", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.RemoveFileOrDirectory(f"/tmp/{self.app_name}.conf")

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True

    def Uninstall(self):

        # Remove Nginx config
        util.LogInfo("Removing Nginx config")
        self.connection.RunChecked([self.nginx_manager_tool, "remove_conf", f"{self.app_name}.conf"], sudo = True)

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)

        # Uninstall Cockpit
        util.LogInfo("Uninstalling Cockpit")
        self.connection.RunChecked([self.cockpit_manager_tool, "systemctl", "disable"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "remove", "-y", "cockpit"], sudo = True)
        return True
