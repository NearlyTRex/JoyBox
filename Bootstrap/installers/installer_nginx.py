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
    listen [::]:80;

    server_name {domain};

    location /.well-known/acme-challenge/ {{
        root /var/www/html;
    }}
}}
"""

# Nginx
class Nginx(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.nginx_config_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name")
        }

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/sbin/nginx")

    def Install(self):

        # Install Nginx
        util.LogInfo("Installing Nginx")
        self.connection.RunChecked([self.aptget_tool, "update"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "install", "-y", "nginx"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "install", "-y", "nginx-common"], sudo = True)

        # Create default entry
        util.LogInfo("Creating default entry")
        if self.connection.WriteFile("/tmp/default", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_conf", "/tmp/default"], sudo = True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_conf", "default"], sudo = True)
            self.connection.RemoveFileOrDirectory("/tmp/default")

        # Create default page
        util.LogInfo("Creating default page")
        if self.connection.WriteFile("/tmp/index.html", "Welcome to nginx"):
            self.connection.RunChecked([self.nginx_manager_tool, "copy_html", "/tmp/index.html"], sudo = True)
            self.connection.RemoveFileOrDirectory("/tmp/index.html")

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True

    def Uninstall(self):

        # Stop Nginx
        util.LogInfo("Stopping Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "stop"], sudo = True)

        # Remove default entry
        util.LogInfo("Removing default entry")
        self.connection.RunChecked([self.nginx_manager_tool, "remove_conf", "default"], sudo = True)

        # Uninstall Nginx
        util.LogInfo("Uninstalling Nginx")
        self.connection.RunChecked([self.aptget_tool, "remove", "-y", "nginx"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "remove", "-y", "nginx-common"], sudo = True)
        return True
