# Imports
import os
import sys

# Local imports
import util
import tools
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
        self.aptget_tool = tools.GetAptGetTool(self.config)
        self.nginx_manager_tool = "/usr/local/bin/manager_nginx.sh"

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/sbin/nginx")

    def Install(self):

        # Install nginx
        util.LogInfo("Installing nginx")
        self.connection.RunChecked([self.aptget_tool, "update"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "install", "-y", "nginx"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "install", "-y", "nginx-common"], sudo = True)

        # Create default entry
        util.LogInfo("Creating default entry")
        if self.connection.WriteFile("/tmp/default", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_conf", "/tmp/default"], sudo = True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_conf", "/tmp/default"], sudo = True)
            self.connection.RemoveFileOrDirectory("/tmp/default")

        # Create default page
        util.LogInfo("Creating default page")
        if self.connection.WriteFile("/tmp/index.html", "Welcome to nginx"):
            self.connection.RunChecked([self.nginx_manager_tool, "copy_html", "/tmp/index.html"], sudo = True)
            self.connection.RemoveFileOrDirectory("/tmp/index.html")

        # Restart nginx
        util.LogInfo("Restarting nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True

    def Uninstall(self):

        # Uninstall nginx
        util.LogInfo("Uninstalling nginx")
        self.connection.RunChecked([self.aptget_tool, "remove", "-y", "nginx"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "remove", "-y", "nginx-common"], sudo = True)
        return True
