# Imports
import os
import sys

# Local imports
import util
from . import installer

# Default config file
default_config_file = """
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name _;

    location / {
        return 200 "OK";
        add_header Content-Type text/plain;
    }

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
}
"""

# Nginx
class Nginx(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super.__init__(config, connection, flags, options)

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/sbin/nginx")

    def Install(self):
        util.LogInfo("Installing nginx")
        self.connection.RunChecked("sudo apt update")
        self.connection.RunChecked("sudo apt install -y nginx")
        self.connection.WriteFile("/tmp/default.conf", default_config_file)
        self.connection.RunChecked("sudo mv /tmp/default.conf /etc/nginx/sites-available/default")
        self.connection.RunChecked("sudo ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default")
        self.connection.RunChecked("sudo mkdir -p /var/www/html")
        self.connection.RunChecked("echo 'Welcome to nginx.' | sudo tee /var/www/html/index.html > /dev/null")
        self.connection.RunChecked("sudo systemctl restart nginx")
        self.connection.RunChecked("sudo systemctl enable nginx")
        self.connection.RunChecked("sudo systemctl start nginx")
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling nginx")
        self.connection.RunChecked("sudo systemctl stop nginx")
        self.connection.RunChecked("sudo systemctl disable nginx")
        self.connection.RunChecked("sudo apt remove -y nginx nginx-common")
        self.connection.Run("sudo rm -rf /etc/nginx")
        self.connection.Run("sudo rm -rf /var/www/html")
        return True
