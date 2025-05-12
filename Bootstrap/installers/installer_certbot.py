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

    location / {{
        return 301 https://$host$request_uri;
    }}
}}

server {{
    listen 443 ssl;
    listen [::]:443 ssl;

    server_name {domain};

    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers HIGH:!aNULL:!MD5;

    root /var/www/html;
    index index.html;

    location / {{
        try_files $uri $uri/ =404;
    }}
}}
"""

# Certbot
class Certbot(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.domain_name = self.config.GetValue("UserData.Servers", "domain_name")
        self.domain_contact = self.config.GetValue("UserData.Servers", "domain_contact")
        self.subdomains = [
            self.config.GetValue("UserData.Wordpress", "wordpress_subdomain"),
            self.config.GetValue("UserData.AzuraCast", "azuracast_subdomain"),
            self.config.GetValue("UserData.FileBrowser", "filebrowser_subdomain"),
            self.config.GetValue("UserData.Jenkins", "jenkins_subdomain")
        ]
        self.fully_qualified_domains = [self.domain_name] + [f"{sub}.{self.domain_name}" for sub in self.subdomains]
        self.nginx_config_values = {
            "domain": self.domain_name
        }

    def IsInstalled(self):
        return self.connection.DoesFileOrDirectoryExist("/usr/bin/certbot")

    def Install(self):

        # Install certbot
        util.LogInfo("Installing certbot")
        self.connection.RunChecked([self.aptget_tool, "update"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "install", "-y", "certbot"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "install", "-y", "python3-certbot-nginx"], sudo = True)

        # Register cert
        util.LogInfo("Registering cert")
        self.connection.RunChecked([self.cert_manager_tool, "register", self.domain_contact] + self.fully_qualified_domains, sudo = True)

        # Add cert renewal
        util.LogInfo("Adding cert renewal")
        self.connection.AddToCronTab(f"0 3 * * * {self.cert_manager_tool} renew")

        # Update default entry
        util.LogInfo("Creating default entry")
        if self.connection.WriteFile("/tmp/default", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_conf", "/tmp/default"], sudo = True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_conf", "default"], sudo = True)
            self.connection.RemoveFileOrDirectory("/tmp/default")

        # Restart nginx
        util.LogInfo("Restarting nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True

    def Uninstall(self):

        # Remove cert renewal
        util.LogInfo("Removing cert renewal")
        self.connection.RemoveFromCronTab(f"0 3 * * * {self.cert_manager_tool} renew")

        # Uninstall certbot
        util.LogInfo("Uninstalling certbot")
        self.connection.RunChecked([self.aptget_tool, "remove", "-y", "certbot"], sudo = True)
        self.connection.RunChecked([self.aptget_tool, "remove", "-y", "python3-certbot-nginx"], sudo = True)
        return True
