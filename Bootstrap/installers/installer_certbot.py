# Imports
import os
import sys

# Local imports
import util
import constants
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
        self.domain_name = self.config.get_value("UserData.Servers", "domain_name")
        self.domain_contact = self.config.get_value("UserData.Servers", "domain_contact")
        self.subdomains = [
            self.config.get_value("UserData.Cockpit", "cockpit_subdomain"),
            self.config.get_value("UserData.Wordpress", "wordpress_subdomain"),
            self.config.get_value("UserData.FileBrowser", "filebrowser_subdomain"),
            self.config.get_value("UserData.Jenkins", "jenkins_subdomain"),
            self.config.get_value("UserData.Audiobookshelf", "audiobookshelf_subdomain"),
            self.config.get_value("UserData.Navidrome", "navidrome_subdomain"),
            self.config.get_value("UserData.Kanboard", "kanboard_subdomain"),
            self.config.get_value("UserData.Ghidra", "ghidra_subdomain"),
        ]
        self.fully_qualified_domains = [self.domain_name] + [f"{sub}.{self.domain_name}" for sub in self.subdomains]
        self.nginx_config_values = {
            "domain": self.domain_name
        }

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/bin/certbot")

    def install(self):

        # Install certbot
        util.log_info("Installing certbot")
        self.connection.run_checked([self.aptget_tool, "update"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "certbot"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "python3-certbot-nginx"], sudo = True)

        # Register cert
        util.log_info("Registering cert")
        self.connection.run_checked([self.cert_manager_tool, "register", self.domain_contact] + self.fully_qualified_domains, sudo = True)

        # Add cert renewal
        util.log_info("Adding cert renewal")
        self.connection.add_to_crontab(f"0 3 * * * {self.cert_manager_tool} renew")

        # Update default entry
        util.log_info("Creating default entry")
        if self.connection.write_file("/tmp/default", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.run_checked([self.nginx_manager_tool, "install_conf", "/tmp/default"], sudo = True)
            self.connection.run_checked([self.nginx_manager_tool, "link_conf", "default"], sudo = True)
            self.connection.remove_file_or_directory("/tmp/default")

        # Restart nginx
        util.log_info("Restarting nginx")
        self.connection.run_checked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True

    def uninstall(self):

        # Remove cert renewal
        util.log_info("Removing cert renewal")
        self.connection.remove_from_crontab(f"0 3 * * * {self.cert_manager_tool} renew")

        # Uninstall certbot
        util.log_info("Uninstalling certbot")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "certbot"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "python3-certbot-nginx"], sudo = True)
        return True
