# Local imports
from joybox.bootstrap import constants
from joybox import serverinfo
from . import installer
from joybox import runoptions
from joybox import logger

# Apex fallback page
#
# Served at the apex only when no application owns it. Seeing this in
# production means the apex-root.conf snippet was reverted to the fallback.
APEX_FALLBACK_PAGE = "<!doctype html><title>JoyBox</title><h1>JoyBox</h1><p>No site is configured for this domain yet.</p>"

# Apex root snippet template
#
# Included by the certbot-managed apex 443 server block. This static version is
# the fallback; the wordpress component replaces it with a proxy block and
# restores this one on teardown.
APEX_ROOT_SNIPPET_TEMPLATE = """
root /var/www/html;
index index.html;

location / {
    try_files $uri $uri/ =404;
}
"""

# Nginx config template
NGINX_CONFIG_TEMPLATE = """
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
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.nginx_config_values = {
            "domain": serverinfo.get_domain_name()
        }

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/sbin/nginx")

    def install(self):

        # Install Nginx
        logger.log_info("Installing Nginx")
        self.connection.run_checked([self.aptget_tool, "update"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "nginx"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "nginx-common"], sudo = True)

        # Create default entry
        logger.log_info("Creating default entry")
        if self.connection.write_file("/tmp/default", NGINX_CONFIG_TEMPLATE.format(**self.nginx_config_values)):
            self.connection.run_checked([self.nginx_manager_tool, "install_conf", "/tmp/default"], sudo = True)
            self.connection.run_checked([self.nginx_manager_tool, "link_conf", "default"], sudo = True)
            self.connection.remove_file_or_directory("/tmp/default")

        # Create apex root snippet
        logger.log_info("Creating apex root snippet")
        self.install_nginx_snippet("apex-root.conf", APEX_ROOT_SNIPPET_TEMPLATE)

        # Create default page
        logger.log_info("Creating default page")
        if self.connection.write_file("/tmp/index.html", APEX_FALLBACK_PAGE):
            self.connection.run_checked([self.nginx_manager_tool, "copy_html", "/tmp/index.html"], sudo = True)
            self.connection.remove_file_or_directory("/tmp/index.html")

        # Restart Nginx
        logger.log_info("Restarting Nginx")
        self.connection.run_checked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True

    def uninstall(self):

        # Stop Nginx
        logger.log_info("Stopping Nginx")
        self.connection.run_checked([self.nginx_manager_tool, "systemctl", "stop"], sudo = True)

        # Remove default entry
        logger.log_info("Removing default entry")
        self.connection.run_checked([self.nginx_manager_tool, "remove_conf", "default"], sudo = True)

        # Uninstall Nginx
        logger.log_info("Uninstalling Nginx")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "nginx"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "nginx-common"], sudo = True)
        return True
