# Local imports
from joybox.bootstrap import constants
from joybox import settings
from joybox import serverinfo
from joybox import runoptions
from joybox import logger
from . import installer

# Nginx config template
NGINX_CONFIG_TEMPLATE = """
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

    # Shared TLS policy, security headers and rate limiting. Cockpit is the
    # server management UI, so it wants these at least as much as the apps do.
    include /etc/nginx/snippets/ssl-params.conf;

    location / {{
        proxy_pass https://127.0.0.1:{port_http};
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

# Installs the Cockpit web console through its manager script, served behind nginx on its subdomain
class Cockpit(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "cockpit"
        self.nginx_config_values = {
            "domain": serverinfo.get_domain_name(),
            "subdomain": settings.get_value("UserData.Cockpit", "cockpit_subdomain"),
            "port_http": settings.get_value("UserData.Cockpit", "cockpit_port_http")
        }

    # Remote Ubuntu only
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    # Whether cockpit.socket is enabled with the JoyBox listen drop-in and its nginx site is enabled
    def is_installed(self):
        output = self.connection.run_output("systemctl is-enabled cockpit.socket")
        return ("enabled" in output
            and self.connection.does_file_or_directory_exist("/etc/systemd/system/cockpit.socket.d/joybox-listen.conf")
            and self.connection.does_file_or_directory_exist(f"/etc/nginx/sites-enabled/{self.app_name}.conf"))

    # Install Cockpit with the cockpit manager, then add and enable its nginx site and
    # restart nginx; False when the site config cannot be staged
    def install(self):

        # Install Cockpit
        logger.log_info("Installing Cockpit")
        self.connection.run_checked([self.cockpit_manager_tool, "install"], sudo = True)

        # Create Nginx config
        logger.log_info("Creating Nginx config")
        if not self.install_nginx_conf(f"{self.app_name}.conf", NGINX_CONFIG_TEMPLATE.format(**self.nginx_config_values)):
            return False

        # Restart Nginx
        logger.log_info("Restarting Nginx")
        self.connection.run_checked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True

    # Remove the nginx site, restart nginx, then uninstall Cockpit with the cockpit manager
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
