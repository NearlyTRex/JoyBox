# Local imports
from joybox.bootstrap import constants
from joybox import serverinfo
from joybox import runoptions
from joybox import logger
from . import installer

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

# Port 80 server for {subdomain}.{domain} that redirects every request to https,
# as a str.format template like the site templates built on it
NGINX_HTTPS_REDIRECT_SERVER = """
server {{
    listen 80;
    server_name {subdomain}.{domain};

    location / {{
        return 301 https://{subdomain}.{domain}$request_uri;
    }}
}}
"""

# Opening of the port 443 server for {subdomain}.{domain}: the Let's Encrypt
# certificate and the shared ssl-params snippet, each after its comment lines
# (an empty comment adds none)
def build_ssl_server_head(cert_comment, params_comment):
    lines = ["", "server {{", "    listen 443 ssl;", "    server_name {subdomain}.{domain};", ""]
    lines += ["    # %s" % line for line in cert_comment.splitlines()]
    lines += [
        "    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;",
        "    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;",
        ""]
    lines += ["    # %s" % line for line in params_comment.splitlines()]
    lines += ["    include /etc/nginx/snippets/ssl-params.conf;", ""]
    return "\n".join(lines)

# A site on {subdomain}.{domain}: the https redirect server, then the ssl server
# opened by build_ssl_server_head and finished by the given locations
def build_https_site_template(
    locations,
    cert_comment = "SSL configuration",
    params_comment = "Shared TLS policy and security headers"):
    return NGINX_HTTPS_REDIRECT_SERVER + build_ssl_server_head(cert_comment, params_comment) + locations

# Installs nginx with the default server entry, the apex fallback snippet and page
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

    # Remote Ubuntu only
    def get_supported_environments(self):
        return [
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    # Whether /usr/sbin/nginx exists
    def is_installed(self):
        return self.connection.does_file_or_directory_exist("/usr/sbin/nginx")

    # apt-get install nginx, then have the nginx manager install the default entry,
    # the apex-root snippet and fallback page, and restart it; False when one cannot be staged
    def install(self):

        # Install Nginx
        logger.log_info("Installing Nginx")
        self.connection.run_checked([self.aptget_tool, "update"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "nginx"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "nginx-common"], sudo = True)

        # Create default entry
        logger.log_info("Creating default entry")
        if not self.install_nginx_conf("default", NGINX_CONFIG_TEMPLATE.format(**self.nginx_config_values)):
            return False

        # Create apex root snippet
        logger.log_info("Creating apex root snippet")
        if not self.install_nginx_snippet("apex-root.conf", APEX_ROOT_SNIPPET_TEMPLATE):
            return False

        # Create default page
        logger.log_info("Creating default page")
        if not self.run_nginx_manager_on_file("copy_html", "index.html", APEX_FALLBACK_PAGE):
            return False

        # Restart Nginx
        logger.log_info("Restarting Nginx")
        self.connection.run_checked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True

    # Stop nginx, remove the default entry, then apt-get remove nginx and nginx-common
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
