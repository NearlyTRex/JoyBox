# Imports
import os
import sys

# Local imports
import constants
from joybox import settings
from joybox import connection
from . import installer
from joybox import runoptions
from joybox import logger

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

    # Shared TLS policy and security headers
    include /etc/nginx/snippets/ssl-params.conf;

    # Whatever serves the apex owns this snippet: nginx installs a static
    # fallback, wordpress replaces it with a proxy block.
    include /etc/nginx/snippets/apex-root.conf;
}}
"""

# Certbot
class Certbot(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.domain_name = settings.get_value("UserData.Servers", "domain_name")
        self.domain_contact = settings.get_value("UserData.Servers", "domain_contact")
        self.tls_mode = settings.get_value("UserData.Servers", "tls_mode",
            default_value = "letsencrypt", throw_exception = False).strip().lower()
        self.subdomains = [
            settings.get_value("UserData.Cockpit", "cockpit_subdomain"),
            settings.get_value("UserData.Wordpress", "wordpress_subdomain"),
            settings.get_value("UserData.FileBrowser", "filebrowser_subdomain"),
            settings.get_value("UserData.Jenkins", "jenkins_subdomain"),
            settings.get_value("UserData.Audiobookshelf", "audiobookshelf_subdomain"),
            settings.get_value("UserData.Navidrome", "navidrome_subdomain"),
            settings.get_value("UserData.Kanboard", "kanboard_subdomain"),
            settings.get_value("UserData.Oscar", "oscar_subdomain"),
            settings.get_value("UserData.FitLog", "fitlog_subdomain"),
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

    def get_cert_dir(self):
        return f"/etc/letsencrypt/live/{self.domain_name}"

    def install_mkcert_cert(self):

        # mkcert has to run on the workstation, not the target: it signs with the
        # local CA that "mkcert -install" put in this machine's trust store, which
        # is what stops the browser warning. The target only receives the leaf.
        logger.log_info("Issuing a mkcert certificate on the local machine")
        local_connection = connection.ConnectionLocal(self.flags, self.options)
        local_dir = local_connection.make_temporary_directory()
        if not local_dir:
            logger.log_error("Could not create a temporary directory for mkcert")
            return False

        local_cert = os.path.join(local_dir, "fullchain.pem")
        local_key = os.path.join(local_dir, "privkey.pem")
        code = local_connection.run_return_code([
            "mkcert",
            "-cert-file", local_cert,
            "-key-file", local_key] + self.fully_qualified_domains)
        if code != 0:
            logger.log_error("mkcert failed. Is it installed, and has 'mkcert -install' been run?")
            local_connection.remove_file_or_directory(local_dir)
            return False

        cert_contents = local_connection.read_file(local_cert)
        key_contents = local_connection.read_file(local_key)
        local_connection.remove_file_or_directory(local_dir)
        if not cert_contents or not key_contents:
            logger.log_error("mkcert produced no certificate")
            return False
        return self.write_cert_pair(cert_contents, key_contents)

    def install_selfsigned_cert(self):

        # No local dependency, but nothing trusts the result - browsers warn once.
        logger.log_info("Generating a self-signed certificate on the target")
        cert_dir = self.get_cert_dir()
        sans = ",".join([f"DNS:{name}" for name in self.fully_qualified_domains])
        self.connection.run_checked(["mkdir", "-p", cert_dir], sudo = True)
        self.connection.run_checked([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "825",
            "-subj", f"/CN={self.domain_name}",
            "-addext", f"subjectAltName={sans}",
            "-keyout", f"{cert_dir}/privkey.pem",
            "-out", f"{cert_dir}/fullchain.pem"], sudo = True)
        self.connection.run_checked(["chmod", "644", f"{cert_dir}/fullchain.pem"], sudo = True)
        self.connection.run_checked(["chmod", "600", f"{cert_dir}/privkey.pem"], sudo = True)
        return True

    def write_cert_pair(self, cert_contents, key_contents):

        # Staged in /tmp then moved with sudo, matching how the other installers
        # get files into root-owned locations.
        cert_dir = self.get_cert_dir()
        self.connection.run_checked(["mkdir", "-p", cert_dir], sudo = True)
        for filename, contents, mode in [
            ("fullchain.pem", cert_contents, "644"),
            ("privkey.pem", key_contents, "600")]:
            staged = f"/tmp/{filename}"
            if not self.connection.write_file(staged, contents):
                logger.log_error(f"Could not stage {filename} on the target")
                return False
            self.connection.run_checked(["mv", staged, f"{cert_dir}/{filename}"], sudo = True)
            self.connection.run_checked(["chmod", mode, f"{cert_dir}/{filename}"], sudo = True)
        logger.log_info(f"Installed certificate to {cert_dir}")
        return True

    def install(self):

        # Install certbot
        logger.log_info("Installing certbot")
        self.connection.run_checked([self.aptget_tool, "update"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "certbot"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "install", "-y", "python3-certbot-nginx"], sudo = True)

        # Issue the certificate. Let's Encrypt cannot validate a domain that only
        # resolves on this workstation, so the local modes substitute a cert at the
        # same path rather than changing what the app templates point at.
        if self.tls_mode == "letsencrypt":
            logger.log_info("Registering cert")
            self.connection.run_checked([self.cert_manager_tool, "register", self.domain_contact] + self.fully_qualified_domains, sudo = True)

            # Add cert renewal
            logger.log_info("Adding cert renewal")
            self.connection.add_to_crontab(f"0 3 * * * {self.cert_manager_tool} renew")
        elif self.tls_mode == "mkcert":
            if not self.install_mkcert_cert():
                return False
        elif self.tls_mode == "selfsigned":
            if not self.install_selfsigned_cert():
                return False
        else:
            logger.log_error(f"Unknown tls_mode '{self.tls_mode}' (expected letsencrypt, mkcert or selfsigned)")
            return False

        # Update default entry
        logger.log_info("Creating default entry")
        if self.connection.write_file("/tmp/default", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.run_checked([self.nginx_manager_tool, "install_conf", "/tmp/default"], sudo = True)
            self.connection.run_checked([self.nginx_manager_tool, "link_conf", "default"], sudo = True)
            self.connection.remove_file_or_directory("/tmp/default")

        # Restart nginx
        logger.log_info("Restarting nginx")
        self.connection.run_checked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True

    def uninstall(self):

        # Remove cert renewal (only the letsencrypt mode ever adds one)
        if self.tls_mode == "letsencrypt":
            logger.log_info("Removing cert renewal")
            self.connection.remove_from_crontab(f"0 3 * * * {self.cert_manager_tool} renew")

        # Uninstall certbot
        logger.log_info("Uninstalling certbot")
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "certbot"], sudo = True)
        self.connection.run_checked([self.aptget_tool, "remove", "-y", "python3-certbot-nginx"], sudo = True)
        return True
