# Imports
import os
import sys

# Local imports
import constants
from joybox import settings
from . import installer_dockerapp
from . import installer_nginx
from joybox import runoptions
from joybox import logger

# Apex root snippet template
#
# Replaces the static snippet installed by the nginx component, so WordPress
# serves the apex domain without a second server block claiming the same
# server_name.
apex_proxy_snippet_template = """
location / {{
    proxy_pass http://localhost:{port_http};
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header Cookie $http_cookie;
}}
"""

# Redirect config template
#
# The apex is canonical; www redirects to it.
nginx_redirect_config_template = """
server {{
    listen 80;
    listen [::]:80;
    listen 443 ssl;
    listen [::]:443 ssl;

    server_name {subdomain}.{domain};

    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    include /etc/nginx/snippets/ssl-params.conf;

    return 301 https://{domain}$request_uri;
}}
"""

# Docker compose template
docker_compose_template = """
services:
  wordpress:
    image: ${WORDPRESS_IMAGE}
    restart: always
    ports:
      - "${WORDPRESS_PORT_HTTP}:80"
    volumes:
      - wp_data:/var/www/html
    environment:
      WORDPRESS_DB_HOST: ${WORDPRESS_DB_HOST}
      WORDPRESS_DB_USER: ${WORDPRESS_DB_USER}
      WORDPRESS_DB_PASSWORD: ${WORDPRESS_DB_PASSWORD}
      WORDPRESS_DB_NAME: ${WORDPRESS_DB_NAME}
      WORDPRESS_CONFIG_EXTRA: |
        if (isset($$_SERVER['HTTP_X_FORWARDED_PROTO']) && $$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
            $$_SERVER['HTTPS'] = 'on';
        }
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s
      timeout: 10s
      retries: 3
    depends_on:
      db:
        condition: service_healthy

  db:
    image: ${WORDPRESS_DB_IMAGE}
    environment:
      MYSQL_DATABASE: ${WORDPRESS_DB_NAME}
      MYSQL_USER: ${WORDPRESS_DB_USER}
      MYSQL_PASSWORD: ${WORDPRESS_DB_PASSWORD}
      MYSQL_ROOT_PASSWORD: ${WORDPRESS_DB_ROOT_PASSWORD}
    volumes:
      - db_data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-p$$MYSQL_ROOT_PASSWORD"]
      interval: 10s
      timeout: 5s
      retries: 12

  wpcli:
    image: ${WORDPRESS_CLI_IMAGE}
    profiles: ["cli"]
    user: "33:33"
    volumes:
      - wp_data:/var/www/html
      - ./seed:/seed:ro
    environment:
      WORDPRESS_DB_HOST: ${WORDPRESS_DB_HOST}
      WORDPRESS_DB_USER: ${WORDPRESS_DB_USER}
      WORDPRESS_DB_PASSWORD: ${WORDPRESS_DB_PASSWORD}
      WORDPRESS_DB_NAME: ${WORDPRESS_DB_NAME}
      WP_SITE_URL: ${WP_SITE_URL}
      WP_SITE_TITLE: ${WP_SITE_TITLE}
      WP_SITE_TAGLINE: ${WP_SITE_TAGLINE}
      WP_ADMIN_USER: ${WP_ADMIN_USER}
      WP_ADMIN_PASS: ${WP_ADMIN_PASS}
      WP_ADMIN_EMAIL: ${WP_ADMIN_EMAIL}
    depends_on:
      - db

volumes:
  db_data:
  wp_data:
"""

# Env template
env_template = """
WORDPRESS_DB_HOST=db
WORDPRESS_DB_USER={db_user}
WORDPRESS_DB_PASSWORD={db_password}
WORDPRESS_DB_NAME={db_name}
WORDPRESS_DB_ROOT_PASSWORD={db_root_password}
WORDPRESS_PORT_HTTP={port_http}
WP_SITE_URL={site_url}
WP_SITE_TITLE={site_title}
WP_SITE_TAGLINE={site_tagline}
WP_ADMIN_USER={admin_user}
WP_ADMIN_PASS={admin_pass}
WP_ADMIN_EMAIL={admin_email}
"""

# Wordpress
class Wordpress(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "wordpress"
        self.nginx_config_values = {
            "domain": settings.get_value("UserData.Servers", "domain_name"),
            "subdomain": settings.get_value("UserData.Wordpress", "wordpress_subdomain"),
            "port_http": settings.get_value("UserData.Wordpress", "wordpress_port_http")
        }
        self.domain_name = settings.get_value("UserData.Servers", "domain_name")
        self.site_url = f"https://{self.domain_name}"
        self.env_values = {
            "db_user": settings.get_value("UserData.Wordpress", "wordpress_db_user"),
            "db_password": settings.get_value("UserData.Wordpress", "wordpress_db_pass"),
            "db_name": settings.get_value("UserData.Wordpress", "wordpress_db_name"),
            "db_root_password": settings.get_value("UserData.Wordpress", "wordpress_db_root_pass"),
            "port_http": settings.get_value("UserData.Wordpress", "wordpress_port_http"),
            "site_url": self.site_url,
            "site_title": settings.get_value("UserData.Wordpress", "wordpress_site_title",
                default_value = "JoyBox", throw_exception = False),
            "site_tagline": settings.get_value("UserData.Wordpress", "wordpress_site_tagline",
                default_value = "", throw_exception = False),
            "admin_user": settings.get_value("UserData.Wordpress", "wordpress_admin_user",
                default_value = "admin", throw_exception = False),
            "admin_pass": settings.get_value("UserData.Wordpress", "wordpress_admin_pass",
                default_value = "", throw_exception = False),
            "admin_email": settings.get_value("UserData.Wordpress", "wordpress_admin_email",
                default_value = "", throw_exception = False)
        }
        self.seed_enabled = str(settings.get_value("UserData.Wordpress", "wordpress_seed_enabled",
            default_value = "True", throw_exception = False)).strip().lower() in ["true", "1", "yes"]

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template
        self.app_subdirs = ["seed"]

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http", "db_user", "db_name", "db_password", "db_root_password",
            "admin_user", "admin_pass", "admin_email"]

        # Backup
        self.backup_label = "Wordpress"
        self.backup_database = "db"
        self.backup_volumes = ["wp_data"]

    def install_nginx_config(self):

        # WordPress serves the apex domain, so it takes over the apex-root
        # snippet rather than adding a server block for the same name.
        logger.log_info("Installing apex root snippet")
        self.install_nginx_snippet("apex-root.conf",
            apex_proxy_snippet_template.format(**self.nginx_config_values))

        # Redirect the www host to the canonical apex
        logger.log_info("Installing www redirect")
        nginx_tmp_path = f"/tmp/{self.app_name}.conf"
        if self.connection.write_file(nginx_tmp_path,
                nginx_redirect_config_template.format(**self.nginx_config_values)):
            self.connection.run_checked([self.nginx_manager_tool, "install_conf", nginx_tmp_path], sudo = True)
            self.connection.run_checked([self.nginx_manager_tool, "link_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.remove_file_or_directory(nginx_tmp_path)
        return True

    def uninstall_nginx_config(self):

        # Hand the apex back to the static fallback
        logger.log_info("Restoring static apex root snippet")
        self.install_nginx_snippet("apex-root.conf", installer_nginx.apex_root_snippet_template)

        # Remove the www redirect
        logger.log_info("Removing www redirect")
        self.connection.run_checked([self.nginx_manager_tool, "remove_conf", f"{self.app_name}.conf"], sudo = True)
        return True

    def post_install(self):

        # Seeding is opt-out
        if not self.seed_enabled:
            logger.log_info("Wordpress seeding disabled, skipping")
            return True

        # Wait for the site to answer before running wp-cli against it
        if not self.wait_for_service_health("wordpress"):
            logger.log_error("Wordpress did not become healthy, skipping seed")
            return False

        # Ship the seed script and its content from the repo
        logger.log_info("Transferring seed content")
        seed_source = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordpress")
        self.connection.transfer_files(seed_source, f"{self.get_app_dir()}/seed")

        # Run the seed. The wordpress:cli entrypoint is wp itself, so the
        # shell has to be named explicitly.
        logger.log_info("Seeding Wordpress content")
        app_dir = self.get_app_dir()
        self.connection.set_current_working_directory(app_dir)
        code = self.connection.run_blocking(self.docker_compose_command +
            ["--env-file", f"{app_dir}/.env", "run", "--rm", "--entrypoint", "/bin/sh", "wpcli", "/seed/seed.sh"])
        self.connection.set_current_working_directory(None)
        if code != 0:
            logger.log_error(f"Wordpress seeding failed (exit {code})")
            return False
        return True
