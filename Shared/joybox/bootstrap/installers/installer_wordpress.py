# Imports
import os

# Local imports
from joybox import bootstrap
from joybox import settings
from joybox import serverinfo
from joybox import runoptions
from joybox import logger
from . import installer_dockerapp
from . import installer_nginx

# Apex root snippet template
#
# Replaces the static snippet installed by the nginx component, so WordPress
# serves the apex domain without a second server block claiming the same
# server_name.
APEX_PROXY_SNIPPET_TEMPLATE = """
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
NGINX_REDIRECT_CONFIG_TEMPLATE = """
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
DOCKER_COMPOSE_TEMPLATE = """
services:
  wordpress:
    image: ${WORDPRESS_IMAGE}
    restart: always
    ports:
      - "127.0.0.1:${WORDPRESS_PORT_HTTP}:80"
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
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
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
ENV_TEMPLATE = """
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

# Runs WordPress with MariaDB in docker on the apex domain, redirecting www,
# and seeds it with wp-cli from the repo unless seeding is turned off
class Wordpress(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "wordpress"
        self.nginx_config_values = {
            "domain": serverinfo.get_domain_name(),
            "subdomain": settings.get_value("UserData.Wordpress", "wordpress_subdomain"),
            "port_http": settings.get_value("UserData.Wordpress", "wordpress_port_http")
        }
        self.domain_name = serverinfo.get_domain_name()
        self.site_url = f"https://{self.domain_name}"
        self.env_values = self._get_env_values()
        self.seed_enabled = str(settings.get_value("UserData.Wordpress", "wordpress_seed_enabled",
            default_value = "True", throw_exception = False)).strip().lower() in ["true", "1", "yes"]

        # Templates
        self.docker_compose_template = DOCKER_COMPOSE_TEMPLATE
        self.env_template = ENV_TEMPLATE
        self.app_subdirs = ["seed"]

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http", "db_user", "db_name", "db_password", "db_root_password",
            "admin_user", "admin_pass", "admin_email"]

        # Backup
        self.backup_label = "Wordpress"
        self.backup_database = "db"
        self.backup_volumes = ["wp_data"]

    # The .env template values: database credentials, site details and the admin login
    def _get_env_values(self):
        return {
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

    # Replace the apex-root snippet with a proxy to WordPress and install the www
    # redirect; False when either cannot be staged
    def install_nginx_config(self):

        # WordPress serves the apex domain, so it takes over the apex-root
        # snippet rather than adding a server block for the same name.
        logger.log_info("Installing apex root snippet")
        if not self.install_nginx_snippet("apex-root.conf",
                APEX_PROXY_SNIPPET_TEMPLATE.format(**self.nginx_config_values)):
            return False

        # Redirect the www host to the canonical apex
        logger.log_info("Installing www redirect")
        return self.install_nginx_conf(f"{self.app_name}.conf",
            NGINX_REDIRECT_CONFIG_TEMPLATE.format(**self.nginx_config_values))

    # Put back the static apex-root snippet and remove the www redirect; False when
    # the snippet cannot be staged, after the redirect is still removed
    def uninstall_nginx_config(self):

        # Hand the apex back to the static fallback
        logger.log_info("Restoring static apex root snippet")
        restored = self.install_nginx_snippet("apex-root.conf", installer_nginx.APEX_ROOT_SNIPPET_TEMPLATE)

        # Remove the www redirect
        logger.log_info("Removing www redirect")
        self.connection.run_checked([self.nginx_manager_tool, "remove_conf", f"{self.app_name}.conf"], sudo = True)
        return restored

    # Once WordPress is healthy, copy the repo's seed files to the server and run
    # seed.sh in the wpcli container; skipped when seeding is off
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
        seed_source = os.path.join(bootstrap.get_data_dir(), "wordpress")
        seed_dir = f"{self.get_app_dir()}/seed"
        self.connection.transfer_files(seed_source, seed_dir)

        # wpcli runs as www-data (33), not the account; the seed holds repo
        # content only, so it can be world-readable
        self.connection.change_permission(seed_dir, "a+rX")

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
