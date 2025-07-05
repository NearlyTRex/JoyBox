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

    location / {{
        proxy_pass http://localhost:{port_http};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;

    }}
}}
"""

# Docker compose template
docker_compose_template = """
version: '3.8'
services:
  wordpress:
    image: wordpress:latest
    restart: always
    ports:
      - "${WORDPRESS_PORT_HTTP}:80"
    environment:
      WORDPRESS_DB_HOST: ${WORDPRESS_DB_HOST}
      WORDPRESS_DB_USER: ${WORDPRESS_DB_USER}
      WORDPRESS_DB_PASSWORD: ${WORDPRESS_DB_PASSWORD}
      WORDPRESS_DB_NAME: ${WORDPRESS_DB_NAME}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s
      timeout: 10s
      retries: 3
    depends_on:
      - db

  db:
    image: mysql:5.7
    environment:
      MYSQL_DATABASE: ${WORDPRESS_DB_NAME}
      MYSQL_USER: ${WORDPRESS_DB_USER}
      MYSQL_PASSWORD: ${WORDPRESS_DB_PASSWORD}
      MYSQL_ROOT_PASSWORD: ${WORDPRESS_DB_ROOT_PASSWORD}
    volumes:
      - db_data:/var/lib/mysql

volumes:
  db_data:
"""

# Env template
env_template = """
WORDPRESS_DB_HOST=db
WORDPRESS_DB_USER={db_user}
WORDPRESS_DB_PASSWORD={db_password}
WORDPRESS_DB_NAME={db_name}
WORDPRESS_DB_ROOT_PASSWORD={db_root_password}
WORDPRESS_PORT_HTTP={port_http}
"""

# Wordpress
class Wordpress(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.app_name = "wordpress"
        self.app_dir = f"$HOME/apps/{self.app_name}"
        self.nginx_config_values = {
            "domain": self.config.get_value("UserData.Servers", "domain_name"),
            "subdomain": self.config.get_value("UserData.Wordpress", "wordpress_subdomain"),
            "port_http": self.config.get_value("UserData.Wordpress", "wordpress_port_http")
        }
        self.env_values = {
            "db_user": self.config.get_value("UserData.Wordpress", "wordpress_db_user"),
            "db_password": self.config.get_value("UserData.Wordpress", "wordpress_db_pass"),
            "db_name": self.config.get_value("UserData.Wordpress", "wordpress_db_name"),
            "db_root_password": self.config.get_value("UserData.Wordpress", "wordpress_db_root_pass"),
            "port_http": self.config.get_value("UserData.Wordpress", "wordpress_port_http")
        }

    def is_installed(self):
        containers = self.connection.run_output("docker ps -a --format '{{.Names}}'")
        return any(self.app_name in name for name in containers.splitlines())

    def install(self):

        # Create directory
        util.log_info("Creating directory")
        self.connection.make_directory(self.app_dir)

        # Write docker compose
        util.log_info("Writing docker compose")
        if self.connection.write_file(f"/tmp/docker-compose.yml", docker_compose_template):
            self.connection.move_file_or_directory("/tmp/docker-compose.yml", f"{self.app_dir}/docker-compose.yml")

        # Write docker env
        util.log_info("Writing docker env")
        if self.connection.write_file(f"/tmp/.env", env_template.format(**self.env_values)):
            self.connection.move_file_or_directory("/tmp/.env", f"{self.app_dir}/.env")

        # Create Nginx entry
        util.log_info("Creating Nginx entry")
        if self.connection.write_file(f"/tmp/{self.app_name}.conf", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.run_checked([self.nginx_manager_tool, "install_conf", f"/tmp/{self.app_name}.conf"], sudo = True)
            self.connection.run_checked([self.nginx_manager_tool, "link_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.remove_file_or_directory(f"/tmp/{self.app_name}.conf")

        # Restart Nginx
        util.log_info("Restarting Nginx")
        self.connection.run_checked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)

        # Start docker
        util.log_info("Starting docker")
        self.connection.get_options().set_current_working_directory(self.app_dir)
        self.connection.run_checked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "up", "-d", "--build"])
        return True

    def uninstall(self):

        # Stop docker
        util.log_info("Stopping docker")
        self.connection.get_options().set_current_working_directory(self.app_dir)
        self.connection.run_checked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "down", "-v"])
        self.connection.get_options().set_current_working_directory(None)

        # Remove directory
        util.log_info("Removing directory")
        self.connection.remove_file_or_directory(self.app_dir)

        # Remove Nginx entry
        util.log_info("Removing Nginx entry")
        self.connection.run_checked([self.nginx_manager_tool, "remove_conf", f"{self.app_name}.conf"], sudo = True)

        # Restart Nginx
        util.log_info("Restarting Nginx")
        self.connection.run_checked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True
