# Imports
import os
import sys

# Local imports
import util
import tools
from . import installer

# Nginx config template
nginx_config_template = """
server {{
    listen 80;
    server_name {subdomain}.{domain};

    location /.well-known/acme-challenge/ {{
        root /var/www/html;
    }}

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

# Docker compose file
docker_compose_template = """
version: '3.8'
services:
  wordpress:
    image: wordpress:latest
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
WORDPRESS_PORT_HTTPS={port_https}
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
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.Wordpress", "wordpress_subdomain"),
            "port_http": self.config.GetValue("UserData.Wordpress", "wordpress_port_http")
        }
        self.env_values = {
            "db_user": self.config.GetValue("UserData.Wordpress", "wordpress_db_user"),
            "db_password": self.config.GetValue("UserData.Wordpress", "wordpress_db_pass"),
            "db_name": self.config.GetValue("UserData.Wordpress", "wordpress_db_name"),
            "db_root_password": self.config.GetValue("UserData.Wordpress", "wordpress_db_root_pass"),
            "port_http": self.config.GetValue("UserData.Wordpress", "wordpress_port_http"),
            "port_https": self.config.GetValue("UserData.Wordpress", "wordpress_port_https")
        }
        self.docker_tool = tools.GetDockerTool(self.config)
        self.docker_compose_tool = tools.GetDockerComposeTool(self.config)
        self.nginx_manager_tool = "/usr/local/bin/manager_nginx.sh"

    def IsInstalled(self):
        containers = self.connection.RunOutput("docker ps -a --format '{{.Names}}'")
        return any(name == self.app_name for name in containers.splitlines())

    def Install(self):

        # Create directory
        util.LogInfo("Making directory")
        self.connection.MakeDirectory(self.app_dir)

        # Write docker compose
        util.LogInfo("Writing docker compose")
        if self.connection.WriteFile(f"/tmp/docker-compose.yml", docker_compose_template):
            self.connection.MoveFileOrDirectory("/tmp/docker-compose.yml", f"{self.app_dir}/docker-compose.yml")

        # Write docker env
        util.LogInfo("Writing docker env")
        if self.connection.WriteFile(f"/tmp/.env", env_template.format(**self.env_values)):
            self.connection.MoveFileOrDirectory("/tmp/.env", f"{self.app_dir}/.env")

        # Create Nginx entry
        util.LogInfo("Creating Nginx entry")
        if self.connection.WriteFile(f"/tmp/{self.app_name}.conf", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_conf", f"/tmp/{self.app_name}.conf"], sudo = True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.RemoveFileOrDirectory(f"/tmp/{self.app_name}.conf")

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)

        # Start docker
        util.LogInfo("Starting docker")
        self.connection.GetOptions().SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "up", "-d", "--build"])
        return True

    def Uninstall(self):

        # Stop docker
        util.LogInfo("Stopping docker")
        self.connection.GetOptions().SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "down", "-v"])

        # Remove directory
        util.LogInfo("Removing directory")
        self.connection.RemoveFileOrDirectory(self.app_dir)

        # Remove Nginx configuration
        util.LogInfo("Removing Nginx entry")
        self.connection.RunChecked([self.nginx_manager_tool, "remove_conf", f"{self.app_name}.conf"], sudo = True)

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True
