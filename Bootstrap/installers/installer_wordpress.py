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
        return 301 https://$host$request_uri;
    }}
}}

server {{
    listen 443 ssl;
    server_name {subdomain}.{domain};

    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    location / {{
        proxy_pass http://localhost:8080;
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
      - "8080:80"
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
        self.nginx_available_conf = f"/etc/nginx/sites-available/{self.app_name}.conf"
        self.nginx_enabled_conf = f"/etc/nginx/sites-enabled/{self.app_name}.conf"
        self.nginx_config_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.Wordpress", "wordpress_subdomain")
        }
        self.env_values = {
            "db_user": self.config.GetValue("UserData.Wordpress", "wordpress_db_user"),
            "db_password": self.config.GetValue("UserData.Wordpress", "wordpress_db_pass"),
            "db_name": self.config.GetValue("UserData.Wordpress", "wordpress_db_name"),
            "db_root_password": self.config.GetValue("UserData.Wordpress", "wordpress_db_root_pass")
        }
        self.docker_tool = tools.GetDockerTool(self.config)
        self.docker_compose_tool = tools.GetDockerComposeTool(self.config)
        self.nginx_manager_tool = "/usr/local/bin/manager_nginx.sh"

    def IsInstalled(self):
        containers = self.connection.RunOutput("docker ps --format '{{.Names}}'")
        return any("wordpress" in name for name in containers.splitlines())

    def Install(self):

        # Create WordPress directory
        util.LogInfo("Making WordPress directory")
        self.connection.MakeDirectory(self.app_dir)

        # Write WordPress docker compose
        util.LogInfo("Writing WordPress docker compose")
        if self.connection.WriteFile(f"/tmp/docker-compose.yml", docker_compose_template):
            self.connection.MoveFileOrDirectory("/tmp/docker-compose.yml", f"{self.app_dir}/docker-compose.yml")

        # Write WordPress docker env
        util.LogInfo("Writing WordPress docker env")
        if self.connection.WriteFile(f"/tmp/.env", env_template.format(**self.env_values)):
            self.connection.MoveFileOrDirectory("/tmp/.env", f"{self.app_dir}/.env")

        # Create WordPress nginx entry
        util.LogInfo("Creating WordPress nginx entry")
        if self.connection.WriteFile(f"/tmp/{self.app_name}.conf", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_conf", f"/tmp/{self.app_name}.conf"], sudo = True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_conf", f"/tmp/{self.app_name}.conf"], sudo = True)
            self.connection.RemoveFileOrDirectory(f"/tmp/{self.app_name}.conf")

        # Restart nginx
        util.LogInfo("Restarting nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)

        # Build WordPress docker
        util.LogInfo("Building WordPress docker")
        self.connection.GetOptions().SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "up", "-d", "--build"])
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling WordPress")
        return True
