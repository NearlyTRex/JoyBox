# Imports
import os
import sys

# Local imports
import util
from . import installer

# Default nginx config file
nginx_config_template = """
server {{
    listen 80;
    server_name www.{domain};

    location / {{
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }}

    location /.well-known/acme-challenge/ {{
        root /var/www/html;
    }}

    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/www.{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/www.{domain}/privkey.pem;

    return 301 https://$host$request_uri;
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

# Env file
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
        super.__init__(config, connection, flags, options)
        self.app_name = "wordpress"
        self.app_dir = f"/opt/apps/{self.app_name}"
        self.nginx_available_conf = f"/etc/nginx/sites-available/{self.app_name}.conf"
        self.nginx_enabled_conf = f"/etc/nginx/sites-enabled/{self.app_name}.conf"
        self.template_values = {
            "domain": self.config["UserData.Servers"]["domain_name"],
            "db_user": self.config["UserData.Wordpress"]["wordpress_db_user"],
            "db_password": self.config["UserData.Wordpress"]["wordpress_db_pass"],
            "db_name": self.config["UserData.Wordpress"]["wordpress_db_name"],
            "db_root_password": self.config["UserData.Wordpress"]["wordpress_db_root_pass"]
        }

    def IsInstalled(self):
        containers = self.connection.RunOutput("sudo docker ps --format '{{.Names}}'")
        return any("wordpress" in name for name in containers.splitlines())

    def Install(self):
        util.LogInfo("Installing WordPress")
        self.connection.RunChecked(f"sudo mkdir -p {self.app_dir}")
        self.connection.WriteFile(f"/tmp/{self.app_name}.conf", nginx_config_template.format(**self.template_values))
        self.connection.WriteFile(f"/tmp/docker-compose.yml", docker_compose_template.format(**self.template_values))
        self.connection.WriteFile(f"/tmp/.env", env_template.format(**self.template_values))
        self.connection.RunChecked(f"sudo mv /tmp/{self.app_name}.conf {self.nginx_available_conf}")
        self.connection.RunChecked(f"sudo mv /tmp/docker-compose.yml {self.app_dir}/docker-compose.yml")
        self.connection.RunChecked(f"sudo mv /tmp/.env {self.app_dir}/.env")
        self.connection.RunChecked(f"sudo ln -sf {self.nginx_available_conf} {self.nginx_enabled_conf}")
        self.connection.RunChecked("sudo systemctl reload nginx")
        self.connection.GetOptions().SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked("sudo docker-compose --env-file .env up -d --build")
        return True

    def Uninstall(self):
        util.LogInfo("Uninstalling WordPress")
        self.connection.GetOptions().SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked("sudo docker-compose down -v")
        self.connection.RunChecked(f"sudo rm -rf {self.app_dir}")
        self.connection.RunChecked(f"sudo rm -f {self.nginx_available_conf}")
        self.connection.RunChecked(f"sudo rm -f {self.nginx_enabled_conf}")
        self.connection.RunChecked("sudo systemctl reload nginx")
        return True
