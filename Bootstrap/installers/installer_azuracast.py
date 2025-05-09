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

# Docker compose file
docker_compose_template = """
name: azuracast
services:
    web:
        container_name: azuracast
        image: 'ghcr.io/azuracast/azuracast:${AZURACAST_VERSION:-latest}'
        labels:
            - com.centurylinklabs.watchtower.scope=azuracast
        ports:
            - '${AZURACAST_HTTP_PORT:-80}:${AZURACAST_HTTP_PORT:-80}'
            - '${AZURACAST_HTTPS_PORT:-443}:${AZURACAST_HTTPS_PORT:-443}'
            - '${AZURACAST_SFTP_PORT:-2022}:${AZURACAST_SFTP_PORT:-2022}'
            - '8000:8000'
            - '8005:8005'
            - '8006:8006'
            - '8010:8010'
            - '8015:8015'
            - '8016:8016'
            - '8020:8020'
            - '8025:8025'
            - '8026:8026'
            - '8030:8030'
            - '8035:8035'
            - '8036:8036'
            - '8040:8040'
            - '8045:8045'
            - '8046:8046'
            - '8050:8050'
            - '8055:8055'
            - '8056:8056'
            - '8060:8060'
            - '8065:8065'
            - '8066:8066'
            - '8070:8070'
            - '8075:8075'
            - '8076:8076'
            - '8090:8090'
            - '8095:8095'
            - '8096:8096'
            - '8100:8100'
            - '8105:8105'
            - '8106:8106'
            - '8110:8110'
            - '8115:8115'
            - '8116:8116'
            - '8120:8120'
            - '8125:8125'
            - '8126:8126'
            - '8130:8130'
            - '8135:8135'
            - '8136:8136'
            - '8140:8140'
            - '8145:8145'
            - '8146:8146'
            - '8150:8150'
            - '8155:8155'
            - '8156:8156'
            - '8160:8160'
            - '8165:8165'
            - '8166:8166'
            - '8170:8170'
            - '8175:8175'
            - '8176:8176'
            - '8180:8180'
            - '8185:8185'
            - '8186:8186'
            - '8190:8190'
            - '8195:8195'
            - '8196:8196'
            - '8200:8200'
            - '8205:8205'
            - '8206:8206'
            - '8210:8210'
            - '8215:8215'
            - '8216:8216'
            - '8220:8220'
            - '8225:8225'
            - '8226:8226'
            - '8230:8230'
            - '8235:8235'
            - '8236:8236'
            - '8240:8240'
            - '8245:8245'
            - '8246:8246'
            - '8250:8250'
            - '8255:8255'
            - '8256:8256'
            - '8260:8260'
            - '8265:8265'
            - '8266:8266'
            - '8270:8270'
            - '8275:8275'
            - '8276:8276'
            - '8280:8280'
            - '8285:8285'
            - '8286:8286'
            - '8290:8290'
            - '8295:8295'
            - '8296:8296'
            - '8300:8300'
            - '8305:8305'
            - '8306:8306'
            - '8310:8310'
            - '8315:8315'
            - '8316:8316'
            - '8320:8320'
            - '8325:8325'
            - '8326:8326'
            - '8330:8330'
            - '8335:8335'
            - '8336:8336'
            - '8340:8340'
            - '8345:8345'
            - '8346:8346'
            - '8350:8350'
            - '8355:8355'
            - '8356:8356'
            - '8360:8360'
            - '8365:8365'
            - '8366:8366'
            - '8370:8370'
            - '8375:8375'
            - '8376:8376'
            - '8380:8380'
            - '8385:8385'
            - '8386:8386'
            - '8390:8390'
            - '8395:8395'
            - '8396:8396'
            - '8400:8400'
            - '8405:8405'
            - '8406:8406'
            - '8410:8410'
            - '8415:8415'
            - '8416:8416'
            - '8420:8420'
            - '8425:8425'
            - '8426:8426'
            - '8430:8430'
            - '8435:8435'
            - '8436:8436'
            - '8440:8440'
            - '8445:8445'
            - '8446:8446'
            - '8450:8450'
            - '8455:8455'
            - '8456:8456'
            - '8460:8460'
            - '8465:8465'
            - '8466:8466'
            - '8470:8470'
            - '8475:8475'
            - '8476:8476'
            - '8480:8480'
            - '8485:8485'
            - '8486:8486'
            - '8490:8490'
            - '8495:8495'
            - '8496:8496'
        env_file:
            - azuracast.env
            - .env
        volumes:
            - 'station_data:/var/azuracast/stations'
            - 'backups:/var/azuracast/backups'
            - 'db_data:/var/lib/mysql'
            - 'www_uploads:/var/azuracast/storage/uploads'
            - 'shoutcast2_install:/var/azuracast/storage/shoutcast2'
            - 'stereo_tool_install:/var/azuracast/storage/stereo_tool'
            - 'rsas_install:/var/azuracast/storage/rsas'
            - 'geolite_install:/var/azuracast/storage/geoip'
            - 'sftpgo_data:/var/azuracast/storage/sftpgo'
            - 'acme:/var/azuracast/storage/acme'
            - '${EXTERNAL_MEDIA_SOURCE:-/mnt/storage/Music}:${EXTERNAL_MEDIA_MOUNT:-/var/azuracast/storage/external}:ro'
        restart: unless-stopped
        ulimits:
            nofile:
                soft: 65536
                hard: 65536
        logging:
            options:
                max-size: 1m
                max-file: '5'
    updater:
        container_name: azuracast_updater
        image: 'ghcr.io/azuracast/updater:latest'
        restart: unless-stopped
        volumes:
            - '/var/run/docker.sock:/var/run/docker.sock'
        logging:
            options:
                max-size: 1m
                max-file: '5'
volumes:
    db_data: {  }
    acme: {  }
    shoutcast2_install: {  }
    stereo_tool_install: {  }
    rsas_install: {  }
    geolite_install: {  }
    sftpgo_data: {  }
    station_data: {  }
    www_uploads: {  }
    backups: {  }
"""

# Env template
env_template = """
COMPOSE_PROJECT_NAME=azuracast
COMPOSE_HTTP_TIMEOUT=300
AZURACAST_VERSION=latest
AZURACAST_HTTP_PORT={port_http}
AZURACAST_HTTPS_PORT={port_https}
AZURACAST_SFTP_PORT=2022
AZURACAST_STATION_PORTS=8000,8005,8006,8010,8015,8016,8020,8025,8026,8030,8035,8036,8040,8045,8046,8050,8055,8056,8060,8065,8066,8070,8075,8076,8090,8095,8096,8100,8105,8106,8110,8115,8116,8120,8125,8126,8130,8135,8136,8140,8145,8146,8150,8155,8156,8160,8165,8166,8170,8175,8176,8180,8185,8186,8190,8195,8196,8200,8205,8206,8210,8215,8216,8220,8225,8226,8230,8235,8236,8240,8245,8246,8250,8255,8256,8260,8265,8266,8270,8275,8276,8280,8285,8286,8290,8295,8296,8300,8305,8306,8310,8315,8316,8320,8325,8326,8330,8335,8336,8340,8345,8346,8350,8355,8356,8360,8365,8366,8370,8375,8376,8380,8385,8386,8390,8395,8396,8400,8405,8406,8410,8415,8416,8420,8425,8426,8430,8435,8436,8440,8445,8446,8450,8455,8456,8460,8465,8466,8470,8475,8476,8480,8485,8486,8490,8495,8496
AZURACAST_PUID=1000
AZURACAST_PGID=1000
AZURACAST_COMPOSE_PRIVILEGED=false
NGINX_TIMEOUT=1800
EXTERNAL_MEDIA_SOURCE={external_media_source}
EXTERNAL_MEDIA_MOUNT={external_media_mount}
"""

# AzuraCast Env template
azuracast_env_template = """
LANG=en_US
APPLICATION_ENV=production
COMPOSER_PLUGIN_MODE=false
AUTO_ASSIGN_PORT_MIN=8500
AUTO_ASSIGN_PORT_MAX=8999
SHOW_DETAILED_ERRORS=false
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER={db_user}
MYSQL_PASSWORD={db_password}
MYSQL_DATABASE={db_name}
MYSQL_ROOT_PASSWORD={db_root_password}
MYSQL_MAX_CONNECTIONS=100
MYSQL_INNODB_BUFFER_POOL_SIZE=128M
MYSQL_INNODB_LOG_FILE_SIZE=16M
ENABLE_REDIS=true
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=1
PHP_MAX_FILE_SIZE=25M
PHP_MEMORY_LIMIT=128M
PHP_MAX_EXECUTION_TIME=30
SYNC_SHORT_EXECUTION_TIME=600
SYNC_LONG_EXECUTION_TIME=1800
NOW_PLAYING_DELAY_TIME=10
NOW_PLAYING_MAX_CONCURRENT_PROCESSES=2
PHP_FPM_MAX_CHILDREN=5
PROFILING_EXTENSION_ENABLED=0
PROFILING_EXTENSION_ALWAYS_ON=false
PROFILING_EXTENSION_HTTP_IP_WHITELIST=*
NGINX_CLIENT_MAX_BODY_SIZE=50M
NGINX_BLOCK_BOTS=true
ENABLE_WEB_UPDATER=true
"""

# AzuraCast
class AzuraCast(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.app_name = "azuracast"
        self.app_dir = f"/var/{self.app_name}"
        self.nginx_config_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.AzuraCast", "azuracast_subdomain"),
            "port_http": self.config.GetValue("UserData.AzuraCast", "azuracast_port_http")
        }
        self.env_values = {
            "port_http": self.config.GetValue("UserData.AzuraCast", "azuracast_port_http"),
            "port_https": self.config.GetValue("UserData.AzuraCast", "azuracast_port_https"),
            "external_media_source": self.config.GetValue("UserData.AzuraCast", "azuracast_external_media_source"),
            "external_media_mount": self.config.GetValue("UserData.AzuraCast", "azuracast_external_media_mount")
        }
        self.azuracast_env_values = {
            "db_user": self.config.GetValue("UserData.AzuraCast", "azuracast_db_user"),
            "db_password": self.config.GetValue("UserData.AzuraCast", "azuracast_db_pass"),
            "db_name": self.config.GetValue("UserData.AzuraCast", "azuracast_db_name"),
            "db_root_password": self.config.GetValue("UserData.AzuraCast", "azuracast_db_root_pass")
        }

    def IsInstalled(self):
        containers = self.connection.RunOutput("docker ps -a --format '{{.Names}}'")
        return any(name == self.app_name for name in containers.splitlines())

    def Install(self):

        # Create Nginx entry
        util.LogInfo("Creating Nginx entry")
        if self.connection.WriteFile(f"/tmp/{self.app_name}.conf", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_conf", f"/tmp/{self.app_name}.conf"], sudo = True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.RemoveFileOrDirectory(f"/tmp/{self.app_name}.conf")

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)

        # Install AzuraCast
        util.LogInfo("Installing AzuraCast")
        env_success = self.connection.WriteFile("/tmp/.env", env_template.format(**self.env_values))
        azuracast_env_success = self.connection.WriteFile("/tmp/azuracast.env", azuracast_env_template.format(**self.azuracast_env_values))
        docker_compose_success = self.connection.WriteFile("/tmp/docker-compose.yml", docker_compose_template)
        if env_success and azuracast_env_success and docker_compose_success:
            self.connection.RunChecked([
                self.azuracast_manager_tool,
                "install", self.app_dir,
                "--env", "/tmp/.env",
                "--azuracast_env", "/tmp/azuracast.env",
                "--compose", "/tmp/docker-compose.yml"], sudo = True)
            self.connection.RemoveFileOrDirectory("/tmp/.env")
            self.connection.RemoveFileOrDirectory("/tmp/azuracast.env")
            self.connection.RemoveFileOrDirectory("/tmp/docker-compose.yml")
        return True

    def Uninstall(self):

        # Uninstall AzuraCast
        util.LogInfo("Uninstalling AzuraCast")
        self.connection.RunChecked([self.azuracast_manager_tool, "uninstall", self.app_dir])

        # Remove Nginx configuration
        util.LogInfo("Removing Nginx entry")
        self.connection.RunChecked([self.nginx_manager_tool, "remove_conf", f"{self.app_name}.conf"], sudo = True)

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return False
