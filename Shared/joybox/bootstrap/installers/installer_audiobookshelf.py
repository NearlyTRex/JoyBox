# Local imports
from joybox import settings
from joybox import serverinfo
from . import installer_dockerapp
from joybox import runoptions
from joybox import logger

# Docker compose template
docker_compose_template = """
services:
  audiobookshelf:
    image: ${AUDIOBOOKSHELF_IMAGE}
    container_name: audiobookshelf
    restart: always
    ports:
      - "127.0.0.1:${AUDIOBOOKSHELF_PORT_HTTP}:80"
    volumes:
      - ${AUDIOBOOKSHELF_AUDIO_DIR}:/audiobooks:ro
      - config_data:/config
      - metadata_data:/metadata
volumes:
  config_data: {}
  metadata_data: {}
"""

# .env template
env_template = """
AUDIOBOOKSHELF_PORT_HTTP={port_http}
AUDIOBOOKSHELF_AUDIO_DIR={audio_dir}
"""

# Audiobookshelf Installer
class Audiobookshelf(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "audiobookshelf"
        self.nginx_config_values = {
            "domain": serverinfo.get_domain_name(),
            "subdomain": settings.get_value("UserData.Audiobookshelf", "audiobookshelf_subdomain"),
            "port_http": settings.get_value("UserData.Audiobookshelf", "audiobookshelf_port_http")
        }
        self.env_values = {
            "port_http": settings.get_value("UserData.Audiobookshelf", "audiobookshelf_port_http"),
            "audio_dir": settings.get_value("UserData.Audiobookshelf", "audiobookshelf_audio_dir")
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template
        self.nginx_config_template = installer_dockerapp.nginx_http_websocket_config_template

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http", "audio_dir"]

        # Admin created on first install
        self.admin_user = settings.get_value("UserData.Audiobookshelf", "audiobookshelf_admin_user",
            default_value = "root", throw_exception = False)
        self.admin_pass = settings.get_value("UserData.Audiobookshelf", "audiobookshelf_admin_pass",
            default_value = "", throw_exception = False)

        # Backup
        # metadata_data is regenerable cached artwork and can be many GB, so
        # it is deliberately not archived.
        self.backup_label = "Audiobookshelf"
        self.backup_volumes = ["config_data"]

    def post_install(self):

        # Without a password the first visitor to the site creates the root user
        if not self.admin_pass:
            logger.log_warning("audiobookshelf_admin_pass is not set; the first visitor to the site creates the root user")
            return True
        if self.flags.pretend_run:
            return True
        base_url = "http://127.0.0.1:%s" % self.env_values["port_http"]
        if not self.wait_for_http(f"{base_url}/status"):
            logger.log_error("Audiobookshelf did not answer, so the root user was not created")
            return False

        # Only an uninitialised server accepts a root user
        status = self.connection.run_output(["curl", "-s", f"{base_url}/status"])
        if '"isInit":false' not in status.replace(" ", ""):
            logger.log_info("Audiobookshelf already has its root user; manage it in the app")
            return True
        logger.log_info(f"Creating the Audiobookshelf root user {self.admin_user}")
        code = self.call_local_api("POST", f"{base_url}/init",
            {"newRoot": {"username": self.admin_user, "password": self.admin_pass}})
        if code != "200":
            logger.log_error(f"Unable to create the Audiobookshelf root user (HTTP {code})")
            return False
        return True
