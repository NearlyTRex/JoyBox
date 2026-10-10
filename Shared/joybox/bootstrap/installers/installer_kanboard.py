# Local imports
from joybox import settings
from joybox import serverinfo
from . import installer_dockerapp
from joybox import runoptions
from joybox import logger

# Docker compose template
#
# Named volumes rather than bind mounts: with userns-remap the container cannot
# write host directories, while a new volume takes the ownership the image
# gives its mount point.
docker_compose_template = """
services:
  kanboard:
    image: ${KANBOARD_IMAGE}
    container_name: kanboard
    restart: always
    ports:
      - "127.0.0.1:${KANBOARD_PORT_HTTP}:80"
    volumes:
      - kanboard_data:/var/www/app/data
      - kanboard_plugins:/var/www/app/plugins
    environment:
      KANBOARD_ADMIN_USER: ${KANBOARD_ADMIN_USER}
      KANBOARD_ADMIN_PASS: ${KANBOARD_ADMIN_PASS}

volumes:
  kanboard_data:
  kanboard_plugins:
"""

# .env template
env_template = """
KANBOARD_PORT_HTTP={port_http}
KANBOARD_ADMIN_USER='{admin_user}'
KANBOARD_ADMIN_PASS='{admin_pass}'
"""

# Sets the admin login from the container environment. A new database starts
# with admin/admin, which is renamed to the configured user; afterwards the
# configured user's password is reset to match JoyBox.ini.
admin_script = """
require "/var/www/app/app/common.php";
$name = getenv("KANBOARD_ADMIN_USER");
$pass = getenv("KANBOARD_ADMIN_PASS");
$users = $container["userModel"];
$user = $users->getByUsername($name) ?: $users->getByUsername("admin");
if ($user) {
    $ok = $users->update(["id" => $user["id"], "username" => $name, "password" => $pass, "role" => "app-admin"]);
} else {
    $ok = $users->create(["username" => $name, "password" => $pass, "role" => "app-admin"]) !== false;
}
exit($ok ? 0 : 1);
"""

# Kanboard Installer
class Kanboard(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "kanboard"
        self.nginx_config_values = {
            "domain": serverinfo.get_domain_name(),
            "subdomain": settings.get_value("UserData.Kanboard", "kanboard_subdomain"),
            "port_http": settings.get_value("UserData.Kanboard", "kanboard_port_http")
        }
        self.env_values = {
            "port_http": settings.get_value("UserData.Kanboard", "kanboard_port_http"),
            "admin_user": settings.get_value("UserData.Kanboard", "kanboard_admin_user",
                default_value = "admin", throw_exception = False),
            "admin_pass": settings.get_value("UserData.Kanboard", "kanboard_admin_pass",
                default_value = "", throw_exception = False)
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template

        # Behavior
        # The password is required: a new Kanboard otherwise answers to admin/admin.
        self.required_settings = ["domain", "subdomain", "port_http", "admin_user", "admin_pass"]
        self.quoted_settings = ["admin_user", "admin_pass"]

        # Backup
        self.backup_label = "Kanboard"
        self.backup_volumes = ["kanboard_data", "kanboard_plugins"]

    def post_install(self):

        # The database is created and migrated by the first PHP process, so
        # the container only has to be up
        if not self.wait_for_service_health("kanboard"):
            logger.log_error("Kanboard did not become healthy, so the admin login was not set")
            return False

        # Set the admin login
        logger.log_info(f"Setting the Kanboard admin login for {self.env_values['admin_user']}")
        code = self.connection.run_blocking(["docker", "exec", "-u", "nginx", "kanboard", "php", "-r", admin_script])
        if code != 0:
            logger.log_error(f"Unable to set the Kanboard admin login (exit {code})")
            return False
        return True
