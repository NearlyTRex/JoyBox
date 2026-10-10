# Local imports
from joybox import settings
from joybox import serverinfo
from . import installer_dockerapp
from joybox import runoptions
from joybox import logger

# Docker compose template
#
# JENKINS_HOME is a named volume: with userns-remap the container cannot write
# host directories. The repositories directory is mounted read-only so jobs can
# read the git repos on the box. The admin script is copied into JENKINS_HOME
# on every start, because the image copies ref files ending in .override.
docker_compose_template = """
services:
  jenkins:
    image: ${JENKINS_IMAGE}
    container_name: jenkins
    restart: always
    ports:
      - "127.0.0.1:${JENKINS_PORT_HTTP}:8080"
      # Agent port stays on loopback: all builds run on this server. Remote
      # agents would need this republished plus an explicit firewall rule.
      - "127.0.0.1:${JENKINS_PORT_AGENT}:50000"
    volumes:
      - jenkins_home:/var/jenkins_home
      - ${JENKINS_REPOSITORIES_DIR}:/mnt/repositories:ro
      - ./joybox-admin.groovy:/usr/share/jenkins/ref/init.groovy.d/joybox-admin.groovy.override:ro
    environment:
      JAVA_OPTS: ${JENKINS_JAVA_OPTS}
      JENKINS_ADMIN_USER: ${JENKINS_ADMIN_USER}
      JENKINS_ADMIN_PASS: ${JENKINS_ADMIN_PASS}

volumes:
  jenkins_home:
"""

# .env template
env_template = """
JENKINS_PORT_HTTP={port_http}
JENKINS_PORT_AGENT={port_agent}
JENKINS_REPOSITORIES_DIR={repositories_dir}
JENKINS_JAVA_OPTS={java_opts}
JENKINS_ADMIN_USER='{admin_user}'
JENKINS_ADMIN_PASS='{admin_pass}'
"""

# Creates the admin account, or resets its password, from the container
# environment on every start. With no password set it does nothing, and the
# setup wizard runs instead.
admin_script = """
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import jenkins.model.Jenkins

def name = System.getenv("JENKINS_ADMIN_USER")
def pass = System.getenv("JENKINS_ADMIN_PASS")
if (name && pass) {
    def jenkins = Jenkins.get()
    def realm = jenkins.getSecurityRealm()
    if (!(realm instanceof HudsonPrivateSecurityRealm)) {
        realm = new HudsonPrivateSecurityRealm(false)
        jenkins.setSecurityRealm(realm)
    }
    def user = realm.getUser(name)
    if (user == null) {
        realm.createAccount(name, pass)
    } else {
        user.addProperty(HudsonPrivateSecurityRealm.Details.fromPlainPassword(pass))
    }
    if (!(jenkins.getAuthorizationStrategy() instanceof FullControlOnceLoggedInAuthorizationStrategy)) {
        def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
        strategy.setAllowAnonymousRead(false)
        jenkins.setAuthorizationStrategy(strategy)
    }
    jenkins.save()
}
"""

class Jenkins(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "jenkins"
        admin_pass = settings.get_value("UserData.Jenkins", "jenkins_admin_pass",
            default_value = "", throw_exception = False)
        self.nginx_config_values = {
            "domain": serverinfo.get_domain_name(),
            "subdomain": settings.get_value("UserData.Jenkins", "jenkins_subdomain"),
            "port_http": settings.get_value("UserData.Jenkins", "jenkins_port_http")
        }
        self.env_values = {
            "port_http": settings.get_value("UserData.Jenkins", "jenkins_port_http"),
            "port_agent": settings.get_value("UserData.Jenkins", "jenkins_port_agent"),
            "repositories_dir": settings.get_value("UserData.Jenkins", "jenkins_repositories_dir",
                default_value = "/mnt/repositories", throw_exception = False),
            "java_opts": "-Djenkins.install.runSetupWizard=false" if admin_pass else "",
            "admin_user": settings.get_value("UserData.Jenkins", "jenkins_admin_user",
                default_value = "admin", throw_exception = False),
            "admin_pass": admin_pass
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http", "port_agent", "repositories_dir"]
        self.quoted_settings = ["admin_user", "admin_pass"]

        # Backup
        self.backup_label = "Jenkins"
        self.backup_volumes = ["jenkins_home"]
        self.backup_excludes = ["./workspace", "./caches"]

    def install(self):

        # Write the admin script before the base class starts the container.
        # It holds no secret, and the container's remapped user has to read it.
        logger.log_info("Writing admin script")
        app_dir = self.get_app_dir()
        self.connection.make_directory(app_dir)
        script_path = f"{app_dir}/joybox-admin.groovy"
        if not self.connection.write_file(script_path, admin_script):
            logger.log_error(f"Unable to write the admin script for {self.app_name}")
            return False
        self.connection.change_permission(script_path, "644")
        if not self.env_values["admin_pass"]:
            logger.log_warning("jenkins_admin_pass is not set; Jenkins will run its setup wizard instead")
        return super().install()
