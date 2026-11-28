# Local imports
from joybox.bootstrap import constants
from joybox import connection
from joybox.bootstrap import installers
from joybox import runoptions
from . import env

# Remote Ubuntu
class RemoteUbuntu(env.Environment):
    def __init__(
        self,
        ssh_host = None,
        ssh_port = None,
        ssh_user = None,
        ssh_password = None,
        ssh_key_filepath = None,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(flags, options)

        # Set environment type
        self.set_environment_type(constants.EnvironmentType.REMOTE_UBUNTU)

        # Create connection
        self.connection = connection.ConnectionSSH(
            ssh_host = ssh_host,
            ssh_port = ssh_port,
            ssh_user = ssh_user,
            ssh_password = ssh_password,
            ssh_key_filepath = ssh_key_filepath,
            flags = self.flags,
            options = self.options)

        # Create installer options
        self.installer_options = {
            "connection": self.connection,
            "flags": self.flags,
            "options": self.options
        }

        # Create components
        self._create_components()

    # Build every server component's installer over this environment's connection
    def _create_components(self):
        self.available_components = {
            "config": installers.Config(**self.installer_options),
            "aptget": installers.AptGet(**self.installer_options),
            "dotfiles": installers.Dotfiles(**self.installer_options),
            "flatpak": installers.Flatpak(**self.installer_options),
            "nginx": installers.Nginx(**self.installer_options),
            "certbot": installers.Certbot(**self.installer_options),
            "cockpit": installers.Cockpit(**self.installer_options),
            "wordpress": installers.Wordpress(**self.installer_options),
            "audiobookshelf": installers.Audiobookshelf(**self.installer_options),
            "navidrome": installers.Navidrome(**self.installer_options),
            "filebrowser": installers.FileBrowser(**self.installer_options),
            "fitlog": installers.FitLog(**self.installer_options),
            "jenkins": installers.Jenkins(**self.installer_options),
            "kanboard": installers.Kanboard(**self.installer_options),
            "oscar": installers.Oscar(**self.installer_options)
        }

    # The sorted port strings the components serve through nginx
    def get_public_ports(self):
        ports = set()
        for component in self.available_components.values():
            ports.update(str(port) for port in getattr(component, "nginx_ports", []))
        return sorted(ports)

    # Refresh apt lists, install the selected server components stopping at the
    # first failure, then autoremove when asked
    def setup(self):
        self.connect()
        self.refresh_package_lists()

        # Process all components
        success = self.process_components("install", force=self.flags.force)
        return self.finish_with_autoremove(success)

    # Uninstall the selected components in reverse order, then autoremove when asked
    def teardown(self):

        # Process components in reverse order
        success = self.process_components("uninstall", reverse_order=True, force=self.flags.force)
        return self.finish_with_autoremove(success)
