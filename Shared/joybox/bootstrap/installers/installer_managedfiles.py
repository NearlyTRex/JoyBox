# Imports
import os

# Local imports
import joybox.bootstrap as bootstrap
from . import installer
from joybox import runoptions
from joybox import logger
from joybox import serialization

# User config files deployed from a folder under Bootstrap
class ManagedFiles(installer.Installer):

    # Display name, Bootstrap folder, (file name, destination, service that reads it)
    # triples, and the services whose restart keeps every audio client connected
    label = None
    data_folder = None
    files = ()
    safe_services = ()

    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.data_dir = os.path.join(bootstrap.get_data_dir(), self.data_folder)

    # Names of the files the current settings deploy; the rest are removed
    def get_active_files(self):
        return [name for name, _, _ in self.files]

    # Contents to deploy for a file, given the text shipped in Bootstrap
    def render(self, name, contents):
        return contents

    # Destination of a file with the home directory expanded
    def get_destination(self, name):
        return next(os.path.expanduser(dest) for file_name, dest, _ in self.files if file_name == name)

    # Destination paths with the home directory expanded
    def get_destinations(self):
        return [self.get_destination(name) for name, _, _ in self.files]

    # Text of a file from this installer's Bootstrap folder, or None when it is missing
    def get_contents(self, name):
        return serialization.read_text_file(os.path.join(self.data_dir, name))

    # Rendered text of a file, or None when its source is missing
    def get_rendered_contents(self, name):
        contents = self.get_contents(name)
        return None if contents is None else self.render(name, contents)

    # An active file matches its rendered source; an inactive one is absent
    def is_current(self, name):
        destination = self.get_destination(name)
        exists = self.connection.does_file_or_directory_exist(destination)
        if name not in self.get_active_files():
            return not exists
        return exists and self.connection.read_file(destination) == self.get_rendered_contents(name)

    # Installed while every file is current
    def is_installed(self):
        return all(self.is_current(name) for name, _, _ in self.files)

    # Write an active file or remove an inactive one
    def apply(self, name):
        destination = self.get_destination(name)
        if name not in self.get_active_files():
            logger.log_info(f"Removing {destination}")
            self.connection.remove_file_or_directory(destination)
            return True
        contents = self.get_rendered_contents(name)
        if contents is None:
            logger.log_error(f"Failed to read {os.path.join(self.data_dir, name)}")
            return False
        if not self.connection.write_file(destination, contents):
            logger.log_error(f"Failed to write {destination}")
            return False
        return True

    # Restart the safe services now and leave the rest to the user, since
    # restarting them drops apps like Discord until they are relaunched
    def restart_services(self, services):
        services = list(dict.fromkeys(services))
        for service in services:
            if service in self.safe_services:
                logger.log_info(f"Restarting {service}")
                self.connection.run_checked(["systemctl", "--user", "restart", service])
        unsafe = [service for service in services if service not in self.safe_services]
        if unsafe:
            logger.log_warning(
                "Quit Discord and other voice apps, then apply it with: systemctl --user restart %s" % " ".join(unsafe))

    # Bring every file in line with the settings, restarting what reads the changed ones
    def install(self):
        logger.log_info(f"Installing {self.label}")
        changed = []
        for name, _, service in self.files:
            if self.is_current(name):
                continue
            if not self.apply(name):
                return False
            changed.append(service)
        self.restart_services(changed)
        logger.log_info(f"{self.label} installed successfully")
        return True

    # Remove the destinations that exist, leaving anything else in their folders
    def uninstall(self):
        logger.log_info(f"Uninstalling {self.label}")
        removed = []
        for name, _, service in self.files:
            destination = self.get_destination(name)
            if self.connection.does_file_or_directory_exist(destination):
                logger.log_info(f"Removing {destination}")
                self.connection.remove_file_or_directory(destination)
                removed.append(service)
        self.restart_services(removed)
        logger.log_info(f"{self.label} uninstalled")
        return True
