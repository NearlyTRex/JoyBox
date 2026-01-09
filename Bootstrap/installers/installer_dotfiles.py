# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# Marker for idempotency detection
JOYBOX_MARKER = "# JOYBOX_DOTFILES_MANAGED"

# Dotfiles
class Dotfiles(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)

        # Paths
        self.bashrc_path = os.path.expandvars("$HOME/.bashrc")
        self.bash_profile_path = os.path.expandvars("$HOME/.bash_profile")
        self.joybox_config_dir = os.path.expandvars("$HOME/.joybox")

        # Get JoyBox root from config or derive from script location
        scripts_dir = self.config.get_value("UserData.Dirs", "scripts_dir")
        if scripts_dir:
            self.joybox_root = scripts_dir.replace("/Scripts", "")
        else:
            self.joybox_root = os.path.expandvars("$HOME/Repositories/JoyBox")

        # Template directory (relative to this file)
        self.template_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dotfiles"
        )

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def is_installed(self):
        if not self.connection.does_file_or_directory_exist(self.bashrc_path):
            return False
        content = self.connection.read_file(self.bashrc_path)
        if content is None:
            return False
        return JOYBOX_MARKER in content

    def _read_template(self, template_name):
        template_path = os.path.join(self.template_dir, template_name)
        try:
            with open(template_path, "r") as f:
                return f.read()
        except Exception as e:
            util.log_error(f"Failed to read template: {template_path}")
            util.log_error(str(e))
            return None

    def _backup_existing(self, path):
        if self.connection.does_file_or_directory_exist(path):
            backup_path = f"{path}.joybox.backup"
            util.log_info(f"Backing up existing {path} to {backup_path}")
            self.connection.copy_file_or_directory(path, backup_path)

    def install(self):

        # Start install
        util.log_info("Installing JoyBox dotfiles")

        # Create ~/.joybox directory
        util.log_info("Creating JoyBox config directory")
        self.connection.make_directory(self.joybox_config_dir)

        # Backup existing files
        self._backup_existing(self.bashrc_path)
        self._backup_existing(self.bash_profile_path)

        # Read and process bashrc template
        bashrc_template = self._read_template("bashrc.template")
        if bashrc_template is None:
            return False
        bashrc_content = f"{JOYBOX_MARKER}\n" + bashrc_template.format(
            joybox_root=self.joybox_root
        )

        # Read bash_profile template
        bash_profile_template = self._read_template("bash_profile.template")
        if bash_profile_template is None:
            return False
        bash_profile_content = f"{JOYBOX_MARKER}\n" + bash_profile_template

        # Write main dotfiles
        util.log_info("Writing .bashrc")
        if not self.connection.write_file(self.bashrc_path, bashrc_content):
            return False
        util.log_info("Writing .bash_profile")
        if not self.connection.write_file(self.bash_profile_path, bash_profile_content):
            return False

        # Install JoyBox-specific config files
        joybox_files = [
            ("joybox_aliases.sh", f"{self.joybox_config_dir}/aliases.sh"),
            ("joybox_functions.sh", f"{self.joybox_config_dir}/functions.sh"),
            ("joybox_completions.sh", f"{self.joybox_config_dir}/completions.sh"),
        ]
        for template_name, dest_path in joybox_files:
            util.log_info(f"Installing {dest_path}")
            content = self._read_template(template_name)
            if content is None:
                return False
            if not self.connection.write_file(dest_path, content):
                return False

        # All done
        util.log_info("Dotfiles installation complete")
        return True

    def uninstall(self):

        # Start uninstall
        util.log_info("Uninstalling JoyBox dotfiles")

        # Restore backups if they exist
        for path in [self.bashrc_path, self.bash_profile_path]:
            backup_path = f"{path}.joybox.backup"
            if self.connection.does_file_or_directory_exist(backup_path):
                util.log_info(f"Restoring {path} from backup")
                self.connection.move_file_or_directory(backup_path, path)
            else:
                util.log_info(f"Removing {path}")
                self.connection.remove_file_or_directory(path)

        # Remove JoyBox config directory
        util.log_info("Removing JoyBox config directory")
        self.connection.remove_file_or_directory(self.joybox_config_dir)

        # All done
        util.log_info("Dotfile uninstallation complete")
        return True
