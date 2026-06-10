# Imports
import os
import sys

# Local imports
import util
import constants
from . import installer

# Managed block markers
BLOCK_BEGIN = "# >>> JOYBOX MANAGED BLOCK >>>"
BLOCK_END = "# <<< JOYBOX MANAGED BLOCK <<<"
BLOCK_NOTE = "# Managed by JoyBox Bootstrap (dotfiles). Edits inside this block are overwritten."

# Dotfiles
class Dotfiles(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)

        # JoyBox paths
        self.joybox_config_dir = os.path.expandvars("$HOME/.joybox")
        self.joybox_root = util.get_repo_root(self.config)

        # Bash paths
        self.bashrc_path = os.path.expandvars("$HOME/.bashrc")
        self.bash_profile_path = os.path.expandvars("$HOME/.bash_profile")

        # Template + capture directories (relative to this file)
        self.template_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dotfiles"
        )
        self.captured_dir = os.path.join(self.template_dir, "captured")

        # Shell config files installed into ~/.joybox and sourced by the managed block
        self.joybox_shell_files = [
            ("shell.sh", "shell.sh"),
            ("joybox_aliases.sh", "aliases.sh"),
            ("joybox_functions.sh", "functions.sh"),
            ("joybox_completions.sh", "completions.sh"),
        ]

        # Additional top-level dotfiles managed (deployed from captured/, captured on backup).
        # repo name is the home name without the leading dot.
        self.managed_dotfiles = [
            ".gitconfig",
            ".tmux.conf",
            ".vimrc",
            ".inputrc",
        ]

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
        return BLOCK_BEGIN in content

    def get_template(self, template_name):
        template_path = os.path.join(self.template_dir, template_name)
        try:
            with open(template_path, "r") as f:
                return f.read()
        except Exception as e:
            util.log_error(f"Failed to read template: {template_path}")
            util.log_error(str(e))
            return None

    def get_repo_name(self, home_name):
        return home_name[1:] if home_name.startswith(".") else home_name

    def deploy_managed_dotfiles(self):
        for home_name in self.managed_dotfiles:
            repo_path = os.path.join(self.captured_dir, self.get_repo_name(home_name))
            home_path = os.path.expandvars(f"$HOME/{home_name}")
            if not os.path.exists(repo_path):
                continue
            if self.connection.does_file_or_directory_exist(home_path):
                backup_path = f"{home_path}.joybox.backup"
                if not self.connection.does_file_or_directory_exist(backup_path):
                    self.connection.copy_file_or_directory(home_path, backup_path)
            util.log_info(f"Deploying {home_name} from captured dotfiles")
            self.connection.copy_file_or_directory(repo_path, home_path)

    def strip_managed_block(self, content, begin, end):
        if begin not in content or end not in content:
            return content
        before, _, rest = content.partition(begin)
        _, _, after = rest.partition(end)
        return (before.rstrip() + "\n" + after.lstrip("\n")).strip() + "\n"

    def inject_managed_block(self, path, body, begin, end, note = None, backup_suffix = ".joybox.backup"):
        existing = ""
        if self.connection.does_file_or_directory_exist(path):
            existing = self.connection.read_file(path) or ""
        if begin not in existing and existing.strip():
            backup_path = f"{path}{backup_suffix}"
            if not self.connection.does_file_or_directory_exist(backup_path):
                util.log_info(f"Backing up original {path} to {backup_path}")
                self.connection.copy_file_or_directory(path, backup_path)
        base = self.strip_managed_block(existing, begin, end).rstrip()
        parts = [begin] + ([note] if note else []) + [body.rstrip(), end]
        block = "\n".join(parts)
        new_content = (base + "\n\n" + block + "\n") if base else (block + "\n")
        util.log_info(f"Updating managed block in {path}")
        return self.connection.write_file(path, new_content)

    def install(self):
        util.log_info("Installing JoyBox dotfiles")

        # Create ~/.joybox directory
        util.log_info("Creating JoyBox config directory")
        self.connection.make_directory(self.joybox_config_dir)

        # Install the shell config files into ~/.joybox
        for template_name, dest_name in self.joybox_shell_files:
            dest_path = f"{self.joybox_config_dir}/{dest_name}"
            util.log_info(f"Installing {dest_path}")
            content = self.get_template(template_name)
            if content is None:
                return False
            if not self.connection.write_file(dest_path, content):
                return False

        # Inject the managed block into .bashrc (sources ~/.joybox/*.sh when interactive)
        bashrc_block = "\n".join([
            f'export JOYBOX_ROOT="{self.joybox_root}"',
            "case $- in",
            "    *i*)",
            "        for __jb_f in shell aliases functions completions; do",
            '            [ -f "$HOME/.joybox/$__jb_f.sh" ] && source "$HOME/.joybox/$__jb_f.sh"',
            "        done",
            "        unset __jb_f",
            "        ;;",
            "esac",
        ])
        if not self.inject_managed_block(
                self.bashrc_path, bashrc_block, BLOCK_BEGIN, BLOCK_END, BLOCK_NOTE):
            return False

        # Inject the managed block into .bash_profile (sources .bashrc)
        bash_profile_block = '[ -f "$HOME/.bashrc" ] && source "$HOME/.bashrc"'
        if not self.inject_managed_block(
                self.bash_profile_path, bash_profile_block, BLOCK_BEGIN, BLOCK_END, BLOCK_NOTE):
            return False

        # Restore any captured top-level dotfiles (.gitconfig, .tmux.conf, ...)
        self.deploy_managed_dotfiles()

        # All done
        util.log_info("Dotfiles installation complete")
        return True

    def uninstall(self):
        util.log_info("Uninstalling JoyBox dotfiles")

        # Remove just the managed block from .bashrc / .bash_profile (leave the rest)
        for path in [self.bashrc_path, self.bash_profile_path]:
            if not self.connection.does_file_or_directory_exist(path):
                continue
            content = self.connection.read_file(path)
            if content is None:
                continue
            if BLOCK_BEGIN in content:
                util.log_info(f"Removing managed block from {path}")
                self.connection.write_file(
                    path, self.strip_managed_block(content, BLOCK_BEGIN, BLOCK_END))

        # Restore any managed-dotfile backups we created
        for home_name in self.managed_dotfiles:
            home_path = os.path.expandvars(f"$HOME/{home_name}")
            backup_path = f"{home_path}.joybox.backup"
            if self.connection.does_file_or_directory_exist(backup_path):
                util.log_info(f"Restoring {home_path} from backup")
                self.connection.move_file_or_directory(backup_path, home_path)

        # Remove JoyBox config directory
        util.log_info("Removing JoyBox config directory")
        self.connection.remove_file_or_directory(self.joybox_config_dir)

        # All done
        util.log_info("Dotfile uninstallation complete")
        return True

    def backup(self):
        util.log_info("Capturing dotfiles into the repo")

        # Make captures dir
        self.connection.make_directory(self.captured_dir)

        # Build capture list
        # Only the genuinely-custom dotfiles are captured. The shell files
        # (.bashrc/.bash_profile) are managed by the block + ~/.joybox/shell.sh
        # masters, so capturing whole copies would duplicate them.
        capture_list = [
            (os.path.expandvars(f"$HOME/{home_name}"), self.get_repo_name(home_name))
            for home_name in self.managed_dotfiles
        ]

        # Capture files
        captured = 0
        for src_path, repo_name in capture_list:
            if not self.connection.does_file_or_directory_exist(src_path):
                continue
            dest_path = os.path.join(self.captured_dir, repo_name)
            util.log_info(f"Capturing {src_path} -> dotfiles/captured/{repo_name}")
            self.connection.copy_file_or_directory(src_path, dest_path)
            captured += 1

        # All done
        util.log_info(f"Captured {captured} dotfile(s) into {self.captured_dir}")
        util.log_info("Review and commit Bootstrap/dotfiles/captured/ to version them")
        return True
