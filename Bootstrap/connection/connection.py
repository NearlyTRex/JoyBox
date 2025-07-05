# Imports
import os
import sys
import copy

# Local imports
import util
import tools

class Connection:
    def __init__(
        self,
        config,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        self.config = config.copy()
        self.flags = flags.copy()
        self.options = options.copy()

    def copy(self):
        return copy.deepcopy(self)

    def setup(self):
        pass

    def teardown(self):
        pass

    def set_current_working_directory(self, cwd):
        self.options.cwd = cwd

    def set_environment(self, env):
        self.options.env = env

    def set_environmentVar(self, var, value):
        self.options.env[var] = value

    def unset_environment_var(self, var):
        del self.options.env[var]

    def set_config(self, config):
        self.config = config

    def get_config(self):
        return self.config

    def set_flags(self, flags):
        self.flags = flags

    def get_flags(self):
        return self.flags

    def set_options(self, options):
        self.options = options

    def get_options(self):
        return self.options

    def create_command_string(self, cmd):
        if not cmd:
            return ""
        if len(cmd) == 0:
            return ""
        if isinstance(cmd, str):
            return copy.deepcopy(cmd)
        if isinstance(cmd, list):
            cmd_str = ""
            for cmd_segment in cmd:
                if " " in cmd_segment:
                    cmd_str += " " + "\"" + cmd_segment + "\""
                else:
                    cmd_str += " " + cmd_segment
            cmd_str = cmd_str.strip()
            return cmd_str
        return ""

    def create_command_list(self, cmd):
        if not cmd:
            return []
        if len(cmd) == 0:
            return []
        if isinstance(cmd, list):
            return copy.deepcopy(cmd)
        if isinstance(cmd, str):
            return cmd.split(" ")
        return []

    def clean_command_output(self, output):
        try:
            return output.decode("utf-8", "ignore")
        except:
            return output

    def mark_command_as_sudo(self, cmd):
        if util.is_linux_platform():
            if isinstance(cmd, str):
                return f"sudo {cmd}"
            elif isinstance(cmd, list):
                return ["sudo"] + cmd
        return cmd

    def print_command(self, cmd):
        if isinstance(cmd, str):
            util.log_info("Running \"%s\"" % cmd)
        if isinstance(cmd, list):
            util.log_info("Running \"%s\"" % " ".join(cmd))

    def run_output(self, cmd, sudo = False):
        return ""

    def run_return_code(self, cmd, sudo = False):
        return 0

    def run_blocking(self, cmd, sudo = False):
        return 0

    def run_interactive(self, cmd, sudo = False):
        return 0

    def run_checked(self, cmd, sudo = False, throw_exception = False):
        return None

    def make_temporary_directory(self):
        return None

    def make_directory(self, src, sudo = False):
        self.run_checked([
            tools.get_make_dir_tool(self.config),
            "-p",
            src
        ], sudo = sudo)

    def remove_file_or_directory(self, src, sudo = False):
        self.run_checked([
            tools.get_remove_tool(self.config),
            "-rf",
            src
        ], sudo = sudo)

    def copy_file_or_directory(self, src, dest, sudo = False):
        self.run_checked([
            tools.get_copy_tool(self.config),
            src,
            dest
        ], sudo = sudo)

    def move_file_or_directory(self, src, dest, sudo = False):
        self.run_checked([
            tools.get_move_tool(self.config),
            src,
            dest
        ], sudo = sudo)

    def link_file_or_directory(self, src, dest, sudo = False):
        self.run_checked([
            tools.get_link_tool(self.config),
            "-sf", src,
            dest
        ], sudo = sudo)

    def does_file_or_directory_exist(self, src):
        return False

    def transfer_files(self, src, dest, excludes = []):
        return False

    def read_file(self, src):
        return None

    def write_file(self, src, contents):
        return False

    def download_file(self, url, dest, sudo = False):
        self.run_checked([
            tools.get_curl_tool(self.config),
            "-L",
            "-o", dest,
            url
        ], sudo = sudo)

    def extract_tar_archive(self, src, dest, sudo = False):
        self.run_checked([
            tools.get_tar_tool(self.config),
            "-xf", src,
            "-C", dest
        ], sudo = sudo)

    def change_owner(self, src, owner, sudo = False):
        self.run_checked([
            tools.get_change_owner_tool(self.config),
            "-R",
            owner,
            src
        ], sudo = sudo)

    def change_permission(self, src, permission, sudo = False):
        self.run_checked([
            tools.get_change_permission_tool(self.config),
            "-R",
            permission,
            src
        ], sudo = sudo)

    def add_to_crontab(self, pattern):
        try:
            if self.flags.verbose:
                util.log_info(f"Adding to crontab: {pattern}")
            if not self.flags.pretend_run:
                output = self.run_output(["crontab", "-l"])
                if output is None or "no crontab for" in output.lower():
                    output = ""
                lines = output.splitlines()
                pattern = pattern.strip()
                if pattern not in [line.strip() for line in lines]:
                    tmp_crontab = "/tmp/crontab_update"
                    new_cron = f"{output.strip()}\n{pattern}" if output.strip() else pattern
                    new_cron += "\n"
                    self.write_file(tmp_crontab, new_cron)
                    self.run_checked(["crontab", tmp_crontab])
                    self.remove_file_or_directory(tmp_crontab)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(f"Unable to add to crontab: {pattern}")
                util.log_error(e)
                util.quit_program()
            return False

    def remove_from_crontab(self, pattern):
        try:
            if self.flags.verbose:
                util.log_info(f"Removing from crontab: {pattern}")
            if not self.flags.pretend_run:
                output = self.run_output(["crontab", "-l"])
                if output is None or "no crontab for" in output.lower():
                    output = ""
                lines = output.splitlines() if output else []
                new_lines = [line for line in lines if line.strip() != pattern.strip()]
                if lines == new_lines:
                    return True
                tmp_crontab = "/tmp/crontab_update"
                new_cron = "\n".join(new_lines)
                new_cron += "\n"
                self.write_file(tmp_crontab, new_cron)
                self.run_checked(["crontab", tmp_crontab])
                self.remove_file_or_directory(tmp_crontab)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(f"Unable to remove from crontab: {pattern}")
                util.log_error(e)
                util.quit_program()
            return False

    def add_to_path(self, src):
        if util.is_windows_platform():
            return self.add_to_windows_path(src)
        else:
            return self.add_to_unix_path(src)

    def add_to_windows_path(self, src):
        try:
            if self.flags.verbose:
                util.log_info(f"Adding {src} to path")
            if not self.flags.pretend_run:

                # Get current path
                current_path = self.run_output([
                    "powershell",
                    "-Command",
                    '[Environment]::GetEnvironmentVariable("PATH", "User")'
                ])
                current_paths = current_path.split(";") if current_path else []
                current_paths = [p.strip() for p in current_path.split(";") if p.strip()]
                if src.strip() in current_paths:
                    return True

                # Append path
                new_paths = ";".join(current_paths + [src])
                new_paths_escaped = new_paths.replace('"', '`"')
                code = self.run_return_code([
                    "powershell",
                    "-Command",
                    f'[Environment]::set_environmentVariable("PATH", "{new_paths_escaped}", "User")'
                ])
                return code == 0
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(f"Unable to add {src} to path")
                util.log_error(e)
                util.quit_program()
            return False

    def add_to_unix_path(self, src):
        try:
            if self.flags.verbose:
                util.log_info(f"Adding {src} to path")
            if not self.flags.pretend_run:

                # Get possible profiles
                profile_candidates = [
                    "~/.bash_profile",
                    "~/.bashrc",
                    "~/.zshrc",
                    "~/.profile"
                ]

                # Get profile
                profile_file = profile_candidates[0]
                for candidate in profile_candidates:
                    if self.does_file_or_directory_exist(candidate):
                        profile_file = candidate
                        break

                # Read current profile
                existing_content = self.read_file(profile_file)
                if not existing_content:
                    existing_content = ""

                # Add to profile
                export_line = f'export PATH="{src}:$PATH"\n'
                if export_line not in existing_content:
                    new_content = existing_content + "\n" + export_line + "\n"
                    return self.write_file(profile_file, new_content)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(f"Unable to add {src} to path")
                util.log_error(e)
                util.quit_program()
            return False
