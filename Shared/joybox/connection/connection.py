# Imports
import copy
import codecs
from abc import ABC, abstractmethod

# Local imports
from joybox import platform_info, runtime, cmdline
from joybox import logger, runoptions

# Base for running commands and file operations on a host, local or remote, under shared run flags and options
class Connection(ABC):
    def __init__(
        self,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        self.flags = flags.copy()
        self.options = options.copy()

    # A deep copy, so flag or option changes on it leave this connection untouched
    def copy(self):
        return copy.deepcopy(self)

    # Open whatever the transport needs before use; nothing for the base
    def setup(self):
        pass

    # Close whatever setup opened; nothing for the base
    def teardown(self):
        pass

    # Directory later commands run in, stored in the run options
    def set_current_working_directory(self, cwd):
        self.options.cwd = cwd

    # Replace the whole environment later commands run with
    def set_environment(self, env):
        self.options.env = env

    # Set one variable in the environment later commands run with
    def set_environment_var(self, var, value):
        self.options.env[var] = value

    # Drop one variable from the command environment; KeyError when it is not set
    def unset_environment_var(self, var):
        del self.options.env[var]

    # Replace the run flags (verbose, pretend, exit on failure) wholesale
    def set_flags(self, flags):
        self.flags = flags

    # The run flags object itself, not a copy
    def get_flags(self):
        return self.flags

    # Replace the run options (cwd, env, shell, output targets) wholesale
    def set_options(self, options):
        self.options = options

    # The run options object itself, not a copy
    def get_options(self):
        return self.options

    # Decode byte chunks as UTF-8, echo them live to the log and record each non-blank line
    def stream_command_output(self, chunks):
        decoder = codecs.getincrementaldecoder("utf-8")(errors = "ignore")
        line = ""
        for chunk in chunks:
            if not chunk:
                continue
            text = decoder.decode(chunk)
            if not text:
                continue
            logger.log_output(text)
            for char in text:
                if char in ("\n", "\r"):
                    if line.strip():
                        logger.record_output(line.strip())
                    line = ""
                else:
                    line += char
        if line.strip():
            logger.record_output(line.strip())

    # Prefix a string or list command with sudo; other types pass through unchanged
    def mark_command_as_sudo(self, cmd):
        if isinstance(cmd, str):
            return f"sudo {cmd}"
        if isinstance(cmd, list):
            return ["sudo"] + cmd
        return cmd

    # Log the command about to run, with sensitive arguments masked
    def print_command(self, cmd):
        masked = cmdline.mask_sensitive_args(cmd)
        if isinstance(masked, str):
            logger.log_info("Running \"%s\"" % masked)
        if isinstance(masked, list):
            logger.log_info("Running \"%s\"" % " ".join(masked))

    # Run a command and return its captured stdout as text
    @abstractmethod
    def run_output(self, cmd, sudo = False):
        ...

    # Run a command and return its exit code
    @abstractmethod
    def run_return_code(self, cmd, sudo = False):
        ...

    # Run a command to completion, streaming its output to the log; returns the exit code
    @abstractmethod
    def run_blocking(self, cmd, sudo = False):
        ...

    # Run a command attached to the user's terminal; returns the exit code
    @abstractmethod
    def run_interactive(self, cmd, sudo = False):
        ...

    # Run a command and fail on a nonzero exit: raise when asked, otherwise quit the program
    @abstractmethod
    def run_checked(self, cmd, sudo = False, throw_exception = False):
        ...

    # The home directory of the user on the target host
    @abstractmethod
    def get_home_directory(self):
        ...

    # Separator for building paths on the target host; forward slash unless overridden
    def get_path_separator(self):
        return "/"

    # Expand a leading ~ or ~/ to the target's home; other paths, and ~user, come back unchanged
    def resolve_home_path(self, src):
        if not isinstance(src, str) or not src.startswith("~"):
            return src
        if len(src) > 1 and src[1] not in ("/", "\\"):
            return src
        home = self.get_home_directory()
        if not home:
            return src
        separator = self.get_path_separator()
        remainder = src[1:].lstrip("/\\")
        if not remainder:
            return home
        return home.rstrip("/\\") + separator + remainder.replace("/", separator)

    # Log and quit when exit on failure is set; otherwise return the given fallback value
    def handle_error(self, message, error, return_value = False):
        if self.flags.exit_on_failure:
            logger.log_error(message)
            logger.log_error(error)
            runtime.quit_program()
        return return_value

    # Create a scratch directory on the target and return its path; None on failure or pretend run
    @abstractmethod
    def make_temporary_directory(self):
        ...

    # Create a directory and its parents on the target; True on success
    @abstractmethod
    def make_directory(self, src, sudo = False):
        ...

    # Delete a file or a whole tree on the target; True on success
    @abstractmethod
    def remove_file_or_directory(self, src, sudo = False):
        ...

    # Copy a file or tree within the target host; True on success
    @abstractmethod
    def copy_file_or_directory(self, src, dest, sudo = False):
        ...

    # Move or rename a path within the target host; True on success
    @abstractmethod
    def move_file_or_directory(self, src, dest, sudo = False):
        ...

    # Make dest a symlink pointing at src on the target; True on success
    @abstractmethod
    def link_file_or_directory(self, src, dest, sudo = False):
        ...

    # Whether the path exists on the target; True during a pretend run
    @abstractmethod
    def does_file_or_directory_exist(self, src):
        ...

    # Copy a file or tree from this machine to dest on the target, skipping the excluded names
    @abstractmethod
    def transfer_files(self, src, dest, excludes = None, sudo = False):
        ...

    # Text contents of a file on the target; None when unreadable or in a pretend run
    @abstractmethod
    def read_file(self, src, sudo = False):
        ...

    # Write text to a file on the target, replacing it; True on success
    @abstractmethod
    def write_file(self, src, contents, sudo = False):
        ...

    # Fetch a URL into dest on the target; True on success
    @abstractmethod
    def download_file(self, url, dest, sudo = False):
        ...

    # Unpack a tar archive into dest on the target; True on success
    @abstractmethod
    def extract_tar_archive(self, src, dest, sudo = False):
        ...

    # Recursively set the owner of a path on the target; True on success
    @abstractmethod
    def change_owner(self, src, owner, sudo = False):
        ...

    # Recursively set the mode of a path on the target; True on success
    @abstractmethod
    def change_permission(self, src, permission, sudo = False):
        ...

    # Replace the user's whole crontab with the given text, staged through a temporary file
    def install_crontab(self, contents):
        temp_dir = self.make_temporary_directory()
        if not temp_dir:
            raise OSError("Unable to stage the crontab")
        try:
            tmp_crontab = temp_dir + "/crontab"
            if not self.write_file(tmp_crontab, contents):
                raise OSError("Unable to write %s" % tmp_crontab)
            self.run_checked(["crontab", tmp_crontab], throw_exception = True)
        finally:
            self.remove_file_or_directory(temp_dir)

    # Append a line to the user's crontab unless an identical line is already there
    def add_to_crontab(self, pattern):
        try:
            if self.flags.verbose:
                logger.log_info(f"Adding to crontab: {pattern}")
            if not self.flags.pretend_run:
                output = self.run_output(["crontab", "-l"])
                if output is None or "no crontab for" in output.lower():
                    output = ""
                lines = output.splitlines()
                pattern = pattern.strip()
                if pattern not in [line.strip() for line in lines]:
                    new_cron = f"{output.strip()}\n{pattern}" if output.strip() else pattern
                    self.install_crontab(new_cron + "\n")
            return True
        except (OSError, ValueError) as e:
            return self.handle_error(f"Unable to add to crontab: {pattern}", e, return_value = False)

    # Drop every crontab line equal to the pattern; True when nothing matched too
    def remove_from_crontab(self, pattern):
        try:
            if self.flags.verbose:
                logger.log_info(f"Removing from crontab: {pattern}")
            if not self.flags.pretend_run:
                output = self.run_output(["crontab", "-l"])
                if output is None or "no crontab for" in output.lower():
                    output = ""
                lines = output.splitlines() if output else []
                new_lines = [line for line in lines if line.strip() != pattern.strip()]
                if lines == new_lines:
                    return True
                self.install_crontab("\n".join(new_lines) + "\n")
            return True
        except (OSError, ValueError) as e:
            return self.handle_error(f"Unable to remove from crontab: {pattern}", e, return_value = False)

    # Add a directory to the user's PATH, by the Windows or Unix route for this machine
    def add_to_path(self, src):
        if platform_info.is_windows_platform():
            return self.add_to_windows_path(src)
        return self.add_to_unix_path(src)

    # Append a directory to the user-level Windows PATH via PowerShell, unless already listed
    def add_to_windows_path(self, src):
        try:
            if self.flags.verbose:
                logger.log_info(f"Adding {src} to path")
            if not self.flags.pretend_run:

                # Get current path
                current_path = self.run_output([
                    "powershell",
                    "-Command",
                    '[Environment]::GetEnvironmentVariable("PATH", "User")'
                ])
                current_paths = []
                if current_path:
                    current_paths = [p.strip() for p in current_path.split(";") if p.strip()]
                if src.strip() in current_paths:
                    return True

                # Append path
                new_paths = ";".join(current_paths + [src])
                new_paths_escaped = new_paths.replace("`", "``").replace('"', '`"').replace("$", "`$")
                code = self.run_return_code([
                    "powershell",
                    "-Command",
                    f'[Environment]::SetEnvironmentVariable("PATH", "{new_paths_escaped}", "User")'
                ])
                return code == 0
            return True
        except (OSError, ValueError) as e:
            return self.handle_error(f"Unable to add {src} to path", e, return_value = False)

    # Append a PATH export to the first existing shell profile, defaulting to ~/.bash_profile
    def add_to_unix_path(self, src):
        try:
            if self.flags.verbose:
                logger.log_info(f"Adding {src} to path")
            if not self.flags.pretend_run:

                # Get possible profiles
                profile_candidates = [
                    "~/.bash_profile",
                    "~/.bashrc",
                    "~/.zshrc",
                    "~/.profile"
                ]

                # Get profile
                profile_candidates = [
                    self.resolve_home_path(candidate) for candidate in profile_candidates]
                if profile_candidates[0].startswith("~"):
                    raise ValueError("the home directory is unknown, so no profile can be found")
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
                escaped = "".join("\\" + char if char in '"\\$`' else char for char in src)
                export_line = f'export PATH="{escaped}:$PATH"\n'
                if export_line not in existing_content:
                    new_content = existing_content + "\n" + export_line + "\n"
                    return self.write_file(profile_file, new_content)
            return True
        except (OSError, ValueError) as e:
            return self.handle_error(f"Unable to add {src} to path", e, return_value = False)
