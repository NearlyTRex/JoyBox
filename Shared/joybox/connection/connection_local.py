# Imports
import os
import sys
import copy
import subprocess
import tempfile

# Local imports
from joybox import platform_info, runtime, pathutil, cmdline, fileops
from joybox import network, archive
from joybox import logger, runoptions
from . import connection

class ConnectionLocal(connection.Connection):
    def __init__(
        self,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        if options and not options.env:
            options.env = copy.deepcopy(os.environ)
        super().__init__(flags, options)

    # Map this connection's run flags to the keyword args shared fileops
    # primitives expect, so local file operations can delegate to them.
    def _io_flags(self):
        return {
            "verbose": self.flags.verbose,
            "pretend_run": self.flags.pretend_run,
            "exit_on_failure": self.flags.exit_on_failure,
        }

    def mark_command_as_sudo(self, cmd):
        if platform_info.is_linux_platform():
            return super().mark_command_as_sudo(cmd)
        return cmd

    def run_output(self, cmd, sudo = False):
        try:
            cmd = cmdline.create_command_list(cmd, style = "split")
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                if self.options.shell:
                    cmd = cmdline.create_command_string(cmd, style = "posix")
                output = ""
                if self.options.include_stderr:
                    output = subprocess.run(
                        cmd,
                        shell = self.options.shell,
                        cwd = self.options.cwd,
                        env = self.options.env,
                        creationflags = self.options.creationflags,
                        stdout = subprocess.PIPE,
                        stderr = subprocess.STDOUT).stdout
                else:
                    output = subprocess.run(
                        cmd,
                        shell = self.options.shell,
                        cwd = self.options.cwd,
                        env = self.options.env,
                        creationflags = self.options.creationflags,
                        stdout = subprocess.PIPE).stdout
                return cmdline.clean_command_output(output.strip())
            return ""
        except subprocess.CalledProcessError as e:
            if self.flags.exit_on_failure:
                logger.log_error(e)
                runtime.quit_program()
            if self.options.include_stderr:
                return e.output
            return ""
        except Exception as e:
            if self.flags.exit_on_failure:
                logger.log_error(e)
                runtime.quit_program()
            return ""

    def run_return_code(self, cmd, sudo = False):
        try:
            cmd = cmdline.create_command_list(cmd, style = "split")
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                if self.options.shell:
                    cmd = cmdline.create_command_string(cmd, style = "posix")
                stdout = self.options.stdout
                stderr = self.options.stderr
                if pathutil.is_path_valid(self.options.stdout):
                    stdout = open(self.options.stdout, "w")
                if pathutil.is_path_valid(self.options.stderr):
                    stderr = open(self.options.stderr, "w")
                code = subprocess.call(
                    cmd,
                    shell = self.options.shell,
                    cwd = self.options.cwd,
                    env = self.options.env,
                    creationflags = self.options.creationflags,
                    stdout = stdout,
                    stderr = stderr)
                if pathutil.is_path_valid(self.options.stdout):
                    stdout.close()
                if pathutil.is_path_valid(self.options.stderr):
                    stderr.close()
                return code
            return 0
        except subprocess.CalledProcessError as e:
            if self.flags.exit_on_failure:
                logger.log_error(e)
                runtime.quit_program()
            return e.returncode
        except Exception as e:
            if self.flags.exit_on_failure:
                logger.log_error(e)
                runtime.quit_program()
            return 1

    def run_blocking(self, cmd, sudo = False):
        try:
            cmd = cmdline.create_command_list(cmd, style = "split")
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                if self.options.shell:
                    cmd = cmdline.create_command_string(cmd, style = "posix")
                process = subprocess.Popen(
                    cmd,
                    shell = self.options.shell,
                    cwd = self.options.cwd,
                    env = self.options.env,
                    creationflags = self.options.creationflags,
                    stdout = subprocess.PIPE,
                    stderr = subprocess.STDOUT,
                    bufsize = 0)
                self.stream_command_output(iter(lambda: process.stdout.read(4096), b""))
                return process.wait()
            return 0
        except subprocess.CalledProcessError as e:
            if self.flags.exit_on_failure:
                logger.log_error(e)
                runtime.quit_program()
            return e.returncode
        except Exception as e:
            if self.flags.exit_on_failure:
                logger.log_error(e)
                runtime.quit_program()
            return 1

    def run_interactive(self, cmd, sudo = False):
        return self.run_blocking(cmd, sudo = sudo)

    def run_checked(self, cmd, sudo = False, throw_exception = False):
        code = self.run_blocking(cmd = cmd, sudo = sudo)
        if code != 0:
            if throw_exception:
                raise ValueError("Unable to run command: %s" % cmd)
            else:
                runtime.quit_program(code)

    def make_temporary_directory(self):
        if self.flags.pretend_run:
            return None
        ok, temp_dir = fileops.create_temporary_directory(verbose = self.flags.verbose)
        if not ok:
            return self.handle_error("Unable to make temporary directory", temp_dir, return_value = None)
        return temp_dir

    def does_file_or_directory_exist(self, src):
        try:
            if self.flags.verbose:
                logger.log_info("Checking existence of %s" % src)
            if not self.flags.pretend_run:
                return os.path.exists(src)
            return True
        except Exception as e:
            return self.handle_error("Error checking existence of %s" % src, e)

    def transfer_files(self, src, dest, excludes = [], sudo = False):
        if sudo:
            try:
                if self.flags.verbose:
                    logger.log_info("Transferring files from %s to %s" % (src, dest))
                if self.flags.skip_existing and os.path.exists(dest):
                    return True
                if not self.flags.pretend_run:
                    cmd = ["cp", "-r", src, dest] if os.path.isdir(src) else ["cp", src, dest]
                    return self.run_return_code(cmd, sudo = True) == 0
                return True
            except Exception as e:
                return self.handle_error(f"Unable to transfer files from {src} to {dest}", e)
        return fileops.copy_file_or_directory(
            src, dest,
            excludes = excludes,
            skip_existing = self.flags.skip_existing,
            **self._io_flags())

    def read_file(self, src, sudo = False):
        try:
            if self.flags.verbose:
                logger.log_info(f"Reading file {src}")
            if not self.flags.pretend_run:
                if sudo:
                    return self.run_output(["cat", src], sudo = True)
                else:
                    contents = ""
                    with open(src, "r") as f:
                        contents = f.read()
                    return contents
            return None
        except Exception as e:
            return self.handle_error(f"Unable to read file {src}", e, return_value = None)

    def write_file(self, src, contents, sudo = False):
        if sudo:
            try:
                if self.flags.verbose:
                    logger.log_info(f"Writing file to {src}")
                if not self.flags.pretend_run:
                    with tempfile.NamedTemporaryFile(mode = "w", delete = False) as f:
                        f.write(contents)
                        temp_path = f.name
                    self.run_blocking(["mv", temp_path, src], sudo = True)
                return True
            except Exception as e:
                return self.handle_error(f"Unable to write file to {src}", e)
        return fileops.touch_file(src, contents = contents, **self._io_flags())

    def make_directory(self, src, sudo = False):
        if sudo:
            try:
                if self.flags.verbose:
                    logger.log_info(f"Making directory {src}")
                if not self.flags.pretend_run:
                    self.run_checked(["mkdir", "-p", src], sudo = True)
                return True
            except Exception as e:
                return self.handle_error(f"Unable to make directory {src}", e)
        return fileops.make_directory(src, **self._io_flags())

    def remove_file_or_directory(self, src, sudo = False):
        if sudo:
            try:
                if self.flags.verbose:
                    logger.log_info(f"Removing {src}")
                if not self.flags.pretend_run:
                    self.run_checked(["sh", "-c", "rm -rf -- %s" % src], sudo = True)
                return True
            except Exception as e:
                return self.handle_error(f"Unable to remove {src}", e)
        return fileops.remove_file_or_directory(src, **self._io_flags())

    def copy_file_or_directory(self, src, dest, sudo = False):
        if sudo:
            try:
                if self.flags.verbose:
                    logger.log_info(f"Copying {src} to {dest}")
                if not self.flags.pretend_run:
                    cmd = ["cp", "-r", src, dest] if os.path.isdir(src) else ["cp", src, dest]
                    self.run_checked(cmd, sudo = True)
                return True
            except Exception as e:
                return self.handle_error(f"Unable to copy {src} to {dest}", e)
        return fileops.copy_file_or_directory(src, dest, **self._io_flags())

    def move_file_or_directory(self, src, dest, sudo = False):
        if sudo:
            try:
                if self.flags.verbose:
                    logger.log_info(f"Moving {src} to {dest}")
                if not self.flags.pretend_run:
                    self.run_checked(["mv", src, dest], sudo = True)
                return True
            except Exception as e:
                return self.handle_error(f"Unable to move {src} to {dest}", e)
        return fileops.move_file_or_directory(src, dest, **self._io_flags())

    def link_file_or_directory(self, src, dest, sudo = False):
        if sudo:
            try:
                if self.flags.verbose:
                    logger.log_info(f"Linking {src} to {dest}")
                if not self.flags.pretend_run:
                    self.run_checked(["ln", "-sf", src, dest], sudo = True)
                return True
            except Exception as e:
                return self.handle_error(f"Unable to link {src} to {dest}", e)
        return fileops.create_symlink(src, dest, **self._io_flags())

    def download_file(self, url, dest, sudo = False):
        if sudo:
            try:
                if self.flags.verbose:
                    logger.log_info(f"Downloading {url} to {dest}")
                if not self.flags.pretend_run:
                    with tempfile.NamedTemporaryFile(delete = False) as f:
                        temp_path = f.name
                    if not network.download_url(url, output_file = temp_path, **self._io_flags()):
                        return self.handle_error(f"Unable to download {url}", "download failed")
                    self.run_checked(["mv", temp_path, dest], sudo = True)
                return True
            except Exception as e:
                return self.handle_error(f"Unable to download {url} to {dest}", e)
        return network.download_url(url, output_file = dest, **self._io_flags())

    def extract_tar_archive(self, src, dest, sudo = False):
        if sudo:
            try:
                if self.flags.verbose:
                    logger.log_info(f"Extracting {src} to {dest}")
                if not self.flags.pretend_run:
                    self.run_checked(["tar", "-xf", src, "-C", dest], sudo = True)
                return True
            except Exception as e:
                return self.handle_error(f"Unable to extract {src} to {dest}", e)
        return archive.extract_archive(src, dest, **self._io_flags())

    def change_owner(self, src, owner, sudo = False):
        if not platform_info.is_linux_platform():
            return True
        try:
            if self.flags.verbose:
                logger.log_info(f"Changing owner of {src} to {owner}")
            if not self.flags.pretend_run:
                self.run_checked(["chown", "-R", owner, src], sudo = sudo)
            return True
        except Exception as e:
            return self.handle_error(f"Unable to change owner of {src}", e)

    def change_permission(self, src, permission, sudo = False):
        if not platform_info.is_linux_platform():
            return True
        try:
            if self.flags.verbose:
                logger.log_info(f"Changing permissions of {src} to {permission}")
            if not self.flags.pretend_run:
                self.run_checked(["chmod", "-R", permission, src], sudo = sudo)
            return True
        except Exception as e:
            return self.handle_error(f"Unable to change permissions of {src}", e)
