# Imports
import os
import sys
import copy
import glob
import subprocess
import shutil
import tempfile
import fnmatch
import urllib.request
import tarfile

# Local imports
import util
from . import connection

class ConnectionLocal(connection.Connection):
    def __init__(
        self,
        config,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        if options and not options.env:
            options.env = copy.deepcopy(os.environ)
        super().__init__(config, flags, options)

    def mark_command_as_sudo(self, cmd):
        if util.is_linux_platform():
            return super().mark_command_as_sudo(cmd)
        return cmd

    def run_output(self, cmd, sudo = False):
        try:
            cmd = self.create_command_list(cmd)
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                if self.options.shell:
                    cmd = self.create_command_string(cmd)
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
                return self.clean_command_output(output.strip())
            return ""
        except subprocess.CalledProcessError as e:
            if self.flags.exit_on_failure:
                util.log_error(e)
                util.quit_program()
            if self.options.include_stderr:
                return e.output
            return ""
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(e)
                util.quit_program()
            return ""

    def run_return_code(self, cmd, sudo = False):
        try:
            cmd = self.create_command_list(cmd)
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                if self.options.shell:
                    cmd = self.create_command_string(cmd)
                stdout = self.options.stdout
                stderr = self.options.stderr
                if util.is_path_valid(self.options.stdout):
                    stdout = open(self.options.stdout, "w")
                if util.is_path_valid(self.options.stderr):
                    stderr = open(self.options.stderr, "w")
                code = subprocess.call(
                    cmd,
                    shell = self.options.shell,
                    cwd = self.options.cwd,
                    env = self.options.env,
                    creationflags = self.options.creationflags,
                    stdout = stdout,
                    stderr = stderr)
                if util.is_path_valid(self.options.stdout):
                    stdout.close()
                if util.is_path_valid(self.options.stderr):
                    stderr.close()
                return code
            return 0
        except subprocess.CalledProcessError as e:
            if self.flags.exit_on_failure:
                util.log_error(e)
                util.quit_program()
            return e.returncode
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(e)
                util.quit_program()
            return 1

    def run_blocking(self, cmd, sudo = False):
        try:
            cmd = self.create_command_list(cmd)
            if sudo:
                cmd = self.mark_command_as_sudo(cmd)
            if self.flags.verbose:
                self.print_command(cmd)
            if not self.flags.pretend_run:
                if self.options.shell:
                    cmd = self.create_command_string(cmd)
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
                util.log_error(e)
                util.quit_program()
            return e.returncode
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(e)
                util.quit_program()
            return 1

    def run_interactive(self, cmd, sudo = False):
        return self.run_blocking(cmd, sudo = sudo)

    def run_checked(self, cmd, sudo = False, throw_exception = False):
        code = self.run_blocking(cmd = cmd, sudo = sudo)
        if code != 0:
            if throw_exception:
                raise ValueError("Unable to run command: %s" % cmd)
            else:
                util.quit_program(code)

    def make_temporary_directory(self):
        try:
            if self.flags.verbose:
                util.log_info("Making temporary directory")
            if not self.flags.pretend_run:
                temp_dir = os.path.realpath(tempfile.mkdtemp())
                if self.flags.verbose:
                    util.log_info("Created temporary directory %s" % temp_dir)
                return temp_dir
            return None
        except Exception as e:
            return self.handle_error("Unable to make temporary directory", e, return_value = None)

    def does_file_or_directory_exist(self, src):
        try:
            if self.flags.verbose:
                util.log_info("Checking existence of %s" % src)
            if not self.flags.pretend_run:
                return os.path.exists(src)
            return True
        except Exception as e:
            return self.handle_error("Error checking existence of %s" % src, e)

    def transfer_files(self, src, dest, excludes = [], sudo = False):
        try:
            if self.flags.verbose:
                util.log_info("Transferring files from %s to %s" % (src, dest))
            if self.flags.skip_existing and os.path.exists(dest):
                return True
            if not self.flags.pretend_run:
                if sudo:
                    if os.path.isdir(src):
                        cmd = ["cp", "-r", src, dest]
                    else:
                        cmd = ["cp", src, dest]
                    code = self.run_return_code(cmd, sudo = True)
                    return code == 0
                else:
                    if os.path.isdir(src):
                        def ignore_patterns(_, names):
                            ignored = set()
                            for pattern in excludes:
                                ignored.update(fnmatch.filter(names, pattern))
                            return ignored
                        shutil.copytree(src, dest, ignore = ignore_patterns if excludes else None, dirs_exist_ok=True)
                    else:
                        if not any(fnmatch.fnmatch(os.path.basename(src), pattern) for pattern in excludes):
                            shutil.copy(src, dest)
            return True
        except Exception as e:
            return self.handle_error(f"Unable to transfer files from {src} to {dest}", e)

    def read_file(self, src, sudo = False):
        try:
            if self.flags.verbose:
                util.log_info(f"Reading file {src}")
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
        try:
            if self.flags.verbose:
                util.log_info(f"Writing file to {src}")
            if not self.flags.pretend_run:
                if sudo:
                    with tempfile.NamedTemporaryFile(mode = "w", delete = False) as f:
                        f.write(contents)
                        temp_path = f.name
                    self.run_blocking(["mv", temp_path, src], sudo = True)
                else:
                    parent_dir = os.path.dirname(src)
                    if parent_dir:
                        os.makedirs(parent_dir, exist_ok = True)
                    with open(src, "w") as f:
                        f.write(contents)
                return True
            return True
        except Exception as e:
            return self.handle_error(f"Unable to write file to {src}", e)

    def make_directory(self, src, sudo = False):
        try:
            if self.flags.verbose:
                util.log_info(f"Making directory {src}")
            if not self.flags.pretend_run:
                if sudo:
                    self.run_checked(["mkdir", "-p", src], sudo = True)
                else:
                    os.makedirs(src, exist_ok = True)
            return True
        except Exception as e:
            return self.handle_error(f"Unable to make directory {src}", e)

    def remove_file_or_directory(self, src, sudo = False):
        try:
            if self.flags.verbose:
                util.log_info(f"Removing {src}")
            if not self.flags.pretend_run:
                if sudo:
                    self.run_checked(["sh", "-c", "rm -rf -- %s" % src], sudo = True)
                else:
                    for match in glob.glob(src):
                        if os.path.isdir(match) and not os.path.islink(match):
                            shutil.rmtree(match)
                        else:
                            os.remove(match)
            return True
        except Exception as e:
            return self.handle_error(f"Unable to remove {src}", e)

    def copy_file_or_directory(self, src, dest, sudo = False):
        try:
            if self.flags.verbose:
                util.log_info(f"Copying {src} to {dest}")
            if not self.flags.pretend_run:
                if sudo:
                    cmd = ["cp", "-r", src, dest] if os.path.isdir(src) else ["cp", src, dest]
                    self.run_checked(cmd, sudo = True)
                else:
                    if os.path.isdir(src):
                        shutil.copytree(src, dest, dirs_exist_ok = True)
                    else:
                        shutil.copy2(src, dest)
            return True
        except Exception as e:
            return self.handle_error(f"Unable to copy {src} to {dest}", e)

    def move_file_or_directory(self, src, dest, sudo = False):
        try:
            if self.flags.verbose:
                util.log_info(f"Moving {src} to {dest}")
            if not self.flags.pretend_run:
                if sudo:
                    self.run_checked(["mv", src, dest], sudo = True)
                else:
                    shutil.move(src, dest)
            return True
        except Exception as e:
            return self.handle_error(f"Unable to move {src} to {dest}", e)

    def link_file_or_directory(self, src, dest, sudo = False):
        try:
            if self.flags.verbose:
                util.log_info(f"Linking {src} to {dest}")
            if not self.flags.pretend_run:
                if sudo:
                    self.run_checked(["ln", "-sf", src, dest], sudo = True)
                else:
                    if os.path.lexists(dest):
                        os.remove(dest)
                    os.symlink(src, dest)
            return True
        except Exception as e:
            return self.handle_error(f"Unable to link {src} to {dest}", e)

    def download_file(self, url, dest, sudo = False):
        try:
            if self.flags.verbose:
                util.log_info(f"Downloading {url} to {dest}")
            if not self.flags.pretend_run:
                if sudo:
                    with tempfile.NamedTemporaryFile(delete = False) as f:
                        temp_path = f.name
                    urllib.request.urlretrieve(url, temp_path)
                    self.run_checked(["mv", temp_path, dest], sudo = True)
                else:
                    urllib.request.urlretrieve(url, dest)
            return True
        except Exception as e:
            return self.handle_error(f"Unable to download {url} to {dest}", e)

    def extract_tar_archive(self, src, dest, sudo = False):
        try:
            if self.flags.verbose:
                util.log_info(f"Extracting {src} to {dest}")
            if not self.flags.pretend_run:
                if sudo:
                    self.run_checked(["tar", "-xf", src, "-C", dest], sudo = True)
                else:
                    with tarfile.open(src) as tar:
                        tar.extractall(path = dest)
            return True
        except Exception as e:
            return self.handle_error(f"Unable to extract {src} to {dest}", e)

    def change_owner(self, src, owner, sudo = False):
        if not util.is_linux_platform():
            return True
        try:
            if self.flags.verbose:
                util.log_info(f"Changing owner of {src} to {owner}")
            if not self.flags.pretend_run:
                self.run_checked(["chown", "-R", owner, src], sudo = sudo)
            return True
        except Exception as e:
            return self.handle_error(f"Unable to change owner of {src}", e)

    def change_permission(self, src, permission, sudo = False):
        if not util.is_linux_platform():
            return True
        try:
            if self.flags.verbose:
                util.log_info(f"Changing permissions of {src} to {permission}")
            if not self.flags.pretend_run:
                self.run_checked(["chmod", "-R", permission, src], sudo = sudo)
            return True
        except Exception as e:
            return self.handle_error(f"Unable to change permissions of {src}", e)
