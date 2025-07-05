# Imports
import os
import sys
import copy
import pwd
import grp
import subprocess
import shutil
import tempfile
import fnmatch
import urllib.request
import zipfile
import tarfile
import json

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
                    bufsize = 1,
                    text = True)
                while True:
                    output = self.clean_command_output(process.stdout.readline().rstrip())
                    if output == "" and process.poll() is not None:
                        break
                    if output:
                        util.log_info(output.strip())
                code = process.poll()
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
            if self.flags.exit_on_failure:
                util.log_error("Unable to make temporary directory")
                util.log_error(e)
                util.quit_program()
            return None

    def does_file_or_directory_exist(self, src):
        try:
            if self.flags.verbose:
                util.log_info("Checking existence of %s" % src)
            if not self.flags.pretend_run:
                return os.path.exists(src)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error("Error checking existence of %s" % src)
                util.log_error(e)
                util.quit_program()
            return False

    def transfer_files(self, src, dest, excludes = []):
        try:
            if self.flags.verbose:
                util.log_info("Transferring files from %s to %s" % (src, dest))
            if self.flags.skip_existing and os.path.exists(dest):
                return True
            if not self.flags.pretend_run:
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
            if self.flags.exit_on_failure:
                util.log_error(f"Unable to transfer files from {src} to {dest}")
                util.log_error(e)
                util.quit_program()
            return False

    def read_file(self, src):
        try:
            if self.flags.verbose:
                util.log_info(f"Reading file {src}")
            if not self.flags.pretend_run:
                contents = ""
                with open(src, "r") as f:
                    contents = f.read()
                return contents
            return None
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(f"Unable to write file to {src}")
                util.log_error(e)
                util.quit_program()
            return None

    def write_file(self, src, contents):
        try:
            if self.flags.verbose:
                util.log_info(f"Writing file to {src}")
            if not self.flags.pretend_run:
                os.makedirs(os.path.dirname(src), exist_ok = True)
                with open(src, "w") as f:
                    f.write(contents)
                return True
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.log_error(f"Unable to write file to {src}")
                util.log_error(e)
                util.quit_program()
            return False
