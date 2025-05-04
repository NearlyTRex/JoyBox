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
        flags = util.RunFlags(),
        options = util.RunOptions()):
        if options and not options.env:
            options.env = copy.deepcopy(os.environ)
        super().__init__(flags, options)

    def RunOutput(self, cmd):
        try:
            cmd = self.CreateCommandList(cmd)
            if self.flags.verbose:
                self.PrintCommand(cmd)
            if not self.flags.pretend_run:
                if self.options.shell:
                    cmd = self.CreateCommandString(cmd)
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
                return self.CleanCommandOutput(output.strip())
            return ""
        except subprocess.CalledProcessError as e:
            if self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            if self.options.include_stderr:
                return e.output
            return ""
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return ""

    def RunReturncode(self, cmd):
        try:
            cmd = self.CreateCommandList(cmd)
            if self.flags.verbose:
                self.PrintCommand(cmd)
            if not self.flags.pretend_run:
                if self.options.shell:
                    cmd = self.CreateCommandString(cmd)
                stdout = self.options.stdout
                stderr = self.options.stderr
                if util.IsPathValid(self.options.stdout):
                    stdout = open(self.options.stdout, "w")
                if util.IsPathValid(self.options.stderr):
                    stderr = open(self.options.stderr, "w")
                code = subprocess.call(
                    cmd,
                    shell = self.options.shell,
                    cwd = self.options.cwd,
                    env = self.options.env,
                    creationflags = self.options.creationflags,
                    stdout = stdout,
                    stderr = stderr)
                if util.IsPathValid(self.options.stdout):
                    stdout.close()
                if util.IsPathValid(self.options.stderr):
                    stderr.close()
                return code
            return 0
        except subprocess.CalledProcessError as e:
            if self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return e.returncode
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return 1

    def RunBlocking(self, cmd):
        try:
            cmd = self.CreateCommandList(cmd)
            if self.flags.verbose:
                self.PrintCommand(cmd)
            if not self.flags.pretend_run:
                if self.options.shell:
                    cmd = self.CreateCommandString(cmd)
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
                    output = self.CleanCommandOutput(process.stdout.readline().rstrip())
                    if output == "" and process.poll() is not None:
                        break
                    if output:
                        util.LogInfo(output.strip())
                code = process.poll()
                return code
            return 0
        except subprocess.CalledProcessError as e:
            if self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return e.returncode
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(e)
                util.QuitProgram()
            return 1

    def RunChecked(self, cmd, throw_exception = False):
        code = self.RunBlocking(cmd = cmd)
        if code != 0:
            if throw_exception:
                raise ValueError("Unable to run command: %s" % cmd)
            else:
                util.QuitProgram(code)

    def MakeTemporaryDirectory(self):
        try:
            if self.flags.verbose:
                util.LogInfo("Making temporary directory")
            if not self.flags.pretend_run:
                temp_dir = os.path.realpath(tempfile.mkdtemp())
                if self.flags.verbose:
                    util.LogInfo("Created temporary directory %s" % temp_dir)
                return temp_dir
            return None
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError("Unable to make temporary directory")
                util.LogError(e)
                util.QuitProgram()
            return None

    def MakeDirectory(self, src):
        try:
            if not os.path.isdir(src):
                if self.flags.verbose:
                    util.LogInfo("Making directory %s" % src)
                if not self.flags.pretend_run:
                    os.makedirs(src, exist_ok = True)
            return True
        except Exception as e:
            if not os.path.isdir(src):
                if self.flags.exit_on_failure:
                    util.LogError("Unable to make directory %s" % src)
                    util.LogError(e)
                    util.QuitProgram()
                return False
            return True

    def RemoveDirectory(self, src):
        try:
            if self.flags.verbose:
                util.LogInfo("Removing directory %s" % src)
            if not self.flags.pretend_run:
                if isinstance(src, tempfile.TemporaryDirectory):
                    src.cleanup()
                elif isinstance(src, str) and os.path.isdir(src):
                    shutil.rmtree(src)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError("Unable to remove directory %s" % src)
                util.LogError(e)
                util.QuitProgram()
            return False

    def CopyFileOrDirectory(self, src, dest):
        try:
            if self.flags.skip_existing and os.path.exists(dest):
                return True
            if self.flags.verbose:
                util.LogInfo("Copying %s to %s" % (src, dest))
            if not self.flags.pretend_run:
                if os.path.isdir(src):
                    shutil.copytree(src, dest, dirs_exist_ok=True)
                else:
                    shutil.copy(src, dest)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError("Unable to copy %s to %s" % (src, dest))
                util.LogError(e)
                util.QuitProgram()
            return False

    def MoveFileOrDirectory(self, src, dest):
        try:
            if self.flags.skip_existing and os.path.exists(dest):
                return True
            if self.flags.verbose:
                util.LogInfo("Moving %s to %s" % (src, dest))
            if not self.flags.pretend_run:
                shutil.move(src, dest)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError("Unable to move %s to %s" % (src, dest))
                util.LogError(e)
                util.QuitProgram()
            return False

    def DoesFileOrDirectoryExist(self, src):
        try:
            if self.flags.verbose:
                util.LogInfo("Checking existence of %s" % src)
            if not self.flags.pretend_run:
                return os.path.exists(src)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError("Error checking existence of %s" % src)
                util.LogError(e)
                util.QuitProgram()
            return False

    def TransferFiles(self, src, dest, excludes = []):
        try:
            if self.flags.verbose:
                util.LogInfo("Transferring files from %s to %s" % (src, dest))
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
                util.LogError(f"Unable to transfer files from {src} to {dest}")
                util.LogError(e)
                util.QuitProgram()
            return False

    def ReadFile(self, src):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Reading file {src}")
            if not self.flags.pretend_run:
                contents = ""
                with open(src, "r") as f:
                    contents = f.read()
                return contents
            return None
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(f"Unable to write file to {src}")
                util.LogError(e)
                util.QuitProgram()
            return None

    def WriteFile(self, src, contents):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Writing file to {src}")
            if not self.flags.pretend_run:
                os.makedirs(os.path.dirname(src), exist_ok = True)
                with open(src, "w") as f:
                    f.write(contents)
                return True
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(f"Unable to write file to {src}")
                util.LogError(e)
                util.QuitProgram()
            return False

    def DownloadFile(self, url, dest):
        try:
            if self.flags.verbose:
                util.LogInfo("Downloading from %s to %s" % (url, dest))
            if not self.flags.pretend_run:
                os.makedirs(os.path.dirname(dest), exist_ok = True)
                urllib.request.urlretrieve(url, dest)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError("Unable to download from %s" % url)
                util.LogError(e)
                util.QuitProgram()
            return True

    def ExtractTarArchive(self, src, dest):
        try:
            if self.flags.verbose:
                util.LogInfo("Extracting TAR archive %s to %s" % (src, dest))
            if not self.flags.pretend_run:
                with tarfile.open(src, "r:*") as archive:
                    archive.extractall(dest)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError("Unable to extract TAR archive %s" % src)
                util.LogError(e)
                util.QuitProgram()
            return False

    def ExtractZipArchive(self, src, dest):
        try:
            if self.flags.verbose:
                util.LogInfo("Extracting ZIP archive %s to %s" % (src, dest))
            if not self.flags.pretend_run:
                with zipfile.ZipFile(src, "r") as archive:
                    archive.extractall(dest)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError("Unable to extract ZIP archive %s" % src)
                util.LogError(e)
                util.QuitProgram()
            return False

    def ChangeOwner(self, src, owner):
        try:
            if self.flags.verbose:
                util.LogInfo("Changing owner of %s to %s" % (src, owner))
            if not self.flags.pretend_run:
                if ":" in owner:
                    user, group = owner.split(":", 1)
                else:
                    user, group = owner, None
                uid = pwd.getpwnam(user).pw_uid
                gid = grp.getgrnam(group).gr_gid if group else -1
                os.chown(src, uid, gid)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError("Unable to change owner of %s to %s" % (src, owner))
                util.LogError(e)
                util.QuitProgram()
            return False

    def ChangePermission(self, src, permission):
        try:
            if self.flags.verbose:
                util.LogInfo("Changing permissions of %s to %s" % (src, permission))
            if not self.flags.pretend_run:
                os.chmod(src, int(permission, 8))
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError("Unable to change permission of %s to %s" % (src, permission))
                util.LogError(e)
                util.QuitProgram()
            return False

    def AddToPath(self, src):
        try:
            if self.flags.verbose:
                util.LogInfo("Adding %s to system path" % src)
            if not self.flags.pretend_run:

                # Windows
                if util.IsWindowsPlatform():

                    # Winreg path functions
                    import winreg
                    def _get_env_path(scope):
                        key = winreg.OpenKey(scope, r"Environment", 0, winreg.KEY_READ)
                        value, _ = winreg.QueryValueEx(key, "Path")
                        winreg.CloseKey(key)
                        return value
                    def _set_env_path(scope, new_path):
                        key = winreg.OpenKey(scope, r"Environment", 0, winreg.KEY_SET_VALUE)
                        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
                        winreg.CloseKey(key)

                    # First try user-level, fallback to system if admin
                    try:
                        path = _get_env_path(winreg.HKEY_CURRENT_USER)
                        if src not in path.split(";"):
                            new_path = f"{path};{src}"
                            _set_env_path(winreg.HKEY_CURRENT_USER, new_path)
                    except PermissionError:
                        path = _get_env_path(winreg.HKEY_LOCAL_MACHINE)
                        if src not in path.split(";"):
                            new_path = f"{path};{src}"
                            _set_env_path(winreg.HKEY_LOCAL_MACHINE, new_path)

                # Unix
                else:

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
                        if self.DoesFileOrDirectoryExist(candidate):
                            profile_file = candidate
                            break

                    # Read current profile
                    existing_content = self.ReadFile(profile_file)
                    if not existing_content:
                        existing_content = ""

                    # Add to profile
                    export_line = f'export PATH="{src}:$PATH"\n'
                    if export_line not in existing_content:
                        new_content = existing_content + "\n" + export_line + "\n"
                        return self.WriteFile(profile_file, new_content)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError("Unable to add %s to system path" % src)
                util.LogError(e)
                util.QuitProgram()
            return False
