import os
import sys
import copy
import subprocess
import shutil
import tempfile
import urllib.request
import zipfile
import tarfile
import util
from . import connection

class CommandLocal(connection.Command):
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
            if self.flags.verbose:
                util.util.LogError(e)
            elif self.flags.exit_on_failure:
                util.util.LogError(e)
                util.util.QuitProgram()
            if self.options.include_stderr:
                return e.output
            return ""
        except Exception as e:
            if self.flags.verbose:
                util.util.LogError(e)
            elif self.flags.exit_on_failure:
                util.util.LogError(e)
                util.util.QuitProgram()
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
            if self.flags.verbose:
                util.util.LogError(e)
            elif self.flags.exit_on_failure:
                util.util.LogError(e)
                util.util.QuitProgram()
            return e.returncode
        except Exception as e:
            if self.flags.verbose:
                util.util.LogError(e)
            elif self.flags.exit_on_failure:
                util.util.LogError(e)
                util.util.QuitProgram()
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
                        util.util.LogInfo(output.strip())
                code = process.poll()
                return code
            return 0
        except subprocess.CalledProcessError as e:
            if self.flags.verbose:
                util.util.LogError(e)
            elif self.flags.exit_on_failure:
                util.util.LogError(e)
                util.util.QuitProgram()
            return e.returncode
        except Exception as e:
            if self.flags.verbose:
                util.util.LogError(e)
            elif self.flags.exit_on_failure:
                util.util.LogError(e)
                util.util.QuitProgram()
            return 1

    def RunChecked(self, cmd, throw_exception = False):
        code = self.RunBlocking(cmd = cmd)
        if code != 0:
            if throw_exception:
                raise ValueError("Unable to run command: %s" % cmd)
            else:
                util.util.QuitProgram(code)

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

    def WriteFile(self, src, contents):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Writing file to {src}")
            if not self.flags.pretend_run:
                if cmd:
                    return cmd.WriteFile(src, contents)
                else:
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
