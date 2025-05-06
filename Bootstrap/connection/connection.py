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
        self.config = config.Copy()
        self.flags = flags.Copy()
        self.options = options.Copy()

    def Copy(self):
        return copy.deepcopy(self)

    def Setup(self):
        pass

    def TearDown(self):
        pass

    def SetCurrentWorkingDirectory(self, cwd):
        self.options.cwd = cwd

    def SetEnvironment(self, env):
        self.options.env = env

    def SetEnvironmentVar(self, var, value):
        self.options.env[var] = value

    def UnsetEnvironmentVar(self, var):
        del self.options.env[var]

    def SetConfig(self, config):
        self.config = config

    def GetConfig(self):
        return self.config

    def SetFlags(self, flags):
        self.flags = flags

    def GetFlags(self):
        return self.flags

    def SetOptions(self, options):
        self.options = options

    def GetOptions(self):
        return self.options

    def CreateCommandString(self, cmd):
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

    def CreateCommandList(self, cmd):
        if not cmd:
            return []
        if len(cmd) == 0:
            return []
        if isinstance(cmd, list):
            return copy.deepcopy(cmd)
        if isinstance(cmd, str):
            return cmd.split(" ")
        return []

    def CleanCommandOutput(self, output):
        try:
            return output.decode("utf-8", "ignore")
        except:
            return output

    def MarkCommandAsSudo(self, cmd):
        if util.IsLinuxPlatform():
            if isinstance(cmd, str):
                return f"sudo {cmd}"
            elif isinstance(cmd, list):
                return ["sudo"] + cmd
        return cmd

    def PrintCommand(self, cmd):
        if isinstance(cmd, str):
            util.LogInfo("Running \"%s\"" % cmd)
        if isinstance(cmd, list):
            util.LogInfo("Running \"%s\"" % " ".join(cmd))

    def RunOutput(self, cmd, sudo = False):
        return ""

    def RunReturncode(self, cmd, sudo = False):
        return 0

    def RunBlocking(self, cmd, sudo = False):
        return 0

    def RunInteractive(self, cmd, sudo = False):
        return 0

    def RunChecked(self, cmd, sudo = False, throw_exception = False):
        return None

    def MakeTemporaryDirectory(self):
        return None

    def MakeDirectory(self, src, sudo = False):
        self.RunChecked([
            tools.GetMakeDirTool(self.config),
            "-p",
            src
        ], sudo = sudo)

    def RemoveFileOrDirectory(self, src, sudo = False):
        self.RunChecked([
            tools.GetRemoveTool(self.config),
            "-rf",
            src
        ], sudo = sudo)

    def CopyFileOrDirectory(self, src, dest, sudo = False):
        self.RunChecked([
            tools.GetCopyTool(self.config),
            src,
            dest
        ], sudo = sudo)

    def MoveFileOrDirectory(self, src, dest, sudo = False):
        self.RunChecked([
            tools.GetMoveTool(self.config),
            src,
            dest
        ], sudo = sudo)

    def LinkFileOrDirectory(self, src, dest, sudo = False):
        self.RunChecked([
            tools.GetLinkTool(self.config),
            "-sf", src,
            dest
        ], sudo = sudo)

    def DoesFileOrDirectoryExist(self, src):
        return False

    def TransferFiles(self, src, dest, excludes = []):
        return False

    def ReadFile(self, src):
        return None

    def WriteFile(self, src, contents):
        return False

    def DownloadFile(self, url, dest, sudo = False):
        self.RunChecked([
            tools.GetCurlTool(self.config),
            "-L",
            "-o", dest,
            url
        ], sudo = sudo)

    def ExtractTarArchive(self, src, dest, sudo = False):
        self.RunChecked([
            tools.GetTarTool(self.config),
            "-xf", src,
            "-C", dest
        ], sudo = sudo)

    def ChangeOwner(self, src, owner, sudo = False):
        self.RunChecked([
            tools.GetChangeOwnerTool(self.config),
            "-R",
            owner,
            src
        ], sudo = sudo)

    def ChangePermission(self, src, permission, sudo = False):
        self.RunChecked([
            tools.GetChangePermissionTool(self.config),
            "-R",
            permission,
            src
        ], sudo = sudo)

    def AddToCronTab(self, pattern):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Adding to crontab: {pattern}")
            if not self.flags.pretend_run:
                output = self.RunOutput(["crontab", "-l"])
                if output is None:
                    output = ""
                lines = output.splitlines()
                if pattern.strip() not in [line.strip() for line in lines]:
                    tmp_crontab = "/tmp/crontab_update"
                    new_cron = output.strip() + "\n" + pattern.strip() + "\n" if output.strip() else pattern.strip() + "\n"
                    self.WriteFile(tmp_crontab, new_cron)
                    self.RunChecked(["crontab", tmp_crontab])
                    self.RemoveFileOrDirectory(tmp_crontab)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(f"Unable to add to crontab: {pattern}")
                util.LogError(e)
                util.QuitProgram()
            return False

    def RemoveFromCronTab(self, pattern):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Removing from crontab: {pattern}")
            if not self.flags.pretend_run:
                output = self.RunOutput(["crontab", "-l"])
                lines = output.splitlines() if output else []
                new_lines = [line for line in lines if line.strip() != pattern.strip()]
                if lines == new_lines:
                    return True
                tmp_crontab = "/tmp/crontab_update"
                new_cron = "\n".join(new_lines) + "\n"
                self.WriteFile(tmp_crontab, new_cron)
                self.RunChecked(["crontab", tmp_crontab])
                self.RemoveFileOrDirectory(tmp_crontab)
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(f"Unable to remove from crontab: {pattern}")
                util.LogError(e)
                util.QuitProgram()
            return False

    def AddToPath(self, src):
        if util.IsWindowsPlatform():
            return self.AddToWindowsPath(src)
        else:
            return self.AddToUnixPath(src)

    def AddToWindowsPath(self, src):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Adding {src} to path")
            if not self.flags.pretend_run:

                # Get current path
                current_path = self.RunOutput([
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
                code = self.RunReturncode([
                    "powershell",
                    "-Command",
                    f'[Environment]::SetEnvironmentVariable("PATH", "{new_paths_escaped}", "User")'
                ])
                return code == 0
            return True
        except Exception as e:
            if self.flags.exit_on_failure:
                util.LogError(f"Unable to add {src} to path")
                util.LogError(e)
                util.QuitProgram()
            return False

    def AddToUnixPath(self, src):
        try:
            if self.flags.verbose:
                util.LogInfo(f"Adding {src} to path")
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
                util.LogError(f"Unable to add {src} to path")
                util.LogError(e)
                util.QuitProgram()
            return False
