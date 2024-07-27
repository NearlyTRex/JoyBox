# Imports
import os, os.path
import sys
import json

# Local imports
import config
import command
import archive
import programs
import gameinfo
import system
import environment
import hashing
import storebase

# Amazon store
class Amazon(storebase.StoreBase):

    # Constructor
    def __init__(self):
        super().__init__()

    # Get name
    def GetName(self):
        return "Amazon"

    # Login
    def Login(
        self,
        verbose = False,
        exit_on_failure = False):

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return False

        # Get script
        nile_script = None
        if programs.IsToolInstalled("Nile"):
            nile_script = programs.GetToolProgram("Nile")
        if not nile_script:
            system.LogError("Nile was not found")
            return False

        # Get login command
        login_cmd = [
            python_tool,
            nile_script,
            "--quiet",
            "auth",
            "--login"
        ]

        # Run login command
        code = command.RunBlockingCommand(
            cmd = login_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if (code != 0):
            return False

        # Get refresh command
        refresh_cmd = [
            python_tool,
            nile_script,
            "--quiet",
            "auth",
            "--refresh"
        ]

        # Run refresh command
        code = command.RunBlockingCommand(
            cmd = refresh_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    # Fetch
    def Fetch(
        self,
        identifier,
        output_dir,
        output_name = None,
        branch = None,
        clean_output = False,
        verbose = False,
        exit_on_failure = False):

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return False

        # Get script
        nile_script = None
        if programs.IsToolInstalled("Nile"):
            nile_script = programs.GetToolProgram("Nile")
        if not nile_script:
            system.LogError("Nile was not found")
            return False

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
        if not tmp_dir_success:
            return False

        # Make temporary dirs
        tmp_dir_fetch = os.path.join(tmp_dir_result, "fetch")
        tmp_dir_archive = os.path.join(tmp_dir_result, "archive")
        system.MakeDirectory(tmp_dir_fetch, verbose = verbose, exit_on_failure = exit_on_failure)
        system.MakeDirectory(tmp_dir_archive, verbose = verbose, exit_on_failure = exit_on_failure)

        # Get fetch command
        fetch_cmd = [
            python_tool,
            nile_script,
            "verify",
            "--path", tmp_dir_fetch,
            identifier
        ]

        # Run fetch command
        code = command.RunBlockingCommand(
            cmd = fetch_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if code != 0:
            system.LogError("Encountered error fetching")
            return False

        # Check that files fetched
        if system.IsDirectoryEmpty(tmp_dir_fetch):
            system.LogError("Files were not fetched successfully")
            return False

        # Archive fetched files
        success = archive.CreateArchiveFromFolder(
            archive_file = os.path.join(tmp_dir_archive, "%s.7z" % output_name),
            source_dir = tmp_dir_fetch,
            volume_size = "4092m",
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            system.RemoveDirectory(tmp_dir_result, verbose = verbose)
            return False

        # Clean output
        if clean_output:
            system.RemoveDirectoryContents(
                dir = output_dir,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Move archived files
        success = system.MoveContents(
            src = tmp_dir_archive,
            dest = output_dir,
            show_progress = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not success:
            system.RemoveDirectory(tmp_dir_result, verbose = verbose)
            return False

        # Delete temporary directory
        system.RemoveDirectory(tmp_dir_result, verbose = verbose)

        # Check result
        return os.path.exists(output_dir)

    # Download
    def Download(
        self,
        json_file,
        output_dir = None,
        skip_existing = False,
        force = False,
        verbose = False,
        exit_on_failure = False):

        # Get game info
        game_info = gameinfo.GameInfo(
            json_file = json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Ignore non-amazon games
        if game_info.get_amazon_appid() == "":
            return True

        # Get output dir
        if output_dir:
            output_offset = environment.GetLockerGamingRomDirOffset(game_info.get_category(), game_info.get_subcategory(), game_info.get_name())
            output_dir = os.path.join(os.path.realpath(output_dir), output_offset)
        else:
            output_dir = environment.GetLockerGamingRomDir(game_info.get_category(), game_info.get_subcategory(), game_info.get_name())
        if skip_existing and system.DoesDirectoryContainFiles(output_dir):
            return True

        # Get latest amazon info
        latest_amazon_info = self.GetInfo(
            identifier = game_info.get_amazon_appid(),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Get build ids
        old_buildid = game_info.get_amazon_buildid()
        new_buildid = latest_amazon_info[config.json_key_amazon_buildid]

        # Check if game should be fetched
        should_fetch = False
        if force or old_buildid is None or new_buildid is None:
            should_fetch = True
        elif len(old_buildid) == 0:
            should_fetch = True
        else:
            should_fetch = new_buildid != old_buildid

        # Fetch game
        if should_fetch:
            success = self.Fetch(
                identifier = game_info.get_amazon_appid(),
                output_dir = output_dir,
                output_name = "%s (%s)" % (game_info.get_name(), hashing.CalculateStringCRC32(new_buildid)),
                clean_output = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

        # Update json file
        json_data = system.ReadJsonFile(
            src = json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        json_data[config.json_key_amazon] = latest_amazon_info
        success = system.WriteJsonFile(
            src = json_file,
            json_data = json_data,
            sort_keys = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return success

    # Get info
    def GetInfo(
        self,
        identifier,
        branch = None,
        verbose = False,
        exit_on_failure = False):

        # Get tool
        python_tool = None
        if programs.IsToolInstalled("PythonVenvPython"):
            python_tool = programs.GetToolProgram("PythonVenvPython")
        if not python_tool:
            system.LogError("PythonVenvPython was not found")
            return False

        # Get script
        nile_script = None
        if programs.IsToolInstalled("Nile"):
            nile_script = programs.GetToolProgram("Nile")
        if not nile_script:
            system.LogError("Nile was not found")
            return False

        # Get info command
        info_cmd = [
            python_tool,
            nile_script,
            "--quiet",
            "details",
            identifier
        ]

        # Run info command
        info_output = command.RunOutputCommand(
            cmd = info_cmd,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if len(info_output) == 0:
            system.LogError("Unable to find amazon information for '%s'" % identifier)
            return False

        # Get amazon json
        amazon_json = {}
        try:
            amazon_json = json.loads(info_output)
        except:
            system.LogError("Unable to parse amazon information for '%s'" % identifier)
            return False

        # Build game info
        game_info = {}
        game_info[config.json_key_amazon_appid] = identifier
        game_info[config.json_key_amazon_buildid] = ""
        if "version" in amazon_json:
            game_info[config.json_key_amazon_buildid] = str(amazon_json["version"])
        if "product" in amazon_json:
            appdata = amazon_json["product"]
            if "title" in appdata:
                game_info[config.json_key_amazon_name] = str(appdata["title"])

        # Return game info
        return game_info

    # Get versions
    def GetVersions(
        self,
        json_file,
        verbose = False,
        exit_on_failure = False):

        # Get game info
        game_info = gameinfo.GameInfo(
            json_file = json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Ignore non-amazon games
        if game_info.get_amazon_appid() == "":
            return (None, None)

        # Get latest amazon info
        latest_amazon_info = self.GetInfo(
            appid = game_info.get_amazon_appid(),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Get build ids
        local_buildid = game_info.get_amazon_buildid()
        remote_buildid = latest_amazon_info[config.json_key_amazon_buildid]
        return (local_buildid, remote_buildid)
