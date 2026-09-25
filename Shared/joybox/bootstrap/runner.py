# Imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.environments as environments
from joybox import logger
from joybox import runoptions
from joybox import serverinfo

# Build the environment that runs components on this machine or on a server
# entry. Remote environments need a server index; its domain is required
# unless the caller is only listing what is available.
def create_environment(
    environment_type,
    server_index = None,
    flags = None,
    ssh_key_filepath = None,
    require_domain = True):

    # Options
    environment_options = {
        "flags": flags if flags is not None else runoptions.RunFlags(),
        "options": runoptions.RunOptions()
    }

    # Remote options come from the server entry
    if environment_type == constants.EnvironmentType.REMOTE_UBUNTU:
        environment_options["options"].set(shell = True)
        if server_index is not None:
            server = serverinfo.ServerInfo(server_index)
            if not server.is_configured():
                logger.log_error(f"No host configured for server {server_index}")
                return None
            if not server.get_domain_name() and require_domain:
                logger.log_error(f"No domain configured for server {server_index} (server_{server_index}_domain_name)")
                return None
            serverinfo.select_server(server_index)
            environment_options.update(server.get_connection_options())

        # An explicit key wins over whatever the server entry carries
        if ssh_key_filepath:
            environment_options["ssh_key_filepath"] = ssh_key_filepath

    # Environment
    if environment_type == constants.EnvironmentType.LOCAL_UBUNTU:
        return environments.LocalUbuntu(**environment_options)
    if environment_type == constants.EnvironmentType.REMOTE_UBUNTU:
        return environments.RemoteUbuntu(**environment_options)
    logger.log_error(f"No environment runner for {environment_type}")
    return None
