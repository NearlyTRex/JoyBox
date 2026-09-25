#!/usr/bin/env python3

# Imports
import os
import sys
import argparse

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "Shared"))
sys.path.append(shared_folder)
from joybox import runoptions
from joybox import logger
from joybox import settings
from joybox import default_settings
import joybox.bootstrap.constants as constants
import joybox.bootstrap.packages as packages
import joybox.bootstrap.runner as runner

# Set up arguments
parser = argparse.ArgumentParser(description="Environment bootstrap script.")
parser.add_argument(
    "-a", "--action",
    choices = ["setup", "teardown", "status", "backup", "restore"],
    help = "Action to perform")
parser.add_argument(
    "-t", "--type",
    type = constants.EnvironmentType,
    choices = list(constants.EnvironmentType),
    required = True,
    help = "Environment type")
parser.add_argument(
    "-c", "--config_file",
    default = settings.get_home_settings_file(),
    help = "Path to config file")
parser.add_argument(
    "-s", "--server_index",
    type = int,
    help = "Server index to use")
parser.add_argument(
    "-k", "--ssh_key_filepath",
    help = "SSH private key to authenticate with (overrides the server entry's key and password)")
parser.add_argument(
    "--components",
    nargs = "*",
    help = "Specific components to setup/teardown (default: all)")
parser.add_argument(
    "--list-components",
    action = "store_true",
    help = "List available components for the specified environment type and exit")
parser.add_argument("-v", "--verbose", action = "store_true", help = "Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action = "store_true", help = "Enable pretend run mode")
parser.add_argument("-x", "--exit_on_failure", action = "store_true", help = "Enable exit on failure mode")
parser.add_argument("-f", "--force", action = "store_true", help = "Force operations even if component is already installed/uninstalled")
parser.add_argument("--autoremove", action = "store_true", help = "Run 'apt-get autoremove' during setup/teardown (off by default; removes system-wide orphaned packages)")
parser.add_argument("--purge-data", dest = "purge_data", action = "store_true", help = "Delete container volumes during teardown (off by default; this destroys databases and app data)")
parser.add_argument("--list-images", dest = "list_images", action = "store_true", help = "List the pinned container image for each docker component and exit")
parser.add_argument("--backup-id", dest = "backup_id", help = "Backup timestamp to restore, or 'latest'")
parser.add_argument("--confirm", dest = "confirm", help = "Type 'restore' to confirm a destructive restore")
args, unknown = parser.parse_known_args()

# Require action unless listing components
is_info_only = args.list_components or args.list_images
if not is_info_only and not args.action:
    parser.error("the following arguments are required: -a/--action")

# Check arguments
is_local_ubuntu = args.type == constants.EnvironmentType.LOCAL_UBUNTU
is_remote_ubuntu = args.type == constants.EnvironmentType.REMOTE_UBUNTU
is_server_index = isinstance(args.server_index, int) and args.server_index >= 0
if is_remote_ubuntu and not is_server_index and not is_info_only:
    logger.log_error_and_quit("No server specified for remote machine")

# Main
def main():

    # Setup logging
    logger.setup_logging()

    # Get config file
    config_file = os.path.realpath(args.config_file)
    settings.set_settings_file(config_file)
    if not os.path.exists(config_file) and not is_info_only:
        if args.action == "setup":
            logger.log_info(f"Config file '{config_file}' not found; creating it with defaults")
            if not default_settings.create_default_config_file(config_file):
                logger.log_error_and_quit(f"Unable to create config file '{config_file}'")
            logger.log_info(f"Created '{config_file}' — edit it to change any values, then re-run if needed")
        else:
            logger.log_error_and_quit(f"Config file '{config_file}' does not exist")

    # Handle list images request
    if args.list_images:
        logger.log_info("Pinned container images:")
        for app_name in sorted(packages.docker_images.keys()):
            logger.log_info(f"  {app_name}:")
            for env_name, pinned_image in sorted(packages.docker_images[app_name].items()):
                override = settings.get_value("UserData.Images", env_name.lower(),
                    default_value = "", throw_exception = False)
                if override and override.strip():
                    logger.log_info(f"    {env_name} = {override.strip()} (override; pin is {pinned_image})")
                else:
                    logger.log_info(f"    {env_name} = {pinned_image}")
        logger.log_info("Edit Shared/joybox/bootstrap/packages/images.py to change a pin.")
        return

    # Create run flags
    flags = runoptions.RunFlags(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if args.force:
        flags.set(force = args.force)
    if args.autoremove:
        flags.set(autoremove = args.autoremove)
    if args.purge_data:
        flags.set(purge_data = args.purge_data)
    if args.backup_id:
        flags.set(backup_id = args.backup_id)
    if args.confirm:
        flags.set(confirm = args.confirm)

    # Create environment runner
    environment_runner = runner.create_environment(
        environment_type = args.type,
        server_index = args.server_index if is_server_index else None,
        flags = flags,
        ssh_key_filepath = args.ssh_key_filepath,
        require_domain = not is_info_only)
    if not environment_runner:
        logger.log_error_and_quit("No environment runner could be created")

    # Handle list components request
    if args.list_components:
        components = environment_runner.get_available_components()
        logger.log_info(f"Available components for {args.type}:")
        for component in sorted(components):
            logger.log_info(f"  - {component}")
        return

    # Set components to process
    if args.components is not None:
        if len(args.components) == 0:
            logger.log_error_and_quit("--components specified but no components listed. Use --list-components to see available components.")
        environment_runner.set_components_to_process(args.components)

    # Gate destructive restores
    if args.action == "restore":
        if not args.components:
            logger.log_error_and_quit("restore requires an explicit --components list; it will not restore everything at once")
        if not args.backup_id:
            logger.log_error_and_quit("restore requires --backup-id <timestamp|latest>")
        if args.confirm != "restore" and not args.pretend_run:
            logger.log_error_and_quit("restore overwrites live data; re-run with --confirm restore (or -p to dry-run)")

    # Dispatch action
    if args.action == "setup":
        environment_runner.setup()
    elif args.action == "teardown":
        environment_runner.teardown()
    elif args.action == "backup":
        environment_runner.backup()
    elif args.action == "restore":
        environment_runner.restore()
    elif args.action == "status":
        results = environment_runner.status()
        installed = [r for r in results if r["installed"]]
        not_installed = [r for r in results if not r["installed"]]
        logger.log_info(f"Component status for {args.type}:")
        logger.log_info("")
        if installed:
            logger.log_info(f"Installed ({len(installed)}):")
            for r in sorted(installed, key=lambda x: x["name"]):
                pkg_status = r.get("package_status")
                if pkg_status:
                    total = len(pkg_status["installed"]) + len(pkg_status["missing"])
                    logger.log_info(f"  [x] {r['name']} ({len(pkg_status['installed'])}/{total} packages)")
                else:
                    logger.log_info(f"  [x] {r['name']}")
        if not_installed:
            logger.log_info(f"Not installed ({len(not_installed)}):")
            for r in sorted(not_installed, key=lambda x: x["name"]):
                pkg_status = r.get("package_status")
                if pkg_status and pkg_status["missing"]:
                    total = len(pkg_status["installed"]) + len(pkg_status["missing"])
                    logger.log_info(f"  [ ] {r['name']} ({len(pkg_status['installed'])}/{total} packages)")
                    logger.log_info(f"      Missing:")
                    for pkg in pkg_status["missing"][:10]:
                        logger.log_info(f"        - {pkg}")
                    if len(pkg_status["missing"]) > 10:
                        logger.log_info(f"        ... and {len(pkg_status['missing']) - 10} more")
                else:
                    logger.log_info(f"  [ ] {r['name']}")

# Start
if __name__ == "__main__":
    main()
