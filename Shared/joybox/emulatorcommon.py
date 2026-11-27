# Local imports
from joybox import config
from joybox import capture
from joybox import logger
from joybox import paths
from joybox import gui

# Run install_package_dir on each DLC dir, then each update dir; False at the first failure
def install_package_dirs(
    install_package_dir,
    dlc_dirs = None,
    update_dirs = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    dlc_dirs = [] if dlc_dirs is None else dlc_dirs
    update_dirs = [] if update_dirs is None else update_dirs
    for package_dirset in [dlc_dirs, update_dirs]:
        for package_dir in package_dirset:
            if not install_package_dir(package_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
                return False
    return True

# The launch file to run: the single file, or the one the user picks from a choices window
# when there are several; empty when there is none
def select_launch_file(game_launch_file):

    # Selected launch file
    selected_launch_file = ""

    # Single choice
    if isinstance(game_launch_file, str) and len(game_launch_file) > 0:
        selected_launch_file = game_launch_file

    # Single list choice
    elif isinstance(game_launch_file, list) and len(game_launch_file) == 1:
        selected_launch_file = game_launch_file[0]

    # More than one potential list choice
    elif isinstance(game_launch_file, list) and len(game_launch_file) > 1:

        # Handle game selection
        def handle_game_selection(selected_file):
            nonlocal selected_launch_file
            selected_launch_file = selected_file

        # Display choices
        gui.display_choices_window(
            choice_list = game_launch_file,
            title_text = "Select Game",
            message_text = "Select game to run",
            button_text = "Run game",
            run_func = handle_game_selection)
    return selected_launch_file

# The launch command with the game name, file and directory tokens filled in
def replace_launch_tokens(launch_cmd, game_launch_name, selected_launch_file, game_cache_dir):
    real_launch_cmd = []
    for cmd_segment in launch_cmd:

        # Replace game name
        if game_launch_name:
            cmd_segment = cmd_segment.replace(config.TOKEN_GAME_NAME, game_launch_name)

        # Replace game file
        if selected_launch_file:
            cmd_segment = cmd_segment.replace(config.TOKEN_GAME_FILE, paths.join_paths(game_cache_dir, selected_launch_file))

        # Replace game dir
        cmd_segment = cmd_segment.replace(config.TOKEN_GAME_DIR, game_cache_dir)

        # Add segment
        real_launch_cmd += [cmd_segment]
    return real_launch_cmd

# Simple generic launcher
def simple_launch(
    game_info,
    launch_cmd,
    launch_options = None,
    capture_type = None,
    capture_file = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game info
    game_launch_name = game_info.get_launch_name()
    game_launch_file = game_info.get_launch_file()
    game_cache_dir = game_info.get_local_cache_dir()

    # Selected launch file
    selected_launch_file = select_launch_file(game_launch_file)

    # Nothing to run
    if len(selected_launch_file) == 0 and not game_launch_name:
        logger.log_warning("Nothing to run")
        return False

    # Replace game tokens
    real_launch_cmd = replace_launch_tokens(launch_cmd, game_launch_name, selected_launch_file, game_cache_dir)

    # Launch game
    return capture.run_capture_command(
        cmd = real_launch_cmd,
        options = launch_options,
        capture_type = capture_type,
        capture_file = capture_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
