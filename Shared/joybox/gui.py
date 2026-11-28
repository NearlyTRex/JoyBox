# Imports
import dataclasses
import importlib
import os
import os.path

# Local imports
from joybox import config
from joybox import logger
from joybox import validation
from joybox import programs
from joybox import modules
from joybox import platform_info, runtime
from joybox import paths

# Get screeninfo, imported on first use
def _get_screeninfo():
    return importlib.import_module("screeninfo")

# Get PIL.Image, imported on first use
def _get_pil_image():
    return importlib.import_module("PIL.Image")

# Get PIL.ImageTk, imported on first use
def _get_pil_image_tk():
    return importlib.import_module("PIL.ImageTk")

# Width and height of the primary monitor in pixels; (0, 0) when none is primary
def get_current_screen_resolution():
    screeninfo = _get_screeninfo()
    for monitor in screeninfo.get_monitors():
        if monitor.is_primary:
            return (monitor.width, monitor.height)
    return (0, 0)

# PySimpleGUI popup function name for each message type; any other type uses psg.popup
POPUP_FUNC_NAMES = (
    (config.MessageType.OK, "popup_ok"),
    (config.MessageType.YES_NO, "popup_yes_no"),
    (config.MessageType.CANCEL, "popup_cancel"),
    (config.MessageType.OK_CANCEL, "popup_ok_cancel"),
    (config.MessageType.ERROR, "popup_error"),
    (config.MessageType.AUTO_CLOSE, "popup_auto_close"),
    (config.MessageType.GET_TEXT, "popup_get_text"),
    (config.MessageType.GET_FILE, "popup_get_file"),
    (config.MessageType.GET_FOLDER, "popup_get_folder"))

# Options a message type's popup takes beyond the common ones; any other type takes
# non_blocking and line_width
POPUP_EXTRA_OPTION_NAMES = (
    (config.MessageType.AUTO_CLOSE, ("auto_close_duration", "non_blocking", "line_width")),
    (config.MessageType.GET_TEXT, ()),
    (config.MessageType.GET_FILE, ("no_window", "save_as", "file_types", "initial_folder", "default_path")),
    (config.MessageType.GET_FOLDER, ("no_window", "initial_folder", "default_path")))

# Load the PySimpleGUI module from its installed tool file
def _import_pysimplegui():
    return modules.import_python_module_file(
        module_path = programs.get_tool_program("PySimpleGUI"),
        module_name = "psg")

# The PySimpleGUI popup function for the message type
def _get_popup_func(psg, message_type):
    for popup_type, func_name in POPUP_FUNC_NAMES:
        if message_type == popup_type:
            return getattr(psg, func_name)
    return psg.popup

# Names of the extra options the message type's popup takes
def _get_popup_extra_option_names(message_type):
    for popup_type, option_names in POPUP_EXTRA_OPTION_NAMES:
        if message_type == popup_type:
            return option_names
    return ("non_blocking", "line_width")

# How a popup looks and behaves; the file, folder, auto-close and line width options
# reach only the message types whose popups take them
@dataclasses.dataclass
class PopupStyle:
    button_color: object = None
    background_color: object = None
    text_color: object = None
    font: object = ("Times", 14)
    line_width: object = None
    icon_file: object = None
    image_file: object = None
    no_window: bool = False
    save_as: bool = False
    file_types: object = None
    initial_folder: object = None
    default_path: object = None
    auto_close_duration: int = 5
    non_blocking: bool = False
    no_titlebar: bool = False
    grab_anywhere: bool = False
    keep_on_top: object = None
    modal: bool = True

# Keyword options for the message type's popup: the common appearance options plus the
# extras that type takes
def _get_popup_options(message_type, title_text, style):
    options = {
        "title": title_text,
        "button_color": style.button_color,
        "background_color": style.background_color,
        "text_color": style.text_color,
        "icon": style.icon_file,
        "font": style.font,
        "no_titlebar": style.no_titlebar,
        "grab_anywhere": style.grab_anywhere,
        "keep_on_top": style.keep_on_top,
        "image": style.image_file,
        "modal": style.modal
    }
    for option_name in _get_popup_extra_option_names(message_type):
        options[option_name] = getattr(style, option_name)
    return options

# Show a PySimpleGUI popup of the given message type in the given style (the default
# PopupStyle when None) and return its answer (button text, entered text or chosen path)
def display_popup(
    title_text,
    message_text,
    message_type = None,
    theme = "DarkAmber",
    style = None):

    # Import PySimpleGUI
    psg = _import_pysimplegui()

    # Check parameters
    validation.assert_is_non_empty_string(title_text, "title_text")
    validation.assert_is_non_empty_string(message_text, "message_text")

    # Set theme
    psg.theme(theme)

    # Display popup (and return result)
    popup_options = _get_popup_options(message_type, title_text, style or PopupStyle())
    return _get_popup_func(psg, message_type)(message_text, **popup_options)

# Show an OK popup kept on top
def display_info_popup(title_text, message_text):
    display_popup(
        title_text = title_text,
        message_text = message_text,
        message_type = config.MessageType.OK,
        style = PopupStyle(keep_on_top = True))

# Show a yes/no popup kept on top; answering No quits the program
def display_warning_popup(title_text, message_text):
    response = display_popup(
        title_text = title_text,
        message_text = message_text,
        message_type = config.MessageType.YES_NO,
        style = PopupStyle(keep_on_top = True))
    if response == "No":
        runtime.quit_program()

# Show an error popup kept on top, then quit the program
def display_error_popup(title_text, message_text):
    display_popup(
        title_text = title_text,
        message_text = message_text,
        message_type = config.MessageType.ERROR,
        style = PopupStyle(keep_on_top = True))
    runtime.quit_program()

# Prompt for text in a popup; returns the entered text, or None when cancelled
def display_text_input_popup(title_text, message_text):
    return display_popup(
        title_text = title_text,
        message_text = message_text,
        message_type = config.MessageType.GET_TEXT)

# Prompt for a file path in a popup; returns the chosen path, or None when cancelled
def display_file_chooser_popup(title_text, message_text):
    return display_popup(
        title_text = title_text,
        message_text = message_text,
        message_type = config.MessageType.GET_FILE)

# Prompt for a folder path in a popup; returns the chosen path, or None when cancelled
def display_folder_chooser_popup(title_text, message_text):
    return display_popup(
        title_text = title_text,
        message_text = message_text,
        message_type = config.MessageType.GET_FOLDER)

# The requested window size, or the primary screen's resolution when it is (None, None)
def _get_window_size(window_size):
    if window_size == (None, None):
        return get_current_screen_resolution()
    return window_size

# The centered title and message rows that head a window
def _build_heading_rows(psg, title_text, message_text, title_font, message_font):
    return [
        [
            psg.Text(
                text = title_text,
                font = title_font,
                expand_x = True,
                justification = "center"
            )
        ],
        [
            psg.Text(
                text = message_text,
                font = message_font,
                expand_x = True,
                justification = "center"
            )
        ]
    ]

# A finalized resizable window, maximized on Windows
def _create_window(psg, title_text, window_layout, window_size):
    window = psg.Window(
        title = title_text,
        layout = window_layout,
        size = window_size,
        resizable = True,
        finalize = True)
    if platform_info.is_windows_platform():
        window.maximize()
    return window

# The loading window's heading, progress bar and, when the image file exists, image rows
def _build_loading_layout(psg, title_text, message_text, title_font, message_font, image_file):

    # Layout window
    window_layout = _build_heading_rows(psg, title_text, message_text, title_font, message_font)
    window_layout += [
        [
            psg.ProgressBar(
                max_value = 100,
                orientation = "h",
                size = (30, 10),
                expand_x = True,
                key = "progress"
            )
        ]
    ]

    # Add image
    if paths.is_path_valid(image_file) and os.path.exists(image_file):
        window_layout += [
            [
                psg.Image(
                    key = "image",
                    expand_x = True,
                    expand_y = True)
            ]
    ]
    return window_layout

# Show the image, scaled to fit half the window's height, in the window's image element;
# a warning when it can't be loaded
def _show_window_image(window, image_file):
    try:
        pil_image = _get_pil_image()
        pil_image_tk = _get_pil_image_tk()
        window_width, window_height = window.size
        image_obj = pil_image.open(image_file)
        image_obj.thumbnail((window_width, window_height / 2))
        window["image"].update(data = pil_image_tk.PhotoImage(image_obj))
    except (ImportError, OSError) as e:
        logger.log_warning("Unable to show image %s: %s" % (image_file, e))

# Popup for a finished task: the completion text on success, the failure text (which quits)
# otherwise; nothing when that text is empty
def _report_task_result(task_result, completion_text, failure_text):
    if task_result:
        if completion_text:
            display_info_popup(
                title_text = "Completed",
                message_text = completion_text)
    elif failure_text:
        display_error_popup(
            title_text = "Failure",
            message_text = failure_text)

# Step the progress bar until the task completes (then report it) or the window is closed
def _run_loading_events(psg, window, completion_text, failure_text, progress_step):
    while True:
        event, values = window.read(timeout=100)
        if event in (psg.WIN_CLOSED, "KEYPRESS_ESCAPE"):
            break

        # Task completed
        if event == "TASK_COMPLETE":
            _report_task_result(values[event], completion_text, failure_text)
            break

        # Update progress bar
        window["progress"].Widget["value"] += progress_step

# Bind Escape, make the progress bar indeterminate and show the image when the file exists
def _setup_loading_window(window, image_file):
    window.bind("<Escape>", "KEYPRESS_ESCAPE")
    window["progress"].Widget.config(mode = "indeterminate")
    if paths.is_path_valid(image_file) and os.path.exists(image_file):
        _show_window_image(window, image_file)

# The task that keeps the loading window open: run_func's result, or False when not callable
def _run_loading_task(run_func, run_func_args):
    if callable(run_func):
        return run_func(**run_func_args)
    return False

# Show a window with an indeterminate progress bar while run_func runs in the background, then a completion or failure popup
def display_loading_window(
    title_text,
    message_text,
    completion_text = "",
    failure_text = "",
    theme = "DarkBrown",
    title_font = ("Times Bold", 20),
    message_font = ("Times", 14),
    progress_step = 5,
    image_file = None,
    window_size = (None, None),
    run_func = None,
    **run_func_args):

    # Import PySimpleGUI
    psg = _import_pysimplegui()

    # Check parameters
    validation.assert_is_non_empty_string(title_text, "title_text")
    validation.assert_is_non_empty_string(message_text, "message_text")
    validation.assert_is_string(completion_text, "completion_text")
    validation.assert_is_string(failure_text, "failure_text")

    # Get window size
    window_size = _get_window_size(window_size)

    # Set theme
    psg.theme(theme)

    # Create window
    window_layout = _build_loading_layout(psg, title_text, message_text, title_font, message_font, image_file)
    window = _create_window(psg, title_text, window_layout, window_size)
    _setup_loading_window(window, image_file)

    # Run task in the background, handle events until it is completed, then close window
    window.perform_long_operation(lambda: _run_loading_task(run_func, run_func_args), "TASK_COMPLETE")
    _run_loading_events(psg, window, completion_text, failure_text, progress_step)
    window.close()

# The choices window's heading, choice list and submit button rows
def _build_choices_layout(psg, choice_list, title_text, message_text, button_text, title_font, message_font, choices_font):
    window_layout = _build_heading_rows(psg, title_text, message_text, title_font, message_font)
    window_layout += [
        [
            psg.Listbox(
                values = choice_list,
                size = (20, 4),
                font = choices_font,
                expand_x = True,
                expand_y = True,
                enable_events = True,
                key = "listbox")
        ],
        [
            psg.Button(
                button_text,
                expand_x = True,
                key = "submit")
        ]
    ]
    return window_layout

# The choice highlighted when submit is pressed; None when the window is closed first
def _read_selected_choice(psg, window):
    while True:
        event, _ = window.read(timeout=100)
        if event in (psg.WIN_CLOSED, "ESCAPE_PRESSED"):
            return None

        # Get selected choice
        if event == 'submit':
            selection = window["listbox"].get()
            if selection:
                return selection[0]

# Show a list of choices and pass the one submitted to run_func; nothing runs when the window is closed
def display_choices_window(
    choice_list,
    title_text,
    message_text,
    button_text,
    theme = "DarkBrown",
    title_font = ("Times Bold", 20),
    message_font = ("Times", 14),
    choices_font = ("Times", 14),
    window_size = (None, None),
    run_func = None):

    # Import PySimpleGUI
    psg = _import_pysimplegui()

    # Check parameters
    validation.assert_is_non_empty_string(title_text, "title_text")
    validation.assert_is_non_empty_string(message_text, "message_text")
    validation.assert_is_non_empty_string(button_text, "button_text")

    # Get window size
    window_size = _get_window_size(window_size)

    # Set theme
    psg.theme(theme)

    # Create window
    window_layout = _build_choices_layout(psg, choice_list, title_text, message_text, button_text, title_font, message_font, choices_font)
    window = _create_window(psg, title_text, window_layout, window_size)
    window.bind("<Escape>", "ESCAPE_PRESSED")

    # Handle events until a choice is submitted or the window is closed
    selected_choice = _read_selected_choice(psg, window)

    # Close window
    window.close()

    # Run selected choice
    if selected_choice and callable(run_func):
        run_func(selected_choice)
