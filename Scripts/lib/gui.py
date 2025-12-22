# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import display
import programs
import modules

# Display popup
def DisplayPopup(
    title_text,
    message_text,
    message_type = None,
    button_color = None,
    background_color = None,
    theme = "DarkAmber",
    text_color = None,
    font = ("Times", 14),
    line_width = None,
    icon_file = None,
    image_file = None,
    no_window = False,
    save_as = False,
    file_types = None,
    initial_folder = None,
    default_path = None,
    auto_close_duration = 5,
    non_blocking = False,
    no_titlebar = False,
    grab_anywhere = False,
    keep_on_top = None,
    modal = True):

    # Import PySimpleGUI
    psg = modules.import_python_module_file(
        module_path = programs.GetToolProgram("PySimpleGUI"),
        module_name = "psg")

    # Check parameters
    system.AssertIsNonEmptyString(title_text, "title_text")
    system.AssertIsNonEmptyString(message_text, "message_text")

    # Set theme
    psg.theme(theme)

    # Get correct popup function
    popup_func = psg.popup
    if message_type == config.MessageType.OK:
        popup_func = psg.popup_ok
    elif message_type == config.MessageType.YES_NO:
        popup_func = psg.popup_yes_no
    elif message_type == config.MessageType.CANCEL:
        popup_func = psg.popup_cancel
    elif message_type == config.MessageType.OK_CANCEL:
        popup_func = psg.popup_ok_cancel
    elif message_type == config.MessageType.ERROR:
        popup_func = psg.popup_error
    elif message_type == config.MessageType.AUTO_CLOSE:
        popup_func = psg.popup_auto_close
    elif message_type == config.MessageType.GET_TEXT:
        popup_func = psg.popup_get_text
    elif message_type == config.MessageType.GET_FILE:
        popup_func = psg.popup_get_file
    elif message_type == config.MessageType.GET_FOLDER:
        popup_func = psg.popup_get_folder

    # Display popup (and return result)
    if message_type == config.MessageType.AUTO_CLOSE:
        return popup_func(
            message_text,
            title = title_text,
            button_color = button_color,
            background_color = background_color,
            text_color = text_color,
            auto_close_duration = auto_close_duration,
            non_blocking = non_blocking,
            icon = icon_file,
            line_width = line_width,
            font = font,
            no_titlebar = no_titlebar,
            grab_anywhere = grab_anywhere,
            keep_on_top = keep_on_top,
            image = image_file,
            modal = modal)
    elif message_type == config.MessageType.GET_TEXT:
        return popup_func(
            message_text,
            title = title_text,
            button_color = button_color,
            background_color = background_color,
            text_color = text_color,
            icon = icon_file,
            font = font,
            no_titlebar = no_titlebar,
            grab_anywhere = grab_anywhere,
            keep_on_top = keep_on_top,
            image = image_file,
            modal = modal)
    elif message_type == config.MessageType.GET_FILE:
        return popup_func(
            message_text,
            title = title_text,
            button_color = button_color,
            background_color = background_color,
            text_color = text_color,
            icon = icon_file,
            font = font,
            no_titlebar = no_titlebar,
            grab_anywhere = grab_anywhere,
            keep_on_top = keep_on_top,
            image = image_file,
            modal = modal,
            no_window = no_window,
            save_as = save_as,
            file_types = file_types,
            initial_folder = initial_folder,
            default_path = default_path)
    elif message_type == config.MessageType.GET_FOLDER:
        return popup_func(
            message_text,
            title = title_text,
            button_color = button_color,
            background_color = background_color,
            text_color = text_color,
            icon = icon_file,
            font = font,
            no_titlebar = no_titlebar,
            grab_anywhere = grab_anywhere,
            keep_on_top = keep_on_top,
            image = image_file,
            modal = modal,
            no_window = no_window,
            initial_folder = initial_folder,
            default_path = default_path)
    else:
        return popup_func(
            message_text,
            title = title_text,
            button_color = button_color,
            background_color = background_color,
            text_color = text_color,
            non_blocking = non_blocking,
            icon = icon_file,
            line_width = line_width,
            font = font,
            no_titlebar = no_titlebar,
            grab_anywhere = grab_anywhere,
            keep_on_top = keep_on_top,
            image = image_file,
            modal = modal)

# Display info popup
def DisplayInfoPopup(title_text, message_text):
    DisplayPopup(
        title_text = title_text,
        message_text = message_text,
        message_type = config.MessageType.OK,
        keep_on_top = True)

# Display warning popup
def DisplayWarningPopup(title_text, message_text):
    response = DisplayPopup(
        title_text = title_text,
        message_text = message_text,
        message_type = config.MessageType.YES_NO,
        keep_on_top = True)
    if response == "No":
        system.QuitProgram()

# Display error popup
def DisplayErrorPopup(title_text, message_text):
    DisplayPopup(
        title_text = title_text,
        message_text = message_text,
        message_type = config.MessageType.ERROR,
        keep_on_top = True)
    system.QuitProgram()

# Display text input popup
def DisplayTextInputPopup(title_text, message_text):
    return DisplayPopup(
        title_text = title_text,
        message_text = message_text,
        message_type = config.MessageType.GET_TEXT)

# Display file chooser popup
def DisplayFileChooserPopup(title_text, message_text):
    return DisplayPopup(
        title_text = title_text,
        message_text = message_text,
        message_type = config.MessageType.GET_FILE)

# Display folder chooser popup
def DisplayFolderChooserPopup(title_text, message_text):
    return DisplayPopup(
        title_text = title_text,
        message_text = message_text,
        message_type = config.MessageType.GET_FOLDER)

# Display loading window
def DisplayLoadingWindow(
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
    psg = modules.import_python_module_file(
        module_path = programs.GetToolProgram("PySimpleGUI"),
        module_name = "psg")

    # Check parameters
    system.AssertIsNonEmptyString(title_text, "title_text")
    system.AssertIsNonEmptyString(message_text, "message_text")
    system.AssertIsString(completion_text, "completion_text")
    system.AssertIsString(failure_text, "failure_text")

    # Get window size
    if window_size == (None, None):
        window_size = display.GetCurrentScreenResolution()

    # Set theme
    psg.theme(theme)

    # Layout window
    window_layout = [
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
        ],
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
    if system.IsPathValid(image_file) and os.path.exists(image_file):
        window_layout += [
            [
                psg.Image(
                    key = "image",
                    expand_x = True,
                    expand_y = True)
            ]
    ]

    # Create window
    window = psg.Window(
        title = title_text,
        layout = window_layout,
        size = window_size,
        resizable = True,
        finalize = True)
    if environment.IsWindowsPlatform():
        window.maximize()
    window.bind("<Escape>", "KEYPRESS_ESCAPE")
    window["progress"].Widget.config(mode = "indeterminate")
    if system.IsPathValid(image_file) and os.path.exists(image_file):
        try:
            from PIL import Image, ImageTk
            window_width, window_height = window.size
            image_obj = Image.open(image_file)
            image_obj.thumbnail((window_width, window_height / 2))
            window["image"].update(data = ImageTk.PhotoImage(image_obj))
        except:
            pass

    # Task that will keep the window open until it is done
    def doTask():
        if callable(run_func):
            if run_func_args:
                return run_func(run_func_args)
            else:
                return run_func()

    # Run task in the background and wait for it to be completed
    window.perform_long_operation(doTask, "TASK_COMPLETE")

    # Handle events
    while True:
        event, values = window.read(timeout=100)
        if event in (psg.WIN_CLOSED, "KEYPRESS_ESCAPE"):
            break

        # Task completed
        if event == "TASK_COMPLETE":
            if values[event]:
                if len(completion_text):
                    DisplayInfoPopup(
                        title_text = "Completed",
                        message_text = completion_text)
            else:
                if len(failure_text):
                    DisplayErrorPopup(
                        title_text = "Failure",
                        message_text = failure_text)
            break

        # Update progress bar
        window["progress"].Widget["value"] += progress_step

    # Close window
    window.close()

# Display choices window
def DisplayChoicesWindow(
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
    psg = modules.import_python_module_file(
        module_path = programs.GetToolProgram("PySimpleGUI"),
        module_name = "psg")

    # Check parameters
    system.AssertIsNonEmptyString(title_text, "title_text")
    system.AssertIsNonEmptyString(message_text, "message_text")
    system.AssertIsNonEmptyString(button_text, "button_text")

    # Get window size
    if window_size == (None, None):
        window_size = display.GetCurrentScreenResolution()

    # Run selected choice
    def RunSelectedChoice(choice):
        if callable(run_func):
            run_func(choice)

    # Set theme
    psg.theme(theme)

    # Layout window
    window_layout = [
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
        ],
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

    # Create window
    window = psg.Window(
        title = title_text,
        layout = window_layout,
        size = window_size,
        resizable = True,
        finalize = True)
    if environment.IsWindowsPlatform():
        window.maximize()
    window.bind("<Escape>", "ESCAPE_PRESSED")

    # Selected choice
    selected_choice = None

    # Handle events
    while True:
        event, values = window.read(timeout=100)
        if event in (psg.WIN_CLOSED, "ESCAPE_PRESSED"):
            break

        # Get selected choice
        if event == 'submit':
            selected_choice = window["listbox"].get()[0]
            break

    # Close window
    window.close()

    # Run selected choice
    if selected_choice:
        RunSelectedChoice(selected_choice)
