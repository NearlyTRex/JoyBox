# Imports
import sys
import types

# Third-party imports
import pytest

# Local imports
from joybox import config, gui


###########################################################
# Popups and windows
#
# PySimpleGUI is loaded from the tool registry at call time and needs a
# display, so a stand-in records what would have been shown and plays back a
# scripted series of window events.
###########################################################

CLOSED = "__WINDOW_CLOSED__"
SCREEN = (1920, 1080)

POPUP_NAMES = [
    "popup", "popup_ok", "popup_yes_no", "popup_cancel", "popup_ok_cancel",
    "popup_error", "popup_auto_close", "popup_get_text", "popup_get_file",
    "popup_get_folder"]


class Widget(dict):
    def __init__(self):
        super().__init__(value = 0)
        self.configured = {}

    def config(self, **kwargs):
        self.configured.update(kwargs)


class Element:
    def __init__(self, selection = None):
        self.Widget = Widget()
        self.updates = []
        self.selection = selection or []

    def update(self, **kwargs):
        self.updates.append(kwargs)

    def get(self):
        return self.selection


class Window:
    def __init__(self, psg, title, layout, size, resizable, finalize):
        self.psg = psg
        self.title = title
        self.layout = layout
        self.size = size
        self.maximized = False
        self.bindings = {}
        self.closed = False
        self.task_result = None
        self.events = list(psg.events)
        self.elements = {
            "progress": Element(),
            "image": Element(),
            "listbox": Element(psg.selections.pop(0) if psg.selections else None)}
        psg.windows.append(self)

    def maximize(self):
        self.maximized = True

    def bind(self, key, event):
        self.bindings[key] = event

    def __getitem__(self, key):
        return self.elements[key]

    def perform_long_operation(self, func, key):
        self.task_result = func()

    def read(self, timeout = None):
        event = self.events.pop(0) if self.events else CLOSED
        return event, {event: self.task_result}

    def close(self):
        self.closed = True


def make_psg(events = (), selections = ()):
    psg = types.SimpleNamespace(
        WIN_CLOSED = CLOSED,
        events = list(events),
        selections = list(selections),
        themes = [],
        popups = [],
        windows = [])
    psg.theme = psg.themes.append
    for name in POPUP_NAMES:
        def popup(message, _name = name, **kwargs):
            psg.popups.append((_name, message, kwargs))
            return psg.popup_result
        setattr(psg, name, popup)
    psg.popup_result = None
    psg.Text = lambda **kwargs: ("Text", kwargs)
    psg.ProgressBar = lambda **kwargs: ("ProgressBar", kwargs)
    psg.Image = lambda **kwargs: ("Image", kwargs)
    psg.Listbox = lambda **kwargs: ("Listbox", kwargs)
    psg.Button = lambda text, **kwargs: ("Button", text, kwargs)
    psg.Window = lambda **kwargs: Window(psg, **kwargs)
    return psg


@pytest.fixture
def psg(monkeypatch):
    fake = make_psg()
    monkeypatch.setattr(gui.programs, "get_tool_program", lambda name: "PySimpleGUI.py")
    monkeypatch.setattr(
        gui.modules, "import_python_module_file",
        lambda module_path, module_name: fake)
    monkeypatch.setattr(gui.display, "get_current_screen_resolution", lambda: SCREEN)
    monkeypatch.setattr(gui.platform_info, "is_windows_platform", lambda: False)
    return fake


@pytest.fixture
def quits(monkeypatch):
    calls = []
    monkeypatch.setattr(gui.runtime, "quit_program", lambda: calls.append(True))
    return calls


def script(psg, *events, selections = ()):
    psg.events[:] = list(events)
    psg.selections[:] = list(selections)


###########################################################
# Popup selection
###########################################################

@pytest.mark.parametrize("message_type,expected", [
    (None, "popup"),
    (config.MessageType.GENERAL, "popup"),
    (config.MessageType.OK, "popup_ok"),
    (config.MessageType.YES_NO, "popup_yes_no"),
    (config.MessageType.CANCEL, "popup_cancel"),
    (config.MessageType.OK_CANCEL, "popup_ok_cancel"),
    (config.MessageType.ERROR, "popup_error"),
    (config.MessageType.AUTO_CLOSE, "popup_auto_close"),
    (config.MessageType.GET_TEXT, "popup_get_text"),
    (config.MessageType.GET_FILE, "popup_get_file"),
    (config.MessageType.GET_FOLDER, "popup_get_folder"),
])
def test_each_message_type_uses_its_popup(psg, message_type, expected):
    gui.display_popup("Title", "Message", message_type = message_type)

    assert [name for name, _, _ in psg.popups] == [expected]


def test_a_popup_shows_its_message_and_title(psg):
    gui.display_popup("Title", "Message")
    _, message, kwargs = psg.popups[0]

    assert message == "Message"
    assert kwargs["title"] == "Title"


def test_a_popup_returns_the_users_answer(psg):
    psg.popup_result = "Yes"

    assert gui.display_popup("Title", "Message", config.MessageType.YES_NO) == "Yes"


def test_a_popup_applies_its_theme(psg):
    gui.display_popup("Title", "Message", theme = "Black")

    assert psg.themes == ["Black"]


def test_an_auto_close_popup_carries_its_duration(psg):
    gui.display_popup(
        "Title", "Message", config.MessageType.AUTO_CLOSE,
        auto_close_duration = 9, non_blocking = True)
    kwargs = psg.popups[0][2]

    assert kwargs["auto_close_duration"] == 9
    assert kwargs["non_blocking"] is True


def test_a_text_prompt_takes_no_line_width(psg):
    gui.display_popup("Title", "Message", config.MessageType.GET_TEXT)

    assert "line_width" not in psg.popups[0][2]


def test_a_file_chooser_carries_its_file_options(psg):
    gui.display_popup(
        "Title", "Message", config.MessageType.GET_FILE,
        save_as = True, file_types = (("Text", "*.txt"),),
        initial_folder = "/start", default_path = "/start/file.txt")
    kwargs = psg.popups[0][2]

    assert kwargs["save_as"] is True
    assert kwargs["file_types"] == (("Text", "*.txt"),)
    assert kwargs["initial_folder"] == "/start"
    assert kwargs["default_path"] == "/start/file.txt"


def test_a_folder_chooser_has_no_save_mode(psg):
    gui.display_popup(
        "Title", "Message", config.MessageType.GET_FOLDER, initial_folder = "/start")
    kwargs = psg.popups[0][2]

    assert kwargs["initial_folder"] == "/start"
    assert "save_as" not in kwargs


def test_a_plain_popup_carries_its_appearance(psg):
    gui.display_popup(
        "Title", "Message", button_color = "red", line_width = 40,
        icon_file = "icon.png", image_file = "image.png", keep_on_top = True)
    kwargs = psg.popups[0][2]

    assert kwargs["button_color"] == "red"
    assert kwargs["line_width"] == 40
    assert kwargs["icon"] == "icon.png"
    assert kwargs["image"] == "image.png"
    assert kwargs["keep_on_top"] is True


@pytest.mark.parametrize("title,message", [("", "Message"), ("Title", ""), (None, "Message")])
def test_a_popup_needs_a_title_and_message(psg, title, message):
    with pytest.raises(AssertionError):
        gui.display_popup(title, message)
    assert psg.popups == []


###########################################################
# Popup shortcuts
###########################################################

def test_an_info_popup_is_an_ok_on_top(psg):
    gui.display_info_popup("Title", "Message")
    name, _, kwargs = psg.popups[0]

    assert name == "popup_ok"
    assert kwargs["keep_on_top"] is True


def test_accepting_a_warning_carries_on(psg, quits):
    psg.popup_result = "Yes"
    gui.display_warning_popup("Title", "Message")

    assert psg.popups[0][0] == "popup_yes_no"
    assert quits == []


def test_declining_a_warning_quits(psg, quits):
    psg.popup_result = "No"
    gui.display_warning_popup("Title", "Message")

    assert quits == [True]


def test_an_error_popup_quits_after_showing(psg, quits):
    gui.display_error_popup("Title", "Message")

    assert psg.popups[0][0] == "popup_error"
    assert quits == [True]


@pytest.mark.parametrize("func,expected", [
    (gui.display_text_input_popup, "popup_get_text"),
    (gui.display_file_chooser_popup, "popup_get_file"),
    (gui.display_folder_chooser_popup, "popup_get_folder"),
])
def test_input_popups_return_what_was_entered(psg, func, expected):
    psg.popup_result = "entered"

    assert func("Title", "Message") == "entered"
    assert psg.popups[0][0] == expected


###########################################################
# Loading window
###########################################################

def test_a_loading_window_runs_its_task(psg):
    ran = []
    gui.display_loading_window("Title", "Message", run_func = lambda: ran.append(True))

    assert ran == [True]


def test_a_loading_window_forwards_task_arguments(psg):
    received = []
    gui.display_loading_window(
        "Title", "Message",
        run_func = lambda **kwargs: received.append(kwargs),
        game = "Name", platform = "System")

    assert received == [{"game": "Name", "platform": "System"}]


def test_a_loading_window_without_a_task_fails_it(psg, quits):
    script(psg, "TASK_COMPLETE")
    gui.display_loading_window("Title", "Message", failure_text = "Broken")

    assert [name for name, _, _ in psg.popups] == ["popup_error"]


def test_a_finished_task_shows_its_completion(psg):
    script(psg, "TASK_COMPLETE")
    gui.display_loading_window(
        "Title", "Message", completion_text = "Done", run_func = lambda: True)

    assert [(name, message) for name, message, _ in psg.popups] == [("popup_ok", "Done")]
    assert psg.windows[0].closed is True


def test_a_finished_task_without_completion_text_shows_nothing(psg):
    script(psg, "TASK_COMPLETE")
    gui.display_loading_window("Title", "Message", run_func = lambda: True)

    assert psg.popups == []


def test_a_failed_task_shows_its_failure_and_quits(psg, quits):
    script(psg, "TASK_COMPLETE")
    gui.display_loading_window(
        "Title", "Message", failure_text = "Broken", run_func = lambda: False)

    assert [(name, message) for name, message, _ in psg.popups] == [("popup_error", "Broken")]
    assert quits == [True]


def test_a_failed_task_without_failure_text_shows_nothing(psg, quits):
    script(psg, "TASK_COMPLETE")
    gui.display_loading_window("Title", "Message", run_func = lambda: False)

    assert psg.popups == []
    assert quits == []


def test_the_progress_bar_advances_while_waiting(psg):
    script(psg, "__TIMEOUT__", "__TIMEOUT__", "TASK_COMPLETE")
    gui.display_loading_window("Title", "Message", progress_step = 7, run_func = lambda: True)
    progress = psg.windows[0]["progress"].Widget

    assert progress["value"] == 14
    assert progress.configured == {"mode": "indeterminate"}


@pytest.mark.parametrize("event", ["KEYPRESS_ESCAPE", CLOSED])
def test_escape_or_close_leaves_the_loading_window(psg, event):
    script(psg, event, "TASK_COMPLETE")
    gui.display_loading_window("Title", "Message", completion_text = "Done", run_func = lambda: True)

    assert psg.popups == []
    assert psg.windows[0].closed is True


def test_a_loading_window_fills_the_screen_by_default(psg):
    gui.display_loading_window("Title", "Message")

    assert psg.windows[0].size == SCREEN


def test_a_loading_window_keeps_a_given_size(psg):
    gui.display_loading_window("Title", "Message", window_size = (640, 480))

    assert psg.windows[0].size == (640, 480)


@pytest.mark.parametrize("windows", [True, False])
def test_a_loading_window_is_maximized_only_on_windows(psg, monkeypatch, windows):
    monkeypatch.setattr(gui.platform_info, "is_windows_platform", lambda: windows)
    gui.display_loading_window("Title", "Message")

    assert psg.windows[0].maximized is windows


@pytest.mark.parametrize("completion,failure", [(None, ""), ("", None)])
def test_loading_window_texts_must_be_strings(psg, completion, failure):
    with pytest.raises(AssertionError):
        gui.display_loading_window(
            "Title", "Message", completion_text = completion, failure_text = failure)
    assert psg.windows == []


def fake_pil(monkeypatch, open_image):
    thumbnails = []

    class Picture:
        def thumbnail(self, size):
            thumbnails.append(size)

    image_module = types.SimpleNamespace(open = lambda path: open_image(path, Picture))
    imagetk_module = types.SimpleNamespace(PhotoImage = lambda image: ("photo", image))
    monkeypatch.setitem(
        sys.modules, "PIL",
        types.SimpleNamespace(Image = image_module, ImageTk = imagetk_module))
    return thumbnails


def test_a_loading_window_shows_its_image(psg, monkeypatch, tmp_path):
    image = tmp_path / "boxfront.png"
    image.write_bytes(b"PNG")
    thumbnails = fake_pil(monkeypatch, lambda path, picture: picture())
    gui.display_loading_window("Title", "Message", image_file = str(image), window_size = (800, 600))
    window = psg.windows[0]

    assert ("Image", {"key": "image", "expand_x": True, "expand_y": True}) in \
        [row[0] for row in window.layout]
    assert thumbnails == [(800, 300)]
    assert window["image"].updates[0]["data"][0] == "photo"


def test_an_unreadable_image_still_opens_the_window(psg, monkeypatch, tmp_path):
    image = tmp_path / "boxfront.png"
    image.write_bytes(b"PNG")

    def broken(path, picture):
        raise OSError("unreadable")

    fake_pil(monkeypatch, broken)
    gui.display_loading_window("Title", "Message", image_file = str(image))

    assert psg.windows[0]["image"].updates == []
    assert psg.windows[0].closed is True


def test_a_missing_image_is_left_out(psg, tmp_path):
    gui.display_loading_window("Title", "Message", image_file = str(tmp_path / "absent.png"))

    assert len(psg.windows[0].layout) == 3


###########################################################
# Choices window
###########################################################

def choose(psg, *events, selections = (), **kwargs):
    script(psg, *events, selections = selections)
    chosen = []
    gui.display_choices_window(
        ["First", "Second"], "Title", "Message", "Go",
        run_func = chosen.append, **kwargs)
    return chosen


def test_submitting_runs_the_selected_choice(psg):
    assert choose(psg, "listbox", "submit", selections = [["Second"]]) == ["Second"]
    assert psg.windows[0].closed is True


def test_the_choices_are_listed(psg):
    choose(psg, "submit", selections = [["First"]])
    listbox = [row[0] for row in psg.windows[0].layout if row[0][0] == "Listbox"][0]

    assert listbox[1]["values"] == ["First", "Second"]


@pytest.mark.parametrize("event", ["ESCAPE_PRESSED", CLOSED])
def test_escape_or_close_chooses_nothing(psg, event):
    assert choose(psg, event, selections = [["First"]]) == []


def test_submitting_with_nothing_selected_keeps_waiting(psg):
    assert choose(psg, "submit", CLOSED, selections = [[]]) == []


def test_a_choice_without_a_handler_is_dropped(psg):
    script(psg, "submit", selections = [["First"]])
    gui.display_choices_window(["First"], "Title", "Message", "Go")

    assert psg.windows[0].closed is True


def test_a_choices_window_fills_the_screen_by_default(psg):
    choose(psg)

    assert psg.windows[0].size == SCREEN


def test_a_choices_window_keeps_a_given_size(psg):
    choose(psg, window_size = (640, 480))

    assert psg.windows[0].size == (640, 480)


@pytest.mark.parametrize("windows", [True, False])
def test_a_choices_window_is_maximized_only_on_windows(psg, monkeypatch, windows):
    monkeypatch.setattr(gui.platform_info, "is_windows_platform", lambda: windows)
    choose(psg)

    assert psg.windows[0].maximized is windows


def test_a_choices_window_needs_button_text(psg):
    with pytest.raises(AssertionError):
        gui.display_choices_window(["First"], "Title", "Message", "")
    assert psg.windows == []
