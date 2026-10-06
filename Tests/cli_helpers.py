# Imports
import runpy
import sys

# Third-party imports
import pytest

# Local imports
from joybox import config, gui, logger, prompts, setup, system

###########################################################
# In-process command harness
#
# Drives a joybox.cli module with sys.argv set. Requirement checks and logging
# setup are skipped. Errors, warnings, infos, previews and error popups are
# recorded; log calls still reach the real logger, so quit_program exits as it
# does in use, and a popup quits as the real one does.
###########################################################

class CommandHarness:

    def __init__(self, monkeypatch, module):
        self.monkeypatch = monkeypatch
        self.module = module
        self.errors = []
        self.warnings = []
        self.infos = []
        self.previews = []
        self.popups = []
        self.confirm = True
        monkeypatch.setattr(setup, "check_requirements", lambda: None)
        monkeypatch.setattr(logger, "setup_logging", lambda: None)
        for name, store in (("log_error", self.errors), ("log_warning", self.warnings), ("log_info", self.infos)):
            monkeypatch.setattr(logger, name, self._recorder(getattr(logger, name), store))
        monkeypatch.setattr(prompts, "prompt_for_preview", self._preview)
        monkeypatch.setattr(gui, "display_error_popup", self._popup)

    @staticmethod
    def _recorder(original, store):
        def record(message, *args, **kwargs):
            store.append(message)
            return original(message, *args, **kwargs)
        return record

    def _preview(self, title, details):
        self.previews.append((title, list(details)))
        return self.confirm

    def _popup(self, title_text, message_text):
        self.popups.append(title_text)
        raise SystemExit(-1)

    def _set_argv(self, argv):
        self.monkeypatch.setattr(sys, "argv", [self.module.__name__.rsplit(".", 1)[-1], *argv])

    def main(self, *argv):
        # Calls main() directly: its return value and exceptions come back as-is
        self._set_argv(argv)
        return self.module.main()

    def run(self, *argv):
        # Goes through run() and the shared error handling, as the installed command does
        self._set_argv(argv)
        return self.module.run()

    def exit_code(self, *argv):
        with pytest.raises(SystemExit) as raised:
            self.run(*argv)
        return raised.value.code


###########################################################
# Call recorder
###########################################################

class Recorder:

    # Stands in for a joybox function, keeping each call's keyword arguments;
    # positional arguments, if any, are kept under "_args"
    def __init__(self, result = None):
        self.calls = []
        self.result = result

    def __call__(self, *args, **kwargs):
        self.calls.append(dict(kwargs, _args = args) if args else kwargs)
        return self.result(*args, **kwargs) if callable(self.result) else self.result

    def values(self, key):
        return [call[key] for call in self.calls]


###########################################################
# Entry points
###########################################################

def assert_entry_points(monkeypatch, module):
    # run() and the __main__ guard both hand main() to the shared error handling
    called = []
    monkeypatch.setattr(system, "run_main", called.append)

    module.run()
    runpy.run_path(module.__file__, run_name = "__main__")

    assert called[0] is module.main
    assert len(called) == 2


###########################################################
# Game info
###########################################################

class FakeGameInfo:

    def __init__(self, name, supercategory = config.Supercategory.ROMS, category = config.Category.NINTENDO,
                 subcategory = config.Subcategory.NINTENDO_SWITCH):
        self.name = name
        self.supercategory = supercategory
        self.category = category
        self.subcategory = subcategory

    def get_name(self):
        return self.name

    def get_supercategory(self):
        return self.supercategory

    def get_category(self):
        return self.category

    def get_subcategory(self):
        return self.subcategory
