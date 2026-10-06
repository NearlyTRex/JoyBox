# Imports
import sys

import pytest

# Local imports
from joybox import modules


###########################################################
# Importing bundled Python modules
###########################################################

@pytest.fixture
def clean_modules(monkeypatch):
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "modules", dict(sys.modules))


def test_a_package_directory_is_imported(tmp_path, clean_modules):
    package = tmp_path / "joybox_probe_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("VALUE = 7\n")

    module = modules.import_python_module_package(str(tmp_path), "joybox_probe_pkg")

    assert module.VALUE == 7
    assert str(tmp_path) in sys.path


def test_an_already_imported_package_is_reused(tmp_path, clean_modules):
    sentinel = object()
    sys.modules["joybox_probe_loaded"] = sentinel

    module = modules.import_python_module_package(str(tmp_path), "joybox_probe_loaded")

    assert module is sentinel
    assert str(tmp_path) not in sys.path


def test_a_missing_package_directory_imports_nothing(tmp_path, clean_modules):
    assert modules.import_python_module_package(str(tmp_path / "absent"), "x") is None


def test_a_module_file_is_imported_and_registered(tmp_path, clean_modules):
    source = tmp_path / "probe.py"
    source.write_text("VALUE = 9\n")

    module = modules.import_python_module_file(str(source), "joybox_probe_file")

    assert module.VALUE == 9
    assert sys.modules["joybox_probe_file"] is module


def test_a_missing_module_file_imports_nothing(tmp_path, clean_modules):
    assert modules.import_python_module_file(str(tmp_path / "absent.py"), "x") is None
