# Imports
import importlib
import pkgutil
import sys
import types

import pytest


###########################################################
# Package namespaces
#
# Every package under joybox re-exports its contents with star imports. When a
# submodule imports a same-named top level module, that module lands on the
# package under the submodule's name, so joybox.collection.jsondata resolves to
# joybox.jsondata - a wrong module that imports cleanly and then fails on first
# use.
###########################################################

def discover_packages():
    import joybox
    return sorted(
        info.name
        for info in pkgutil.walk_packages(joybox.__path__, prefix = "joybox.")
        if info.ispkg)


PACKAGES = discover_packages()


def submodules_of(package_name):
    package = importlib.import_module(package_name)
    return sorted(
        info.name for info in pkgutil.iter_modules(package.__path__)
        if not info.name.startswith("_"))


CASES = [
    (package, submodule)
    for package in PACKAGES
    for submodule in submodules_of(package)
]

CASE_IDS = ["%s.%s" % pair for pair in CASES]


def test_packages_were_discovered():
    assert len(PACKAGES) > 2


def test_submodules_were_discovered():
    assert len(CASES) > 20


@pytest.mark.parametrize("package,submodule", CASES, ids = CASE_IDS)
def test_every_submodule_imports_under_its_own_name(package, submodule):
    full_name = "%s.%s" % (package, submodule)
    module = importlib.import_module(full_name)

    assert module.__name__ == full_name
    assert sys.modules[full_name] is module


@pytest.mark.parametrize("package,submodule", CASES, ids = CASE_IDS)
def test_a_submodule_name_is_not_taken_by_another_module(package, submodule):
    # A non-module attribute under the same name is a deliberate data export,
    # and fails loudly on first use. Another module is the silent case.
    full_name = "%s.%s" % (package, submodule)
    importlib.import_module(full_name)
    attribute = getattr(importlib.import_module(package), submodule, None)

    if not isinstance(attribute, types.ModuleType):
        pytest.skip("%s exports a non-module under this name" % package)

    assert attribute.__name__ == full_name


@pytest.mark.parametrize("package", PACKAGES)
def test_every_submodule_is_reachable_from_its_package(package):
    # A submodule the package __init__ never imports is invisible to callers
    # that only import the package.
    module = importlib.import_module(package)
    missing = [
        submodule for submodule in submodules_of(package)
        if not hasattr(module, submodule)
    ]

    assert not missing, f"{package} does not export: {missing}"


###########################################################
# Exported names
###########################################################

def public_definitions(module):
    import inspect
    found = {}
    for name, value in vars(module).items():
        if name.startswith("_") or isinstance(value, types.ModuleType):
            continue
        if not (inspect.isfunction(value) or inspect.isclass(value)):
            continue
        if getattr(value, "__module__", None) != module.__name__:
            continue
        found[name] = value
    return found


@pytest.mark.parametrize("package", PACKAGES)
def test_a_name_defined_twice_is_not_exported_bare(package):
    # Two submodules defining get_libs32 are exported as get_dxvk_libs32 and
    # get_vkd3d_libs32. A bare export could only be one of them, and the other
    # would be unreachable through the package.
    owners = {}
    for submodule in submodules_of(package):
        module = importlib.import_module("%s.%s" % (package, submodule))
        for name, value in public_definitions(module).items():
            owners.setdefault(name, []).append((submodule, value))

    module = importlib.import_module(package)
    shadowed = {}
    for name, claimants in owners.items():
        if len(claimants) < 2:
            continue
        exported = getattr(module, name, None)
        if exported is None:
            continue
        losers = [owner for owner, value in claimants if value is not exported]
        if losers:
            shadowed[name] = losers

    assert not shadowed, f"{package} exports one of several definitions: {shadowed}"


@pytest.mark.parametrize("package", PACKAGES)
def test_every_exported_definition_is_the_one_it_names(package):
    # An alias that points at the wrong submodule's function is invisible until
    # the wrong libraries get installed.
    module = importlib.import_module(package)
    wrong = []
    for name, value in vars(module).items():
        if name.startswith("_") or isinstance(value, types.ModuleType):
            continue
        origin = getattr(value, "__module__", None)
        if not origin or not origin.startswith(package + "."):
            continue
        if not hasattr(importlib.import_module(origin), getattr(value, "__name__", "")):
            wrong.append(name)

    assert not wrong, f"{package} exports names missing from their own module: {wrong}"
