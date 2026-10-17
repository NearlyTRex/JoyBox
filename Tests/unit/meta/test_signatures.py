# Imports
import importlib
import inspect
import pkgutil
import warnings

# Local imports
import joybox


###########################################################
# Override signatures
#
# A method that overrides a base class method is called through the base
# type: callers hold an Emulator, an Installer or a Connection and don't know
# which subclass they got. An override that renames, drops or reorders a
# parameter, or changes a default, makes a call that works on one subclass
# raise TypeError, or quietly mean something else, on another. An override
# keeps every parameter of the method it overrides, unchanged and in order,
# and may add optional ones after them. There is no list of exceptions.
###########################################################

OPTIONAL_KINDS = (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)


# Every class defined in a joybox module, by its full name
def library_classes():
    found = {}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for module_info in pkgutil.walk_packages(joybox.__path__, "joybox."):
            module = importlib.import_module(module_info.name)
            for value in vars(module).values():
                if inspect.isclass(value) and value.__module__ == module.__name__:
                    found["%s.%s" % (value.__module__, value.__qualname__)] = value
    return found


# Whether member cannot stand in for base_member
def breaks_the_contract(base_member, member):
    base_parameters = list(inspect.signature(inspect.unwrap(base_member)).parameters.values())
    own_parameters = list(inspect.signature(inspect.unwrap(member)).parameters.values())
    if len(own_parameters) < len(base_parameters):
        return True
    for base, own in zip(base_parameters, own_parameters[:len(base_parameters)], strict = True):
        if (base.name, base.kind, base.default) != (own.name, own.kind, own.default):
            return True
    return any(
        extra.default is inspect.Parameter.empty and extra.kind not in OPTIONAL_KINDS
        for extra in own_parameters[len(base_parameters):])


# module.Class.method for each override that breaks its base's contract.
# Dunders are skipped: __init__ legitimately differs per subclass.
def mismatched_overrides(classes):
    found = []
    for cls in classes:
        for name, member in vars(cls).items():
            if (name.startswith("__") and name.endswith("__")) or not inspect.isfunction(member):
                continue
            base_member = next(
                (vars(base)[name] for base in cls.__mro__[1:] if inspect.isfunction(vars(base).get(name))), None)
            if base_member is not None and breaks_the_contract(base_member, member):
                found.append("%s.%s.%s" % (cls.__module__, cls.__qualname__, name))
    return sorted(found)


LIBRARY_CLASSES = library_classes()


def test_library_classes_were_discovered():
    assert "joybox.emulatorbase.EmulatorBase" in LIBRARY_CLASSES
    assert len(LIBRARY_CLASSES) > 200


def test_an_override_keeps_the_signature_of_the_method_it_overrides():
    found = mismatched_overrides(LIBRARY_CLASSES.values())

    assert found == [], "overrides that break the contract of their base method: " + ", ".join(found)

###########################################################
# The check itself
#
# The classes are assembled with type() because their overrides are broken
# on purpose, which a class statement would have linters flag.
###########################################################

def one_parameter(self, a): ...
def renamed_parameter(self, x): ...
def optional_second(self, a, b = 1): ...
def required_second(self, a, b): ...
def extra_optional(self, a, b = None, **options): ...
def swapped(self, b, a): ...
def default_changed(self, a, b = 2): ...
def no_parameters(self): ...


Base = type("Base", (), {
    "same": optional_second,
    "renamed": one_parameter,
    "dropped_default": optional_second,
    "added_optional": one_parameter,
    "added_required": one_parameter,
    "dropped": optional_second,
    "reordered": required_second,
    "_private": one_parameter,
})

Child = type("Child", (Base,), {
    "same": optional_second,
    "renamed": renamed_parameter,
    "dropped_default": required_second,
    "added_optional": extra_optional,
    "added_required": required_second,
    "dropped": one_parameter,
    "reordered": swapped,
    "_private": renamed_parameter,
    "new_method": no_parameters,
})

GrandChild = type("GrandChild", (Child,), {"same": default_changed})


def method_names(found):
    return [name.split(".")[-1] for name in found]


def test_renamed_dropped_reordered_and_changed_default_parameters_are_flagged():
    assert method_names(mismatched_overrides([Child])) == [
        "_private", "added_required", "dropped", "dropped_default", "renamed", "reordered"]


def test_optional_parameters_after_the_base_ones_and_new_methods_are_allowed():
    found = method_names(mismatched_overrides([Child]))

    assert "added_optional" not in found
    assert "new_method" not in found


def test_an_override_is_compared_with_the_nearest_base_that_defines_it():
    assert method_names(mismatched_overrides([GrandChild])) == ["same"]
