# Imports
import inspect

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.config.types import AssetType
from joybox.config.types import EnumType
from joybox.config.types import RemoteActionSyncType
from joybox.config.types import RemoteActionType
from joybox.config.types import SetupParams


class Shade(EnumType):
    DARK = ("Dark")
    LIGHT = ("Light", ".lt")


class Borrowed(EnumType):
    # Members built from another enum's member, or from a nested pair
    VIDEO = AssetType.VIDEO
    PAIR = (("Pair", ".pr"),)


class Numbered(EnumType):
    ONE = 1


class Other(EnumType):
    DARK = ("Dark")
    MISSING = ("Missing")


###########################################################
# EnumType
#
# EnumType is deliberately string-interoperable: a member compares and hashes
# equal to its own value, so strings read from settings or JSON can be used
# interchangeably with members.
###########################################################

def enum_classes():
    found = []
    for name in dir(config):
        candidate = getattr(config, name)
        if inspect.isclass(candidate) and issubclass(candidate, EnumType) and candidate is not EnumType:
            found.append((name, candidate))
    return sorted(found)


ENUM_CLASSES = enum_classes()
ENUM_IDS = [name for name, _ in ENUM_CLASSES]


@pytest.fixture(scope = "module")
def sample_enum():
    return config.Platform


def test_enum_classes_were_discovered():
    assert len(ENUM_CLASSES) > 50, f"only found {len(ENUM_CLASSES)} enum classes"


###########################################################
# String interoperability
###########################################################

def test_a_member_equals_its_own_value(sample_enum):
    member = sample_enum.members()[0]
    assert member == member.val()


def test_a_member_does_not_equal_an_unrelated_string(sample_enum):
    assert sample_enum.members()[0] != "definitely not a platform"


def test_a_member_hashes_like_its_value(sample_enum):
    # Lets a dict keyed by members be looked up with the string form.
    member = sample_enum.members()[0]

    assert hash(member) == hash(member.val())
    assert {member: "payload"}[member.val()] == "payload"


def test_a_member_concatenates_with_strings(sample_enum):
    member = sample_enum.members()[0]

    assert member + "!" == member.val() + "!"
    assert ">" + member == ">" + member.val()


def test_members_order_by_value(sample_enum):
    members = sample_enum.members()[:2]
    first, second = members[0], members[1]

    assert (first < second) == (first.val() < second.val())


###########################################################
# Conversion
###########################################################

def test_a_member_converts_from_its_string(sample_enum):
    member = sample_enum.members()[0]
    assert sample_enum.from_enum(member.val()) is member


def test_a_member_converts_from_itself(sample_enum):
    member = sample_enum.members()[0]
    assert sample_enum.from_enum(member) is member


def test_converting_an_unknown_string_returns_none(sample_enum):
    assert sample_enum.from_enum("not a member") is None


def test_from_string_ignores_case(sample_enum):
    member = sample_enum.members()[0]
    assert sample_enum.from_string(member.val().lower()) is member


@pytest.mark.parametrize("value", [None, 1, ["a"]])
def test_from_string_of_a_non_string_is_none(sample_enum, value):
    assert sample_enum.from_string(value) is None


def test_convertibility_is_reported(sample_enum):
    member = sample_enum.members()[0]

    assert sample_enum.is_convertible(member) is True
    assert sample_enum.is_convertible(member.val()) is True
    assert sample_enum.is_convertible("not a member") is False


def test_membership_is_reported(sample_enum):
    member = sample_enum.members()[0]

    assert sample_enum.is_member(member) is True
    assert sample_enum.is_member(member.val()) is False


###########################################################
# Invariants across every enum
###########################################################

@pytest.mark.parametrize("name,enum_class", ENUM_CLASSES, ids = ENUM_IDS)
def test_no_duplicate_values(name, enum_class):
    # from_enum resolves the first match, making a later duplicate unreachable.
    values = [member.value for member in enum_class.members()]
    duplicates = sorted({value for value in values if values.count(value) > 1})

    assert not duplicates, f"{name} has duplicate values: {duplicates}"


@pytest.mark.parametrize("name,enum_class", ENUM_CLASSES, ids = ENUM_IDS)
def test_every_member_has_a_value_and_cvalue(name, enum_class):
    for member in enum_class.members():
        assert member.val() is not None, f"{name}.{member.name} has no value"
        assert member.cval() is not None, f"{name}.{member.name} has no cvalue"


@pytest.mark.parametrize("name,enum_class", ENUM_CLASSES, ids = ENUM_IDS)
def test_every_member_is_not_empty(name, enum_class):
    for member in enum_class.members():
        assert str(member.val()).strip(), f"{name}.{member.name} has an empty value"


@pytest.mark.parametrize("name,enum_class", ENUM_CLASSES, ids = ENUM_IDS)
def test_accessors_agree_on_length(name, enum_class):
    assert len(enum_class.members()) == len(enum_class.values())
    assert len(enum_class.members()) == len(enum_class.cvalues())


@pytest.mark.parametrize("name,enum_class", ENUM_CLASSES, ids = ENUM_IDS)
def test_every_member_round_trips_through_its_value(name, enum_class):
    # Values cross JSON and settings boundaries as plain strings.
    for member in enum_class.members():
        assert enum_class.from_enum(member.val()) is member, \
            f"{name}.{member.name} does not round-trip"


@pytest.mark.parametrize("name,enum_class", ENUM_CLASSES, ids = ENUM_IDS)
def test_every_member_is_in_its_own_class(name, enum_class):
    for member in enum_class.members():
        assert member.val() in enum_class


###########################################################
# Construction
###########################################################

def test_a_plain_member_uses_its_value_as_cvalue():
    assert Shade.DARK.cval() == "Dark"
    assert Shade.LIGHT.cval() == ".lt"


def test_a_non_string_member_uses_its_value_as_cvalue():
    assert Numbered.ONE.cval() == 1


def test_a_member_built_from_another_member_keeps_its_cvalue():
    assert Borrowed.VIDEO.val() == "Video"
    assert Borrowed.VIDEO.cval() == ".mp4"


def test_a_member_built_from_a_nested_pair_splits_it():
    assert Borrowed.PAIR.val() == "Pair"
    assert Borrowed.PAIR.cval() == ".pr"


###########################################################
# String behaviour
###########################################################

def test_str_lower_and_upper_use_the_value():
    assert str(Shade.LIGHT) == "Light"
    assert Shade.LIGHT.lower() == "light"
    assert Shade.LIGHT.upper() == "LIGHT"


def test_concatenating_a_non_string_is_unsupported():
    with pytest.raises(TypeError):
        Shade.DARK + 1
    with pytest.raises(TypeError):
        1 + Shade.DARK


def test_members_of_different_enums_with_one_value_are_equal():
    assert Shade.DARK == Other.DARK
    assert Shade.DARK != Other.MISSING


def test_a_member_never_equals_a_non_string():
    assert (Shade.DARK == 1) is False


def test_ordering_against_members_strings_and_others():
    assert Shade.DARK < Shade.LIGHT and Shade.DARK < "Light"
    assert Shade.DARK <= Shade.DARK and Shade.DARK <= "Dark"
    assert Shade.LIGHT > Shade.DARK and Shade.LIGHT > "Dark"
    assert Shade.LIGHT >= Shade.LIGHT and Shade.LIGHT >= "Light"
    for compare in (
        lambda: Shade.DARK < 1,
        lambda: Shade.DARK <= 1,
        lambda: Shade.DARK > 1,
        lambda: Shade.DARK >= 1):
        with pytest.raises(TypeError):
            compare()


###########################################################
# Class membership
###########################################################

def test_class_membership_accepts_members_values_and_foreign_members():
    assert Shade.DARK in Shade
    assert "Dark" in Shade
    assert Other.DARK in Shade
    assert RemoteActionType.PULL in RemoteActionSyncType


def test_class_membership_rejects_unknown_values():
    assert "Nope" not in Shade
    assert Other.MISSING not in Shade
    assert 1 not in Shade


###########################################################
# Conversion helpers
###########################################################

def test_from_enum_maps_a_foreign_member_by_value():
    assert Shade.from_enum(Other.DARK) is Shade.DARK
    assert Shade.from_enum(Other.MISSING) is None
    assert Shade.from_enum(1) is None


def test_from_string_of_an_unknown_name_is_none():
    assert Shade.from_string("nope") is None


@pytest.mark.parametrize("values,expected", [
    (None, None),
    ("", None),
    ([], None),
    ("dark, LIGHT", [Shade.DARK, Shade.LIGHT]),
    (["light", Shade.DARK, "nope", 1], [Shade.LIGHT, Shade.DARK]),
    (["nope"], None),
    (Shade.LIGHT, [Shade.LIGHT]),
    (1, None),
])
def test_from_list(values, expected):
    assert Shade.from_list(values) == expected


@pytest.mark.parametrize("value,expected", [
    (Shade.LIGHT, "Light"),
    ("light", "Light"),
    ("nope", None),
    (1, None),
])
def test_to_string(value, expected):
    assert Shade.to_string(value) == expected


def test_to_lower_and_upper_string():
    assert Shade.to_lower_string("LIGHT") == "light"
    assert Shade.to_upper_string(Shade.DARK) == "DARK"
    assert Shade.to_lower_string("nope") is None
    assert Shade.to_upper_string("nope") is None


###########################################################
# SetupParams
###########################################################

def test_setup_params_default_to_off():
    assert SetupParams().to_dict() == {
        "locker_type": None,
        "skip_autobackup": False,
        "verbose": False,
        "pretend_run": False,
        "exit_on_failure": False}


def test_setup_params_read_what_args_provide():
    class Args:
        locker_type = "Local"
        verbose = True

    params = SetupParams.from_args(Args())

    assert params.to_dict() == {
        "locker_type": "Local",
        "skip_autobackup": False,
        "verbose": True,
        "pretend_run": False,
        "exit_on_failure": False}
