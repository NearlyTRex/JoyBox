# Imports
import inspect

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.config.types import EnumType


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
