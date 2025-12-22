# Imports
import os

###########################################################
# Assertion and validation utilities
###########################################################

# Assert that condition is true
def assert_condition(condition, description):
    assert condition, "Condition failed: %s" % description

# Assert that variable is not none
def assert_is_not_none(var_value, var_name):
    assert var_value is not None, "%s should not be None" % var_name

# Assert that variable is string
def assert_is_string(var_value, var_name):
    assert type(var_value) == str, "%s should be a string" % var_name

# Assert that variable is non-empty string
def assert_is_non_empty_string(var_value, var_name):
    assert (type(var_value) == str) and (len(var_value) > 0), "%s should be a non-empty string" % var_name

# Assert that variable is non-empty string of specific length
def assert_is_string_of_specific_length(var_value, var_len, var_name):
    assert (type(var_value) == str) and (len(var_value) == var_len), "%s should be a string of size %s" % (var_name, var_len)

# Assert that variable is valid path
def assert_is_valid_path(var_value, var_name):
    import paths
    assert paths.is_path_valid(var_value), "%s should be a valid path" % var_name

# Assert that variable is integer
def assert_is_int(var_value, var_name):
    assert type(var_value) == int, "%s should be an integer" % var_name

# Assert that variable is castable to integer
def assert_is_castable_to_int(var_value, var_name):
    test_value = None
    try:
        test_value = int(var_value)
    except:
        pass
    assert type(test_value) == int, "%s should be castable to an integer" % var_name

# Assert that variable is boolean
def assert_is_bool(var_value, var_name):
    assert type(var_value) == bool, "%s should be a boolean" % var_name

# Assert that variable is castable to boolean
def assert_is_castable_to_bool(var_value, var_name):
    test_value = None
    try:
        if var_value == "True":
            test_value = True
        elif var_value == "False":
            test_value = False
    except:
        pass
    assert type(test_value) == bool, "%s should be castable to boolean" % var_name

# Assert that variable is list
def assert_is_list(var_value, var_name):
    assert type(var_value) == list, "%s should be an list" % var_name

# Assert that variable is dictionary
def assert_is_dictionary(var_value, var_name):
    assert type(var_value) == dict, "%s should be an dict" % var_name

# Assert that variable is dictionary and key exists
def assert_dictionary_has_key(var_value, var_key):
    assert type(var_value) == dict and var_key in var_value, "Key '%s' not found in dictionary" % var_key

# Assert that variable is callable
def assert_callable(var_value, var_name):
    assert callable(var_value), "%s should be a callable" % var_name

# Assert that path exists
def assert_path_exists(var_value, var_name):
    assert os.path.exists(var_value), "%s should be a path that exists" % var_name
