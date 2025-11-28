# Imports
import os, os.path
import sys
import argparse

# Local imports
import config
import system

# Enum parser
def ParseEnumValue(enum_type, enum_value):
    if isinstance(enum_value, enum_type):
        return enum_value
    else:
        try:
            return enum_type.from_string(enum_value)
        except Exception as e:
            return None

# Enum argparse action
class EnumArgparseAction(argparse.Action):
    def __init__(self, option_strings, dest, type, **kwargs):
        self.enum_type = type
        super().__init__(option_strings, dest, type=str, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        enum_value = ParseEnumValue(self.enum_type, values)
        setattr(namespace, self.dest, enum_value)

# Argument parser
class ArgumentParser:
    def __init__(self, description):
        self.parser = argparse.ArgumentParser(
            description = description,
            formatter_class = argparse.ArgumentDefaultsHelpFormatter)

    #################################################

    # Parse known arguments
    def parse_known_args(self):
        return self.parser.parse_known_args()

    # Check if the given name is a known argument
    def is_known_argument(self, name):
        return any(action.dest == name for action in self.parser._actions)

    #################################################

    # Get path
    def get_path(self, argname):
        if not self.is_known_argument(argname):
            return None
        args, unknown = self.parse_known_args()
        args_dict = vars(args)
        if argname not in args_dict.keys():
            return None
        if not args_dict[argname]:
            return None
        virt_path = args_dict[argname]
        real_path = os.path.realpath(virt_path)
        return real_path

    # Get checked path
    def get_checked_path(self, argname):
        path = self.get_path(argname)
        if not system.DoesPathExist(path):
            system.LogError("Path '%s' does not exist" % path, quit_program = True)
        return path

    #################################################

    # Add string argument
    def add_string_argument(
        self,
        args,
        default = None,
        required = False,
        description = None):
        arg_names = args if isinstance(args, tuple) else (args,)
        is_positional = not arg_names[0].startswith("-")
        if is_positional:
            self.parser.add_argument(
                *arg_names,
                default = default,
                nargs = "?" if default is not None else None,
                type = str,
                help = description)
        else:
            self.parser.add_argument(
                *arg_names,
                default = default,
                required = required,
                type = str,
                help = description)

    # Add boolean argument
    def add_boolean_argument(
        self,
        args,
        description = None):
        self.parser.add_argument(
            *args if isinstance(args, tuple) else (args,),
            action = "store_true",
            help = description)

    # Add enum argument
    def add_enum_argument(
        self,
        args,
        arg_type = None,
        default = None,
        description = None,
        allow_multiple = False):
        enum_values = arg_type.values()
        quoted_enum_values = [f"'{value}'" for value in enum_values]
        if allow_multiple:
            if default is not None:
                if not isinstance(default, list):
                    default = [default]
            else:
                default = []
            self.parser.add_argument(
                *args if isinstance(args, tuple) else (args,),
                default = default,
                type = ParseEnumValue,
                choices = arg_type.values(),
                help = f"{description}.\nAllowed values are [{', '.join(quoted_enum_values)}]",
                nargs = "+",
                metavar = "")
        else:
            self.parser.add_argument(
                *args if isinstance(args, tuple) else (args,),
                default = default,
                type = arg_type,
                action = EnumArgparseAction,
                choices = arg_type.values(),
                help = f"{description}.\nAllowed values are [{', '.join(quoted_enum_values)}]",
                metavar = "")

    # Add enum list argument
    def add_enum_list_argument(
        self,
        args,
        arg_type = None,
        description = None):
        enum_values = arg_type.values()
        quoted_enum_values = [f"'{value}'" for value in enum_values]
        self.parser.add_argument(
            *args if isinstance(args, tuple) else (args,),
            default = None,
            type = str,
            help = f"{description} (comma delimited).\nAllowed values are [{', '.join(quoted_enum_values)}]")

    #################################################

    # Add input path argument
    def add_input_path_argument(self, args = ("-i", "--input_path"), default = None, required = False, description = "Input path"):
        self.add_string_argument(
            args = args,
            default = default,
            required = required,
            description = description)

    # Add output path argument
    def add_output_path_argument(self, args = ("-o", "--output_path"), default = None, required = False, description = "Output path"):
        self.add_string_argument(
            args = args,
            default = default,
            required = required,
            description = description)

    # Get input path
    def get_input_path(self):
        return self.get_checked_path("input_path")

    # Get output path
    def get_output_path(self):
        return self.get_checked_path("output_path")

    #################################################

    # Add game supercategory argument
    def add_game_supercategory_argument(self, args = ("-u", "--game_supercategory"), description = "Game supercategory type"):
        self.add_enum_argument(
            args = args,
            arg_type = config.Supercategory,
            default = config.Supercategory.ROMS,
            description = description)

    # Add game category argument
    def add_game_category_argument(self, args = ("-c", "--game_category"), description = "Game category type"):
        self.add_enum_argument(
            args = args,
            arg_type = config.Category,
            description = description)

    # Add game subcategory argument
    def add_game_subcategory_argument(self, args = ("-s", "--game_subcategory"), description = "Game subcategory type"):
        self.add_enum_argument(
            args = args,
            arg_type = config.Subcategory,
            description = description)

    # Add game name argument
    def add_game_name_argument(self, args = ("-n", "--game_name"), description = "Game name"):
        self.add_string_argument(
            args = args,
            description = description)

    # Add game offset argument
    def add_game_offset_argument(self, args = ("-g", "--game_offset"), description = "Game offset"):
        self.add_string_argument(
            args = args,
            description = description)

    # Get selected supercategories
    def get_selected_supercategories(self, argname = "game_supercategory"):
        args, unknown = self.parse_known_args()
        supercategories = []
        supercategory_arg = getattr(args, argname, None)
        if supercategory_arg:
            supercategories = [supercategory_arg]
        else:
            supercategories = config.Supercategory.members()
        return supercategories

    # Get selected categories
    def get_selected_categories(self, argname = "game_category"):
        args, unknown = self.parse_known_args()
        categories = []
        category_arg = getattr(args, argname, None)
        if category_arg:
            categories = [category_arg]
        else:
            categories = config.Category.members()
        return categories

    # Get selected subcategories
    def get_selected_subcategories(
        self,
        category_argname = "game_category",
        subcategory_argname = "game_subcategory"):
        args, unknown = self.parse_known_args()
        subcategory_map = {}
        for category in self.get_selected_categories(argname = category_argname):
            subcategories = []
            subcategory_arg = getattr(args, subcategory_argname, None)
            if subcategory_arg:
                subcategories = [subcategory_arg]
            else:
                subcategories = config.subcategory_map.get(category, [])
            subcategory_map[category] = subcategories
        return subcategory_map

    #################################################

    # Add common arguments
    def add_common_arguments(self):
        self.add_boolean_argument(
            args = ("-v", "--verbose"),
            description = "Enable verbose mode")
        self.add_boolean_argument(
            args = ("-p", "--pretend_run"),
            description = "Do a pretend run with no permanent changes")
        self.add_boolean_argument(
            args = ("-x", "--exit_on_failure"),
            description = "Enable exit on failure mode")

    #################################################
