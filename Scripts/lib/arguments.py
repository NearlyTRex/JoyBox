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
            system.LogErrorAndQuit("Path '%s' does not exist" % path)
        return path

    #################################################

    # Add string argument
    def add_string_argument(
        self,
        args,
        default = None,
        description = None):
        self.parser.add_argument(
            *args if isinstance(args, tuple) else (args,),
            default = default,
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
                default = [val.value if isinstance(val, arg_type) else val for val in default]
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
            if isinstance(default, arg_type):
                default = default.value
            self.parser.add_argument(
                *args if isinstance(args, tuple) else (args,),
                default = default,
                type = arg_type,
                action = EnumArgparseAction,
                choices = arg_type.values(),
                help = f"{description}.\nAllowed values are [{', '.join(quoted_enum_values)}]",
                metavar = "")

    #################################################

    # Add input path argument
    def add_input_path_argument(self, args = ("-i", "--input_path"), default = None, description = "Input path"):
        self.add_string_argument(
            args = args,
            description = description)

    # Add output path argument
    def add_output_path_argument(self, args = ("-o", "--output_path"), default = None, description = "Output path"):
        self.add_string_argument(
            args = args,
            description = description)

    # Get input path
    def get_input_path(self):
        return self.get_checked_path("input_path")

    # Get output path
    def get_output_path(self):
        return self.get_checked_path("output_path")

    #################################################

    # Add passphrase type argument
    def add_passphrase_type_argument(
        self,
        args = ("-t", "--passphrase_type"),
        description = "Passphrase type",
        allow_multiple = False):
        self.add_enum_argument(
            args = args,
            arg_type = config.PassphraseType,
            description = description,
            allow_multiple = allow_multiple)

    # Add source type argument
    def add_source_type_argument(
        self,
        args = ("-l", "--source_type"),
        default = config.SourceType.REMOTE,
        description = "Source type",
        allow_multiple = False):
        self.add_enum_argument(args = args,
            arg_type = config.SourceType,
            default = default,
            description = description,
            allow_multiple = allow_multiple)

    # Add asset type argument
    def add_asset_type_argument(
        self,
        args = ("-e", "--asset_type"),
        default = config.AssetType.BOXFRONT,
        description = "Asset type",
        allow_multiple = False):
        self.add_enum_argument(
            args = args,
            arg_type = config.AssetType,
            default = default,
            description = description,
            allow_multiple = allow_multiple)

    # Add archive type argument
    def add_archive_type_argument(
        self,
        args = ("-a", "--archive_type"),
        default = config.ArchiveType.ZIP,
        description = "Archive type",
        allow_multiple = False):
        self.add_enum_argument(
            args = args,
            arg_type = config.ArchiveType,
            default = default,
            description = description,
            allow_multiple = allow_multiple)

    # Add disc image type argument
    def add_disc_image_type_argument(
        self,
        args = ("-t", "--disc_image_type"),
        default = config.DiscImageType.ISO,
        description = "Disc image type",
        allow_multiple = False):
        self.add_enum_argument(
            args = args,
            arg_type = config.DiscImageType,
            default = default,
            description = description,
            allow_multiple = allow_multiple)

    # Add generation mode argument
    def add_generation_mode_argument(
        self,
        args = ("-m", "--generation_mode"),
        default = config.GenerationModeType.STANDARD,
        description = "Generation mode",
        allow_multiple = False):
        self.add_enum_argument(
            args = args,
            arg_type = config.GenerationModeType,
            default = default,
            description = description,
            allow_multiple = allow_multiple)

    #################################################

    # Add game category arguments
    def add_game_category_arguments(
        self,
        supercategory_args = ("-u", "--game_supercategory"),
        category_args = ("-c", "--game_category"),
        subcategory_args = ("-s", "--game_subcategory"),
        supercategory_description = "Game supercategory type",
        category_description = "Game category type",
        subcategory_description = "Game subcategory type"):
        self.add_enum_argument(
            args = supercategory_args,
            arg_type = config.Supercategory,
            default = config.Supercategory.ROMS,
            description = supercategory_description)
        self.add_enum_argument(
            args = category_args,
            arg_type = config.Category,
            description = category_description)
        self.add_enum_argument(
            args = subcategory_args,
            arg_type = config.Subcategory,
            description = subcategory_description)

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
