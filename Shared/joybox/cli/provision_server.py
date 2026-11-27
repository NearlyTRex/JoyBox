# Imports
from joybox import arguments
from joybox.bootstrap import provision
from joybox import logger
from joybox import setup
from joybox import system

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "provision_server")
    parser.add_integer_argument(args = ("-s", "--server"), description = "Index of the server entry under `[UserData.Servers]`")
    parser.add_string_list_argument(args = ("-c", "--components"), several_per_flag = True, description = "Components to deploy; every remote component when omitted")
    parser.add_string_list_argument(args = ("--stages"), several_per_flag = True, description = "Stages to run, from `vm`, `login`, `day0`, `deploy`, `sshd` and `verify`; all of them when omitted")
    parser.add_common_arguments()
    return parser

# Check the inputs, plan the stages for a server entry, then run them over SSH to deploy, harden and verify it
def main():

    # Parse arguments
    parser = build_parser()
    args, unknown = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Check the inputs before touching anything; a dropped word could silently
    # skip a stage or a component
    server, stages = provision.check_provision_inputs(args.server, args.stages, unknown)

    # Plan, then run unless pretending
    provision.provision_server(
        server_index = args.server,
        server = server,
        stages = stages,
        components = args.components,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
