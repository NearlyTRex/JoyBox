# Imports
import pytest

# Local imports
from joybox import computer, config


###########################################################
# Setting up a computer game
#
# A store download is installed into a throwaway prefix, its discs mounted
# alongside, and the prefix's drive packed as the install image. Any step
# reporting failure has to stop the run before an incomplete image is packed.
###########################################################

class FakeSetupOptions:

    def __init__(self, root):
        self.root = root
        self.prefix_calls = []
        self.prefix_result = True

    def create_prefix(self, **kwargs):
        self.prefix_calls.append(kwargs)
        return self.prefix_result

    def get_prefix_dir(self):
        return self.root + "/prefix"

    def get_prefix_c_drive_real(self):
        return self.root + "/prefix/drive_c"

    def get_prefix_dos_c_drive(self):
        return self.root + "/prefix/dos_c"

    def get_prefix_dos_d_drive(self):
        return self.root + "/prefix/dos_d"

    def get_prefix_scumm_dir(self):
        return self.root + "/prefix/scumm"


class RecordingStep:

    def __init__(self, log, name):
        self.log = log
        self.name = name

    def run(self, **kwargs):
        self.log.append((self.name, kwargs))
        return True


class FakeGameInfo:

    def __init__(self, log, keep_discs = False):
        self.keep_discs = keep_discs
        self.preinstall = [RecordingStep(log, "pre")]
        self.install = [RecordingStep(log, "install")]
        self.postinstall = [RecordingStep(log, "post")]

    def get_name(self):
        return "Game"

    def get_category(self):
        return "Computer"

    def get_subcategory(self):
        return "Windows"

    def does_store_need_to_keep_discs(self):
        return self.keep_discs

    def get_main_store_install_dir(self):
        return "/store/Game"

    def get_store_setup_preinstall_steps(self):
        return self.preinstall

    def get_store_setup_install_programs(self):
        return self.install

    def get_store_setup_postinstall_steps(self):
        return self.postinstall


class SetupWorld:

    def __init__(self, monkeypatch, tmp_path):
        self.calls = []
        self.results = {}
        self.discs = []
        self.setup_dir = str(tmp_path / "setup")
        self.options = FakeSetupOptions(str(tmp_path))
        self.public = tmp_path / "public"
        self.order = []
        self.game = FakeGameInfo(self.order)
        monkeypatch.setattr(
            computer.environment, "get_cache_gaming_setup_dir",
            lambda category, subcategory, name: self.setup_dir)
        monkeypatch.setattr(computer.command, "create_command_options", lambda: self.options)
        monkeypatch.setattr(computer.platform_info, "is_wine_platform", lambda: True)
        monkeypatch.setattr(computer.platform_info, "is_sandboxie_platform", lambda: False)
        monkeypatch.setattr(
            computer.paths, "build_file_list_by_extensions",
            lambda root, extensions: list(self.discs))
        monkeypatch.setattr(
            computer.sandbox, "build_token_map",
            lambda **kwargs: self.record("build_token_map", kwargs) or {"$TOKEN": "x"})
        monkeypatch.setattr(
            computer.sandbox, "get_public_profile_path", lambda options: str(self.public))
        for owner, name in [
            (computer.fileops, "make_directory"),
            (computer.fileops, "copy_contents"),
            (computer.fileops, "copy_file_or_directory"),
            (computer.fileops, "remove_directory"),
            (computer.sandbox, "mount_disc_image"),
            (computer.sandbox, "unmount_disc_image"),
            (computer.install, "pack_install_image"),
        ]:
            monkeypatch.setattr(owner, name, self.recorder(name))

    def record(self, name, kwargs):
        self.calls.append((name, kwargs))
        self.order.append((name, kwargs))

    def recorder(self, name):
        def call(**kwargs):
            self.record(name, kwargs)
            result = self.results.get(name, True)
            return result(kwargs) if callable(result) else result
        return call

    def named(self, name):
        return [kwargs for called, kwargs in self.calls if called == name]

    def run(self, **kwargs):
        return computer.setup_computer_game(
            self.game, "/downloads/Game/setup.exe", "/out/Game.img", **kwargs)


@pytest.fixture
def world(monkeypatch, tmp_path):
    return SetupWorld(monkeypatch, tmp_path)


def test_a_setup_packs_the_prefix_drive(world):
    assert world.run() is True
    packed = world.named("pack_install_image")

    assert packed == [{
        "input_dir": world.options.get_prefix_c_drive_real(),
        "output_image": "/out/Game.img",
        "verbose": False, "pretend_run": False, "exit_on_failure": False}]


def test_a_setup_uses_a_setup_prefix(world):
    world.run()
    created = world.options.prefix_calls[0]

    assert created["prefix_name"] == config.PrefixType.SETUP
    assert (created["is_wine_prefix"], created["is_sandboxie_prefix"]) == (True, False)


def test_a_setup_copies_the_download_beside_it(world):
    world.run()
    copied = world.named("copy_contents")[0]

    assert copied["src"] == "/downloads/Game"
    assert copied["dest"] == world.setup_dir
    assert copied["skip_existing"] is True


def test_a_setup_makes_the_emulator_drives(world):
    world.run()
    made = [kwargs["src"] for kwargs in world.named("make_directory")]

    for path in [world.setup_dir, world.options.get_prefix_dos_c_drive(),
                 world.options.get_prefix_dos_d_drive(), world.options.get_prefix_scumm_dir()]:
        assert path in made


def test_the_steps_run_in_order_with_the_token_map(world):
    world.run()
    steps = [(name, kwargs) for name, kwargs in world.order if name in ("pre", "install", "post")]

    assert [name for name, _ in steps] == ["pre", "install", "post"]
    assert all(kwargs["token_map"] == {"$TOKEN": "x"} for _, kwargs in steps)
    assert steps[1][1]["options"] is world.options


def test_the_steps_run_before_packing(world):
    world.run()
    names = [name for name, _ in world.order]

    assert names.index("post") < names.index("pack_install_image")


def test_the_token_map_points_at_the_setup(world):
    world.discs = ["/setup/disc1.chd"]
    world.game.keep_discs = True
    world.run()
    built = world.named("build_token_map")[0]

    assert built["store_install_dir"] == "/store/Game"
    assert built["setup_base_dir"] == world.setup_dir
    assert built["hdd_base_dir"] == world.options.get_prefix_c_drive_real()
    assert built["disc_files"] == ["/setup/disc1.chd"]
    assert built["use_drive_letters"] is True


def test_discs_are_mounted_and_unmounted(world):
    world.discs = ["/setup/disc1.chd", "/setup/disc2.chd"]

    assert world.run() is True
    mounted = [kwargs["src"] for kwargs in world.named("mount_disc_image")]
    unmounted = [kwargs["src"] for kwargs in world.named("unmount_disc_image")]
    assert mounted == unmounted == world.discs
    assert world.named("mount_disc_image")[0]["mount_dir"].endswith("/disc1")
    assert world.named("copy_file_or_directory") == []


def test_discs_are_kept_when_the_store_needs_them(world):
    world.discs = ["/setup/disc1.chd"]
    world.game.keep_discs = True

    assert world.run() is True
    kept = world.named("copy_file_or_directory")[0]
    assert kept["src"] == "/setup/disc1.chd"
    assert kept["dest"] == world.options.get_prefix_dos_d_drive()


def test_public_files_are_carried_into_the_image(world):
    world.public.mkdir()
    world.run()
    public = world.options.get_prefix_c_drive_real() + "/Public"

    assert public in [kwargs["src"] for kwargs in world.named("make_directory")]
    assert {"src": str(world.public), "dest": public}.items() <= \
        world.named("copy_contents")[1].items()


def test_no_public_profile_copies_nothing_more(world):
    world.run()

    assert len(world.named("copy_contents")) == 1


def test_the_setup_is_cleaned_up(world):
    world.run()
    removed = [kwargs["src"] for kwargs in world.named("remove_directory")]

    assert removed == [world.options.get_prefix_dir(), world.setup_dir]


def test_setup_files_can_be_kept(world):
    world.run(keep_setup_files = True)
    removed = [kwargs["src"] for kwargs in world.named("remove_directory")]

    assert removed == [world.options.get_prefix_dir()]


def test_the_run_settings_reach_every_step(world):
    world.run(verbose = True, pretend_run = True, exit_on_failure = True)

    for name, kwargs in world.order:
        if "pretend_run" in kwargs:
            assert (kwargs["verbose"], kwargs["pretend_run"], kwargs["exit_on_failure"]) == \
                (True, True, True), name


def test_a_setup_directory_that_cannot_be_made_stops_the_setup(world):
    world.results["make_directory"] = lambda kwargs: kwargs["src"] != world.setup_dir

    assert world.run() is False
    assert world.options.prefix_calls == []


def test_a_prefix_that_cannot_be_made_stops_the_setup(world):
    world.options.prefix_result = False

    assert world.run() is False
    assert world.named("copy_contents") == []


def test_a_download_that_cannot_be_copied_stops_the_setup(world):
    world.results["copy_contents"] = False

    assert world.run() is False
    assert world.order[-1][0] == "copy_contents"


@pytest.mark.parametrize("failing,keep_discs", [
    ("mount_disc_image", False),
    ("copy_file_or_directory", True),
    ("pack_install_image", False),
    ("unmount_disc_image", False),
])
def test_a_failed_step_stops_the_setup(world, failing, keep_discs):
    world.discs = ["/setup/disc1.chd"]
    world.game.keep_discs = keep_discs
    world.results[failing] = False

    assert world.run() is False
    assert world.named("remove_directory") == []
