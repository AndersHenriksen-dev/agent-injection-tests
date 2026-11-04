"""Code and config stay matched: each config file has its Python file, and a mistake in one fails loudly."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

import injectiontests
from injectiontests.lib.shared.models import Strict
from injectiontests.lib.shared.settings import CONFIG_DIR, config_path, read_config

PACKAGE = Path(injectiontests.__file__).parent
LIB = PACKAGE / "lib"

# A Python file that reads a folder of config files instead of one.
FOLDERS_OF_CONFIG = {"fund_agent/cases"}


def _python_files() -> list[Path]:
    return [file for file in LIB.rglob("*.py") if file.name != "__init__.py"]


def _module_name(file: Path) -> str:
    return ".".join(("injectiontests", *file.relative_to(PACKAGE).with_suffix("").parts))


class TestMirror:
    def test_the_folders_match(self) -> None:
        code = {folder.name for folder in LIB.iterdir() if folder.is_dir() and folder.name != "__pycache__"}
        config = {folder.name for folder in CONFIG_DIR.iterdir() if folder.is_dir()}
        assert code == config

    @pytest.mark.parametrize("file", sorted(CONFIG_DIR.rglob("*.yaml")), ids=lambda file: file.stem)
    def test_every_config_file_has_its_python_file(self, file: Path) -> None:
        relative = file.relative_to(CONFIG_DIR).with_suffix("")
        owner = relative.parent if relative.parent.as_posix() in FOLDERS_OF_CONFIG else relative
        assert (LIB / owner).with_suffix(".py").is_file(), f"{file} belongs to no Python file"

    @pytest.mark.parametrize("file", _python_files(), ids=lambda file: file.stem)
    def test_a_python_file_that_reads_config_has_its_file(self, file: Path) -> None:
        reads_config = "config_for(__name__" in file.read_text(encoding="utf-8")
        assert not reads_config or config_path(_module_name(file)).is_file()

    def test_the_path_follows_the_module(self) -> None:
        assert config_path("injectiontests.lib.shared.claims") == CONFIG_DIR / "shared" / "claims.yaml"


class TestFolders:
    def test_the_entry_point_is_the_only_code_beside_the_folders(self) -> None:
        assert {file.name for file in PACKAGE.glob("*.py")} == {"__init__.py", "cli.py"}

    def test_each_side_of_the_package_has_its_commands_file(self) -> None:
        assert (LIB / "existing_agents" / "commands.py").is_file()
        assert (LIB / "fund_agent" / "commands.py").is_file()

    @pytest.mark.parametrize(
        ("folder", "must_not_import"),
        [
            ("existing_agents", "fund_agent"),
            ("fund_agent", "existing_agents"),
            ("shared", "existing_agents"),
            ("shared", "fund_agent"),
        ],
    )
    def test_the_folders_stay_apart(self, folder: str, must_not_import: str) -> None:
        for file in (LIB / folder).glob("*.py"):
            for node in ast.walk(ast.parse(file.read_text(encoding="utf-8"))):
                if isinstance(node, ast.ImportFrom):
                    assert must_not_import not in (node.module or ""), f"{file.name} imports {node.module}"


class _Shape(Strict):
    number: int


class TestReadingConfig:
    def test_a_good_file_is_read(self, tmp_path: Path) -> None:
        path = tmp_path / "good.yaml"
        path.write_text("number: 3\n", encoding="utf-8")
        assert read_config(path, _Shape).number == 3

    @pytest.mark.parametrize("text", ["numbr: 3\n", "number: three\n", "{}\n"], ids=["typo", "wrong-type", "missing"])
    def test_a_mistake_fails_loudly(self, tmp_path: Path, text: str) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ValidationError):
            read_config(path, _Shape)


def test_the_public_names_are_importable() -> None:
    assert callable(injectiontests.audit)
    assert callable(injectiontests.load_target)
    assert callable(injectiontests.scan)
