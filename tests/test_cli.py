from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path

import pytest

import r2capa.cli as cli
from r2capa.model import BasicBlock, Snapshot
from r2capa.snapshot import AnalysisRequiredError

from .conftest import FakeR2

RULES = Path(__file__).parent / "data" / "regression-rule.yml"


def _arguments(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "file": None,
        "rules": [],
        "analyze": False,
        "function": None,
        "json": False,
        "verbose": 0,
        "features": False,
        "r2_script": False,
        "snapshot": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _use_snapshot(monkeypatch: pytest.MonkeyPatch, snapshot: Snapshot) -> None:
    monkeypatch.setattr(cli.SnapshotBuilder, "build", lambda _self: snapshot)


def test_snapshot_and_feature_output(
    snapshot: Snapshot, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_snapshot(monkeypatch, snapshot)
    r2 = FakeR2({})

    assert cli.run(_arguments(snapshot=True, analyze=True), r2) == 0
    serialized = json.loads(capsys.readouterr().out)
    assert serialized["base_address"] == 0x400000
    assert "aaa" in r2.commands

    assert cli.run(_arguments(features=True, function=0x401000), r2) == 0
    features = json.loads(capsys.readouterr().out)
    assert any(record["feature"] == "api(kernel32.CreateFileW)" for record in features)


def test_missing_rules_is_actionable(
    snapshot: Snapshot, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _use_snapshot(monkeypatch, snapshot)
    monkeypatch.delenv("R2CAPA_RULES", raising=False)
    monkeypatch.setattr(Path, "home", lambda: Path("/definitely/missing"))

    assert cli.run(_arguments(), FakeR2({})) == 2
    assert "R2CAPA_RULES" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ({"json": True}, '"r2capa regression capability"'),
        ({"r2_script": True}, "f capa.r2capa_regression_capability.0 @ 0x401000"),
        ({"verbose": 1}, "r2capa regression capability"),
    ],
)
def test_match_output_modes(
    mode: dict[str, object],
    expected: str,
    snapshot: Snapshot,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_snapshot(monkeypatch, snapshot)

    assert cli.run(_arguments(rules=[RULES], **mode), FakeR2({})) == 0
    assert expected in capsys.readouterr().out


def test_rule_path_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("R2CAPA_RULES", "/tmp/rules")

    assert cli._rule_paths(_arguments()) == [Path("/tmp/rules")]


def test_main_reports_analysis_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "_open_r2", lambda _path: FakeR2({}))

    def fail(_self: object) -> Snapshot:
        raise AnalysisRequiredError("run aaa")

    monkeypatch.setattr(cli.SnapshotBuilder, "build", fail)

    assert cli.main([]) == 2
    assert "run aaa" in capsys.readouterr().err


@pytest.mark.parametrize("address", [0x401000, 0x40100C, 0x401020])
def test_function_address_resolves_containing_function(
    address: int,
    snapshot: Snapshot,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_snapshot(monkeypatch, snapshot)

    assert cli.run(_arguments(function=address, rules=[RULES], json=True), FakeR2({})) == 0
    assert "r2capa regression capability" in capsys.readouterr().out


def test_function_address_in_detached_block(
    snapshot: Snapshot, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    function = snapshot.functions[0]
    detached = BasicBlock(0x500000, 0x10)
    function = replace(function, blocks=(*function.blocks, detached))
    _use_snapshot(monkeypatch, replace(snapshot, functions=(function,)))

    assert cli.run(_arguments(function=0x500005, features=True), FakeR2({})) == 0
    assert "api(kernel32.CreateFileW)" in capsys.readouterr().out


@pytest.mark.parametrize("address", [0xDEADBEEF, 0x401030])
def test_unknown_function_address_is_an_error(
    address: int,
    snapshot: Snapshot,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _use_snapshot(monkeypatch, snapshot)

    assert cli.run(_arguments(function=address, features=True), FakeR2({})) == 2
    output = capsys.readouterr()
    assert "no function contains" in output.err
    assert output.out == ""


def test_function_lookup_handles_overlaps_and_gaps(snapshot: Snapshot) -> None:
    function = snapshot.functions[0]
    outer = replace(function, size=0x100, blocks=(BasicBlock(0x401000, 0x10),))
    inner = replace(function, address=0x401008, size=4, blocks=())
    snapshot = replace(snapshot, functions=(outer, inner))

    assert snapshot.function_at(0x401008) is inner
    assert snapshot.function_at(0x401010) is None
    assert snapshot.function_at(0x401080) is None

    snapshot = replace(snapshot, functions=(inner,))
    assert snapshot.function_at(0x401009) is inner
    assert snapshot.function_at(0x40100C) is None
