from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import r2capa.cli as cli
from r2capa.model import Snapshot
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
