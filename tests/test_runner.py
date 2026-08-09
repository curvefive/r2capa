from __future__ import annotations

from pathlib import Path

from r2capa.extractor import Radare2FeatureExtractor
from r2capa.model import Snapshot
from r2capa.runner import analyze, render

RULES = Path(__file__).parent / "data" / "regression-rule.yml"


def test_end_to_end_rule_match(snapshot: Snapshot) -> None:
    result = analyze(Radare2FeatureExtractor(snapshot), [RULES])

    assert "r2capa regression capability" in result.document.rules
    assert result.document.meta.analysis.extractor == "Radare2FeatureExtractor"
    assert "r2capa regression capability" in render(result, verbosity=0)
