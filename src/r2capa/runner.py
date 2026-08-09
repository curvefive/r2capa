"""Run capa with the radare2 extractor and render native capa results."""

from __future__ import annotations

import inspect
import io
import os
import tempfile
from contextlib import redirect_stdout
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import cast

import capa.loader
import capa.render.default
import capa.render.result_document as rdoc
import capa.render.verbose
import capa.render.vverbose
import capa.rules
import capa.rules.cache
from capa.capabilities.common import Capabilities, find_capabilities
from capa.rules import RuleSet

from r2capa.extractor import Radare2FeatureExtractor


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    rules: RuleSet
    capabilities: Capabilities
    metadata: rdoc.Metadata
    document: rdoc.ResultDocument


@cache
def _cache_directory() -> Path:
    configured = os.environ.get("R2CAPA_CACHE")
    preferred = Path(configured) if configured else Path.home() / ".cache" / "r2capa"
    try:
        preferred.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=preferred, prefix=".write-test-"):
            pass
        return preferred
    except OSError:
        return Path(tempfile.mkdtemp(prefix="r2capa-cache-"))


def load_rules(paths: list[Path]) -> RuleSet:
    if not paths:
        raise ValueError("at least one capa rules path is required")
    return capa.rules.get_rules(paths, cache_dir=_cache_directory(), enable_cache=True)


def analyze(
    extractor: Radare2FeatureExtractor,
    rule_paths: list[Path],
    *,
    argv: list[str] | None = None,
) -> AnalysisResult:
    rules = load_rules(rule_paths)
    capabilities = find_capabilities(rules, extractor, disable_progress=True)
    input_path = Path(extractor.snapshot.path)
    metadata_arguments: list[object] = [
        argv or [],
        input_path,
        extractor.snapshot.format,
    ]
    if "os_" in inspect.signature(capa.loader.collect_metadata).parameters:
        metadata_arguments.append(extractor.snapshot.os)
    metadata_arguments.extend((rule_paths, extractor, capabilities))
    metadata = capa.loader.collect_metadata(*metadata_arguments)
    layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)
    if isinstance(metadata, rdoc.StaticMetadata):
        assert isinstance(layout, rdoc.StaticLayout)
        metadata.analysis.layout = layout
    document = rdoc.ResultDocument.from_capa(metadata, rules, capabilities.matches)
    return AnalysisResult(rules, capabilities, metadata, document)


def render(result: AnalysisResult, verbosity: int) -> str:
    renderer = capa.render.default.render
    if verbosity >= 2:
        renderer = capa.render.vverbose.render
    elif verbosity == 1:
        renderer = capa.render.verbose.render

    # capa 9.4's default renderer writes to stdout and returns an empty string;
    # later renderers return their output. Support both without duplicate output.
    captured = io.StringIO()
    with redirect_stdout(captured):
        rendered = cast(
            str,
            renderer(result.metadata, result.rules, result.capabilities.matches),
        )
    return rendered or captured.getvalue()
