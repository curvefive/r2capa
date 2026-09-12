"""Command line and r2pipe entrypoint for r2capa."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from capa.features.address import AbsoluteVirtualAddress

from r2capa.extractor import Radare2FeatureExtractor
from r2capa.runner import AnalysisResult, analyze, render
from r2capa.snapshot import AnalysisRequiredError, R2Client, SnapshotBuilder


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="r2capa", description="run capa on a radare2 analysis")
    parser.add_argument("--file", type=Path, help="open a file in a new r2 session")
    parser.add_argument("-r", "--rules", action="append", type=Path, default=[])
    parser.add_argument("-A", "--analyze", action="store_true", help="run 'aaa' before capa")
    parser.add_argument(
        "-f",
        "--function",
        type=lambda value: int(value, 0),
        help="analyze the function containing this address",
    )
    parser.add_argument("-j", "--json", action="store_true", help="emit capa ResultDocument JSON")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument(
        "--features", action="store_true", help="list extracted features, not matches"
    )
    parser.add_argument(
        "--r2-script", action="store_true", help="emit flags as an r2 command script"
    )
    parser.add_argument("--snapshot", action="store_true", help="emit the normalized r2 snapshot")
    return parser


def _rule_paths(arguments: argparse.Namespace) -> list[Path]:
    if arguments.rules:
        return cast(list[Path], arguments.rules)
    configured = os.environ.get("R2CAPA_RULES")
    if configured:
        return [Path(configured)]
    default = Path.home() / ".local" / "share" / "r2capa" / "rules"
    return [default] if default.exists() else []


def _open_r2(path: Path | None) -> R2Client:
    import r2pipe

    if path is None:
        return cast(R2Client, r2pipe.open())
    return cast(R2Client, r2pipe.open(str(path)))


def _address_text(address: Any) -> str:
    if isinstance(address, AbsoluteVirtualAddress):
        return f"0x{int(address):x}"
    return str(address)


def _feature_records(extractor: Radare2FeatureExtractor) -> Iterable[dict[str, str]]:
    for feature, address in extractor.extract_global_features():
        yield {"scope": "global", "address": _address_text(address), "feature": str(feature)}
    for feature, address in extractor.extract_file_features():
        yield {"scope": "file", "address": _address_text(address), "feature": str(feature)}
    for function in extractor.get_functions():
        for feature, address in extractor.extract_function_features(function):
            yield {"scope": "function", "address": _address_text(address), "feature": str(feature)}
        for block in extractor.get_basic_blocks(function):
            for feature, address in extractor.extract_basic_block_features(function, block):
                yield {
                    "scope": "basic block",
                    "address": _address_text(address),
                    "feature": str(feature),
                }
            for instruction in extractor.get_instructions(function, block):
                for feature, address in extractor.extract_insn_features(
                    function, block, instruction
                ):
                    yield {
                        "scope": "instruction",
                        "address": _address_text(address),
                        "feature": str(feature),
                    }


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "_", value.lower()).strip("_")


def _r2_script(result: AnalysisResult) -> str:
    lines = ["fs capa"]
    for rule_name, matches in sorted(result.capabilities.matches.items()):
        public_matches = [] if result.rules[rule_name].meta.get("capa/subscope-rule") else matches
        for index, (address, _match) in enumerate(public_matches):
            if isinstance(address, AbsoluteVirtualAddress):
                lines.append(f"f capa.{_slug(rule_name)}.{index} @ 0x{int(address):x}")
    return "\n".join(lines)


def run(arguments: argparse.Namespace, r2: R2Client) -> int:
    if arguments.analyze:
        r2.cmd("aaa")
    snapshot = SnapshotBuilder(r2).build()
    if arguments.snapshot:
        print(json.dumps(snapshot.to_dict(), default=lambda value: value.hex(), sort_keys=True))
        return 0

    function_filter = None
    if arguments.function is not None:
        function = snapshot.function_at(arguments.function)
        if function is None:
            print(f"error: no function contains {arguments.function:#x}", file=sys.stderr)
            return 2
        function_filter = {function.address}
    extractor = Radare2FeatureExtractor(snapshot, functions=function_filter)
    if arguments.features:
        print(json.dumps(list(_feature_records(extractor)), indent=2, sort_keys=True))
        return 0

    rules = _rule_paths(arguments)
    if not rules:
        print(
            "error: capa rules not found; pass --rules PATH or set R2CAPA_RULES",
            file=sys.stderr,
        )
        return 2
    result = analyze(extractor, rules, argv=sys.argv)
    if arguments.json:
        print(result.document.model_dump_json(exclude_none=True))
    elif arguments.r2_script:
        print(_r2_script(result))
    else:
        print(render(result, arguments.verbose))
    return 0


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        r2 = _open_r2(arguments.file)
        return run(arguments, r2)
    except AnalysisRequiredError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
