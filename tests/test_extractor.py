from __future__ import annotations

import sys
from dataclasses import replace

import pytest
from capa.features.address import AbsoluteVirtualAddress, FileOffsetAddress
from capa.features.basicblock import BasicBlock
from capa.features.common import OS, Arch, Characteristic, Format, String
from capa.features.file import Export, FunctionName, Import, Section
from capa.features.insn import API, Mnemonic, Number

from r2capa.extractor import Radare2FeatureExtractor
from r2capa.model import BasicBlock as ModelBlock
from r2capa.model import Function, Snapshot


def _values(features: list[tuple[object, object]], feature_type: type[object]) -> set[object]:
    return {feature.value for feature, _address in features if isinstance(feature, feature_type)}


def test_global_and_file_features(snapshot: Snapshot) -> None:
    extractor = Radare2FeatureExtractor(snapshot)
    global_features = list(extractor.extract_global_features())
    file_features = list(extractor.extract_file_features())

    assert _values(global_features, Format) == {"pe"}
    assert _values(global_features, Arch) == {"amd64"}
    assert _values(global_features, OS) == {"windows"}
    assert {".text", ".data"} <= _values(file_features, Section)
    assert "kernel32.CreateFileW" in _values(file_features, Import)
    assert "exported" in _values(file_features, Export)
    assert "main" in _values(file_features, FunctionName)
    string_locations = [
        address for feature, address in file_features if isinstance(feature, String)
    ]
    assert string_locations == [FileOffsetAddress(0x1200)]


def test_function_block_and_instruction_features(snapshot: Snapshot) -> None:
    extractor = Radare2FeatureExtractor(snapshot)
    function = next(extractor.get_functions())
    function_features = list(extractor.extract_function_features(function))
    blocks = list(extractor.get_basic_blocks(function))
    block_features = list(extractor.extract_basic_block_features(function, blocks[1]))
    instructions = list(extractor.get_instructions(function, blocks[0]))
    call_features = list(extractor.extract_insn_features(function, blocks[0], instructions[2]))
    xor_features = list(extractor.extract_insn_features(function, blocks[0], instructions[3]))
    indirect_features = list(extractor.extract_insn_features(function, blocks[0], instructions[4]))

    assert "loop" in _values(function_features, Characteristic)
    assert any(isinstance(feature, BasicBlock) for feature, _address in block_features)
    assert "tight loop" in _values(block_features, Characteristic)
    assert "kernel32.CreateFileW" in _values(call_features, API)
    assert "calls from" in _values(call_features, Characteristic)
    assert "nzxor" in _values(xor_features, Characteristic)
    assert "indirect call" in _values(indirect_features, Characteristic)


def test_numbers_strings_and_function_filter(snapshot: Snapshot) -> None:
    extractor = Radare2FeatureExtractor(snapshot, functions={0x401000})
    function = next(extractor.get_functions())
    block = next(extractor.get_basic_blocks(function))
    instructions = list(extractor.get_instructions(function, block))

    number_features = list(extractor.extract_insn_features(function, block, instructions[0]))
    string_features = list(extractor.extract_insn_features(function, block, instructions[1]))

    assert 0x2A in _values(number_features, Number)
    assert "mov" in _values(number_features, Mnemonic)
    assert "hello from r2" in _values(string_features, String)
    assert extractor.get_base_address() == AbsoluteVirtualAddress(0x400000)
    assert extractor.get_function_name(AbsoluteVirtualAddress(0x403000)) == "kernel32.CreateFileW"


def test_unknown_function_filter_is_empty(snapshot: Snapshot) -> None:
    extractor = Radare2FeatureExtractor(snapshot, functions={0xDEADBEEF})

    assert list(extractor.get_functions()) == []


@pytest.mark.parametrize("cyclic", [False, True])
def test_large_control_flow_graph(snapshot: Snapshot, cyclic: bool) -> None:
    count = sys.getrecursionlimit() + 100
    start = 0x600000
    blocks = tuple(
        ModelBlock(
            start + index,
            1,
            jump=start + index + 1 if index + 1 < count else (start if cyclic else None),
        )
        for index in range(count)
    )
    function = Function(start, count, "large", blocks)
    extractor = Radare2FeatureExtractor(replace(snapshot, functions=(function,)))
    features = list(extractor.extract_function_features(next(extractor.get_functions())))

    assert ("loop" in _values(features, Characteristic)) == cyclic


@pytest.mark.parametrize("detached_cycle", [False, True])
def test_shared_successors_and_disconnected_cycles(
    snapshot: Snapshot, detached_cycle: bool
) -> None:
    blocks = (
        ModelBlock(0, 1, jump=1, fail=2),
        ModelBlock(1, 1, jump=3),
        ModelBlock(2, 1, jump=3),
        ModelBlock(3, 1, jump=0xFFFF),
    )
    if detached_cycle:
        blocks += (ModelBlock(4, 1, jump=5), ModelBlock(5, 1, jump=4))
    extractor = Radare2FeatureExtractor(
        replace(snapshot, functions=(Function(0, 6, "diamond", blocks),))
    )
    features = list(extractor.extract_function_features(next(extractor.get_functions())))

    assert ("loop" in _values(features, Characteristic)) == detached_cycle
