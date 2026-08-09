from __future__ import annotations

import pytest

from r2capa.snapshot import AnalysisRequiredError, SnapshotBuilder

from .conftest import FakeR2


def _responses() -> dict[str, object]:
    return {
        "ij": {
            "core": {"file": "/missing/sample.exe"},
            "bin": {
                "arch": "x86",
                "bits": 64,
                "baddr": 0x400000,
                "class": "PE32+",
                "os": "windows",
            },
        },
        "iSj": [
            {"name": ".text", "vaddr": 0x401000, "paddr": 0x200, "vsize": 0x1000},
            {"name": ".data", "vaddr": 0x402000, "paddr": 0x1200, "vsize": 0x1000},
        ],
        "iij": [
            {
                "name": "CreateFileW",
                "libname": "kernel32.dll",
                "plt": 0x403000,
                "vaddr": 0x405000,
            }
        ],
        "iEj": [{"name": "entry", "vaddr": 0x401000}],
        "izj": [{"string": "hello", "vaddr": 0x402000, "paddr": 0x1200}],
        "aflj": [{"addr": 0x401000, "size": 0x20, "name": "sym.main"}],
        "pdfj @ 0x401000": {
            "ops": [
                {
                    "addr": 0x401000,
                    "size": 5,
                    "opcode": "mov eax, 0x2a",
                    "type": "mov",
                    "opex": {
                        "operands": [
                            {"type": "reg", "value": "eax"},
                            {"type": "imm", "value": 42},
                        ]
                    },
                },
                {
                    "addr": 0x401005,
                    "size": 5,
                    "opcode": "call 0x403000",
                    "type": "call",
                    "jump": 0x403000,
                    "ptr": 0x402100,
                    "opex": {"operands": [{"type": "imm", "value": 0x403000}]},
                },
            ]
        },
        "afbj @ 0x401000": [{"addr": 0x401000, "size": 0x10, "jump": 0x401000, "fail": -1}],
        "pxj 32 @ 0x402100": [1, 2, 3, 4],
        "fj": [{"name": "capa.api.user32.MessageBoxW", "offset": 0x404000}],
    }


def test_build_snapshot_normalizes_r2_json() -> None:
    r2 = FakeR2(_responses())
    snapshot = SnapshotBuilder(r2).build()

    assert snapshot.format == "pe"
    assert snapshot.arch == "amd64"
    assert snapshot.base_address == 0x400000
    assert snapshot.imports[0].addresses == (0x403000, 0x405000)
    assert snapshot.functions[0].blocks[0].instructions[1].jump == 0x403000
    assert snapshot.data[0x402100] == b"\x01\x02\x03\x04"
    assert snapshot.analyst_apis[0x404000] == "user32.MessageBoxW"


def test_build_snapshot_requires_r2_analysis() -> None:
    responses = _responses()
    responses["aflj"] = []

    with pytest.raises(AnalysisRequiredError, match="run 'aaa'"):
        SnapshotBuilder(FakeR2(responses)).build()


def test_builder_can_skip_referenced_bytes() -> None:
    r2 = FakeR2(_responses())
    snapshot = SnapshotBuilder(r2, collect_data_bytes=False).build()

    assert snapshot.data == {}
    assert not any(command.startswith("pxj") for command in r2.commands)
