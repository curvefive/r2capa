from __future__ import annotations

from typing import Any

import pytest

from r2capa.model import BasicBlock, Function, Instruction, Section, Snapshot, StringEntry, Symbol


class FakeR2:
    def __init__(self, responses: dict[str, Any]):
        self.responses = responses
        self.commands: list[str] = []

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        return str(self.responses.get(command, ""))

    def cmdj(self, command: str) -> Any:
        self.commands.append(command)
        return self.responses.get(command)


@pytest.fixture
def snapshot() -> Snapshot:
    instructions = (
        Instruction(
            address=0x401000,
            size=5,
            mnemonic="mov",
            opcode="mov eax, 0x2a",
            kind="mov",
            opex={
                "operands": [
                    {"type": "reg", "value": "eax"},
                    {"type": "imm", "value": 0x2A},
                ]
            },
        ),
        Instruction(
            address=0x401005,
            size=7,
            mnemonic="lea",
            opcode="lea rcx, [0x402000]",
            kind="lea",
            ptr=0x402000,
            opex={"operands": [{"type": "reg", "value": "rcx"}]},
        ),
        Instruction(
            address=0x40100C,
            size=5,
            mnemonic="call",
            opcode="call sym.imp.CreateFileW",
            kind="call",
            jump=0x403000,
            opex={"operands": [{"type": "imm", "value": 0x403000}]},
        ),
        Instruction(
            address=0x401011,
            size=2,
            mnemonic="xor",
            opcode="xor eax, ebx",
            kind="xor",
            opex={
                "operands": [
                    {"type": "reg", "value": "eax"},
                    {"type": "reg", "value": "ebx"},
                ]
            },
        ),
        Instruction(
            address=0x401013,
            size=2,
            mnemonic="call",
            opcode="call rax",
            kind="ucall",
            opex={"operands": [{"type": "reg", "value": "rax"}]},
        ),
    )
    return Snapshot(
        path="sample.exe",
        base_address=0x400000,
        format="pe",
        arch="amd64",
        bits=64,
        os="windows",
        md5="0" * 32,
        sha1="1" * 40,
        sha256="2" * 64,
        sections=(
            Section(".text", 0x401000, 0x200, 0x1000),
            Section(".data", 0x402000, 0x1200, 0x1000),
        ),
        imports=(Symbol("CreateFileW", 0x403000, "kernel32.dll", 0x405000),),
        exports=(Symbol("exported", 0x401100),),
        strings=(StringEntry("hello from r2", 0x402000, 0x1200),),
        functions=(
            Function(
                address=0x401000,
                size=0x30,
                name="sym.main",
                blocks=(
                    BasicBlock(0x401000, 0x20, jump=0x401020, instructions=instructions),
                    BasicBlock(
                        0x401020,
                        0x10,
                        jump=0x401020,
                        instructions=(
                            Instruction(
                                address=0x401020,
                                size=2,
                                mnemonic="jmp",
                                opcode="jmp 0x401020",
                                kind="jmp",
                                jump=0x401020,
                                opex={"operands": [{"type": "imm", "value": 0x401020}]},
                            ),
                        ),
                    ),
                ),
            ),
        ),
        data={0x402100: b"\x01\x02\x03\x04"},
        analyst_apis={0x404000: "user32.MessageBoxW"},
    )
