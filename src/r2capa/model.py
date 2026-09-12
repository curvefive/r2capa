"""Normalized, serializable representation of the r2 data used by capa."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Section:
    name: str
    vaddr: int
    paddr: int
    size: int

    def contains(self, address: int) -> bool:
        return self.vaddr <= address < self.vaddr + self.size


@dataclass(frozen=True, slots=True)
class Symbol:
    name: str
    address: int
    module: str = ""
    alternate_address: int | None = None

    @property
    def addresses(self) -> tuple[int, ...]:
        if self.alternate_address is None or self.alternate_address == self.address:
            return (self.address,)
        return (self.address, self.alternate_address)


@dataclass(frozen=True, slots=True)
class StringEntry:
    value: str
    vaddr: int
    paddr: int


@dataclass(frozen=True, slots=True)
class Instruction:
    address: int
    size: int
    mnemonic: str
    opcode: str
    kind: str = ""
    jump: int | None = None
    ptr: int | None = None
    value: int | None = None
    opex: dict[str, Any] = field(default_factory=dict)

    @property
    def operands(self) -> tuple[dict[str, Any], ...]:
        operands = self.opex.get("operands", ())
        if not isinstance(operands, list):
            return ()
        return tuple(operand for operand in operands if isinstance(operand, dict))


@dataclass(frozen=True, slots=True)
class BasicBlock:
    address: int
    size: int
    jump: int | None = None
    fail: int | None = None
    instructions: tuple[Instruction, ...] = ()

    @property
    def successors(self) -> tuple[int, ...]:
        return tuple(target for target in (self.jump, self.fail) if target is not None)


@dataclass(frozen=True, slots=True)
class Function:
    address: int
    size: int
    name: str
    blocks: tuple[BasicBlock, ...] = ()

    @property
    def instructions(self) -> tuple[Instruction, ...]:
        return tuple(instruction for block in self.blocks for instruction in block.instructions)


@dataclass(frozen=True, slots=True)
class Snapshot:
    path: str
    base_address: int
    format: str
    arch: str
    bits: int
    os: str
    md5: str
    sha1: str
    sha256: str
    sections: tuple[Section, ...] = ()
    imports: tuple[Symbol, ...] = ()
    exports: tuple[Symbol, ...] = ()
    strings: tuple[StringEntry, ...] = ()
    functions: tuple[Function, ...] = ()
    data: dict[int, bytes] = field(default_factory=dict)
    analyst_apis: dict[int, str] = field(default_factory=dict)

    def section_at(self, address: int) -> Section | None:
        return next((section for section in self.sections if section.contains(address)), None)

    def function_at(self, address: int) -> Function | None:
        # Prefer an exact entry over another function's overlapping blocks.
        for function in self.functions:
            if function.address == address:
                return function
        return next(
            (
                function
                for function in self.functions
                if (
                    any(
                        block.address <= address < block.address + block.size
                        for block in function.blocks
                    )
                    if function.blocks
                    else function.address <= address < function.address + function.size
                )
            ),
            None,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
