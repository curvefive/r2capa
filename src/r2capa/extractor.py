"""capa static feature extractor backed by a normalized radare2 snapshot."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterator
from typing import Any

from capa.features.address import NO_ADDRESS, AbsoluteVirtualAddress, Address, FileOffsetAddress
from capa.features.basicblock import BasicBlock as BasicBlockFeature
from capa.features.common import (
    ARCH_AMD64,
    ARCH_I386,
    FORMAT_ELF,
    FORMAT_PE,
    MAX_BYTES_FEATURE_SIZE,
    OS,
    OS_LINUX,
    OS_MACOS,
    OS_WINDOWS,
    Arch,
    Bytes,
    Characteristic,
    Feature,
    Format,
    String,
)
from capa.features.extractors import helpers
from capa.features.extractors.base_extractor import (
    BBHandle,
    FunctionHandle,
    InsnHandle,
    SampleHashes,
    StaticFeatureExtractor,
)
from capa.features.file import Export, FunctionName, Import, Section
from capa.features.insn import (
    API,
    MAX_STRUCTURE_SIZE,
    Mnemonic,
    Number,
    Offset,
    OperandNumber,
    OperandOffset,
)

from r2capa.model import BasicBlock, Function, Instruction, Snapshot, Symbol

_STACK_REGISTERS = {"bp", "ebp", "rbp", "sp", "esp", "rsp"}
_CALL_KINDS = {"call", "ccall", "icall", "ircall", "rcall", "ucall"}
_JUMP_KINDS = {"cjmp", "ijmp", "jmp", "mjmp", "rjmp", "ujmp"}
_GENERIC_FUNCTION_PREFIXES = ("fcn.", "loc.", "sub.")
_STACK_WRITE_RE = re.compile(
    r"\bmov\w*\s+(?:\w+\s+)?\[[^\]]*(?:bp|sp)[^\]]*\]\s*,\s*(0x[0-9a-f]+|\d+)",
    re.IGNORECASE,
)


def _address(value: int) -> AbsoluteVirtualAddress:
    return AbsoluteVirtualAddress(value)


def _symbol_names(symbol: Symbol) -> tuple[str, ...]:
    name = symbol.name
    for prefix in ("sym.imp.", "imp."):
        if name.startswith(prefix):
            name = name.removeprefix(prefix)
    module = symbol.module
    if not module and "." in name:
        possible_module, _, possible_name = name.rpartition(".")
        if possible_module and possible_name:
            module, name = possible_module, possible_name
    if module.lower().endswith(".dll"):
        module = module[:-4]
    elif module.lower().endswith(".so"):
        module = module[:-3]
    return tuple(helpers.generate_symbols(module, name, include_dll=True))


def _operand_type(operand: dict[str, Any]) -> str:
    return str(operand.get("type", "")).lower()


def _operand_integer(operand: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = operand.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError:
                pass
    nested = operand.get("value")
    if isinstance(nested, dict):
        return _operand_integer(nested, *keys, "value")
    return None


def _operand_registers(operand: dict[str, Any]) -> set[str]:
    registers = set()
    for key in ("base", "index", "reg", "register", "value"):
        value = operand.get(key)
        if isinstance(value, str):
            registers.add(value.lower())
        elif isinstance(value, dict):
            registers.update(_operand_registers(value))
    return registers


def _has_stack_reference(instruction: Instruction) -> bool:
    if any(_operand_registers(operand) & _STACK_REGISTERS for operand in instruction.operands):
        return True
    return bool(re.search(r"\b(?:e|r)?(?:bp|sp)\b", instruction.opcode, re.IGNORECASE))


def _is_indirect(instruction: Instruction) -> bool:
    if instruction.kind in {"ucall", "icall", "ircall"}:
        return True
    if instruction.kind not in _CALL_KINDS:
        return False
    return instruction.jump is None and any(
        _operand_type(operand) in {"mem", "reg"} for operand in instruction.operands[:1]
    )


def _has_loop(function: Function) -> bool:
    edges = {
        block.address: tuple(target for target in block.successors if target is not None)
        for block in function.blocks
    }
    visiting: set[int] = set()
    visited: set[int] = set()

    # Explicit DFS frames keep large or adversarial CFGs off Python's call stack.
    for root in edges:
        if root in visited:
            continue
        visiting.add(root)
        stack = [(root, iter(edges[root]))]
        while stack:
            node, successors = stack[-1]
            target = next(successors, None)
            if target is None:
                stack.pop()
                visiting.remove(node)
                visited.add(node)
            elif target in visiting:
                return True
            elif target in edges and target not in visited:
                visiting.add(target)
                stack.append((target, iter(edges[target])))
    return False


def _printable_immediate_length(value: int) -> int:
    if value < 0:
        return 0
    width = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(width, byteorder="little", signed=False)
    ascii_count = sum(0x20 <= byte < 0x7F for byte in raw)
    utf16_count = sum(
        0x20 <= raw[index] < 0x7F and raw[index + 1] == 0 for index in range(0, len(raw) - 1, 2)
    )
    return max(ascii_count, utf16_count)


class Radare2FeatureExtractor(StaticFeatureExtractor):  # type: ignore[misc]
    """Translate radare2 analysis records into capa features."""

    def __init__(self, snapshot: Snapshot, *, functions: set[int] | None = None):
        super().__init__(SampleHashes(snapshot.md5, snapshot.sha1, snapshot.sha256))
        self.snapshot = snapshot
        self.function_filter = functions
        self._functions = {function.address: function for function in snapshot.functions}
        self._strings = {entry.vaddr: entry.value for entry in snapshot.strings}
        self._api_names: dict[int, tuple[str, ...]] = {}
        for symbol in snapshot.imports:
            names = _symbol_names(symbol)
            for address in symbol.addresses:
                self._api_names[address] = names
        for address, name in snapshot.analyst_apis.items():
            self._api_names[address] = (name,)
        self._callers: dict[int, list[int]] = defaultdict(list)
        for function in snapshot.functions:
            for instruction in function.instructions:
                if instruction.kind in _CALL_KINDS and instruction.jump is not None:
                    self._callers[instruction.jump].append(instruction.address)

    def get_base_address(self) -> AbsoluteVirtualAddress:
        return _address(self.snapshot.base_address)

    def extract_global_features(self) -> Iterator[tuple[Feature, Address]]:
        if self.snapshot.format == "pe":
            yield Format(FORMAT_PE), NO_ADDRESS
        elif self.snapshot.format == "elf":
            yield Format(FORMAT_ELF), NO_ADDRESS

        if self.snapshot.arch == "i386":
            yield Arch(ARCH_I386), NO_ADDRESS
        elif self.snapshot.arch == "amd64":
            yield Arch(ARCH_AMD64), NO_ADDRESS

        os_name = self.snapshot.os
        if os_name in {"windows", "w32"}:
            yield OS(OS_WINDOWS), NO_ADDRESS
        elif os_name == "linux":
            yield OS(OS_LINUX), NO_ADDRESS
        elif os_name in {"darwin", "macos", "osx"}:
            yield OS(OS_MACOS), NO_ADDRESS

    def extract_file_features(self) -> Iterator[tuple[Feature, Address]]:
        for section in self.snapshot.sections:
            yield Section(section.name), _address(section.vaddr)
        for symbol in self.snapshot.imports:
            for name in _symbol_names(symbol):
                yield Import(name), _address(symbol.address)
        for symbol in self.snapshot.exports:
            yield Export(symbol.name), _address(symbol.address)
        for entry in self.snapshot.strings:
            location: Address = (
                FileOffsetAddress(entry.paddr) if entry.paddr >= 0 else _address(entry.vaddr)
            )
            yield String(entry.value), location
        for function in self.snapshot.functions:
            name = function.name
            if name.startswith("sym."):
                name = name.removeprefix("sym.")
            if name and not name.startswith(_GENERIC_FUNCTION_PREFIXES):
                yield FunctionName(name), _address(function.address)

    def get_functions(self) -> Iterator[FunctionHandle]:
        imported_addresses = {
            address for symbol in self.snapshot.imports for address in symbol.addresses
        }
        for function in self.snapshot.functions:
            if function.address in imported_addresses:
                continue
            if self.function_filter is not None and function.address not in self.function_filter:
                continue
            yield FunctionHandle(address=_address(function.address), inner=function)

    def is_library_function(self, addr: Address) -> bool:
        return isinstance(addr, AbsoluteVirtualAddress) and int(addr) in self._api_names

    def get_function_name(self, addr: Address) -> str:
        if isinstance(addr, AbsoluteVirtualAddress):
            if names := self._api_names.get(int(addr)):
                return names[0]
            if function := self._functions.get(int(addr)):
                return function.name
        raise KeyError(addr)

    def extract_function_features(self, fh: FunctionHandle) -> Iterator[tuple[Feature, Address]]:
        function = fh.inner
        assert isinstance(function, Function)
        for caller in self._callers.get(function.address, ()):
            yield Characteristic("calls to"), _address(caller)
        if _has_loop(function):
            yield Characteristic("loop"), fh.address
        if any(
            instruction.kind in _CALL_KINDS and instruction.jump == function.address
            for instruction in function.instructions
        ):
            yield Characteristic("recursive call"), fh.address

    def get_basic_blocks(self, fh: FunctionHandle) -> Iterator[BBHandle]:
        function = fh.inner
        assert isinstance(function, Function)
        for block in function.blocks:
            yield BBHandle(address=_address(block.address), inner=block)

    def extract_basic_block_features(
        self, fh: FunctionHandle, bbh: BBHandle
    ) -> Iterator[tuple[Feature, Address]]:
        block = bbh.inner
        assert isinstance(block, BasicBlock)
        yield BasicBlockFeature(), bbh.address
        if block.instructions and block.instructions[-1].jump == block.address:
            yield Characteristic("tight loop"), bbh.address
        stack_string_length = 0
        for instruction in block.instructions:
            if match := _STACK_WRITE_RE.search(instruction.opcode):
                stack_string_length += _printable_immediate_length(int(match.group(1), 0))
        if stack_string_length >= 8:
            yield Characteristic("stack string"), bbh.address

    def get_instructions(self, fh: FunctionHandle, bbh: BBHandle) -> Iterator[InsnHandle]:
        block = bbh.inner
        assert isinstance(block, BasicBlock)
        for instruction in block.instructions:
            yield InsnHandle(address=_address(instruction.address), inner=instruction)

    def extract_insn_features(
        self, fh: FunctionHandle, bbh: BBHandle, ih: InsnHandle
    ) -> Iterator[tuple[Feature, Address]]:
        instruction = ih.inner
        assert isinstance(instruction, Instruction)
        yield Mnemonic(instruction.mnemonic), ih.address
        yield from self._extract_api(instruction, ih.address)
        yield from self._extract_numbers_and_offsets(instruction, ih.address)
        yield from self._extract_references(instruction, ih.address)
        yield from self._extract_characteristics(instruction, ih.address)

    def _extract_api(
        self, instruction: Instruction, location: Address
    ) -> Iterator[tuple[Feature, Address]]:
        if instruction.kind not in _CALL_KINDS | _JUMP_KINDS:
            return
        target = instruction.jump if instruction.jump is not None else instruction.ptr
        if target is None:
            return
        for name in self._api_names.get(target, ()):
            yield API(name), location

    def _extract_numbers_and_offsets(
        self, instruction: Instruction, location: Address
    ) -> Iterator[tuple[Feature, Address]]:
        if instruction.mnemonic.startswith("ret"):
            return
        stack_reference = _has_stack_reference(instruction)
        for index, operand in enumerate(instruction.operands):
            operand_type = _operand_type(operand)
            if operand_type in {"imm", "immediate"}:
                value = _operand_integer(operand, "value", "imm")
                if value is None:
                    continue
                yield Number(value), location
                yield OperandNumber(index, value), location
                if instruction.mnemonic == "add" and 0 < value < MAX_STRUCTURE_SIZE:
                    yield Offset(value), location
                    yield OperandOffset(index, value), location
            elif operand_type in {"mem", "memory"} and not stack_reference:
                displacement = _operand_integer(operand, "disp", "displacement")
                if displacement is None:
                    displacement = 0
                yield Offset(displacement), location
                yield OperandOffset(index, displacement), location

    def _extract_references(
        self, instruction: Instruction, location: Address
    ) -> Iterator[tuple[Feature, Address]]:
        if instruction.ptr is None:
            return
        if value := self._strings.get(instruction.ptr):
            yield String(value), location
        elif data := self.snapshot.data.get(instruction.ptr):
            candidate = data[:MAX_BYTES_FEATURE_SIZE]
            if candidate and any(candidate):
                yield Bytes(candidate), location

    def _extract_characteristics(
        self, instruction: Instruction, location: Address
    ) -> Iterator[tuple[Feature, Address]]:
        opcode = instruction.opcode.lower()
        if instruction.kind in _CALL_KINDS and instruction.jump is not None:
            yield Characteristic("calls from"), _address(instruction.jump)
        if _is_indirect(instruction):
            yield Characteristic("indirect call"), location
        if (
            instruction.mnemonic == "call"
            and instruction.jump == instruction.address + instruction.size
        ):
            yield Characteristic("call $+5"), location
        if "fs:" in opcode or "fs:[" in opcode:
            yield Characteristic("fs access"), location
        if "gs:" in opcode or "gs:[" in opcode:
            yield Characteristic("gs access"), location
        if re.search(r"\bfs:\s*\[?(?:0x)?30\]?", opcode) or re.search(
            r"\bgs:\s*\[?(?:0x)?60\]?", opcode
        ):
            yield Characteristic("peb access"), location
        if instruction.mnemonic == "xor" and len(instruction.operands) >= 2:
            first, second = instruction.operands[:2]
            if first != second and not _has_stack_reference(instruction):
                yield Characteristic("nzxor"), location
        if instruction.kind in _CALL_KINDS | _JUMP_KINDS and instruction.jump is not None:
            source_section = self.snapshot.section_at(instruction.address)
            target_section = self.snapshot.section_at(instruction.jump)
            if (
                source_section is not None
                and target_section is not None
                and source_section.name != target_section.name
                and instruction.jump not in self._api_names
            ):
                yield Characteristic("cross section flow"), location
