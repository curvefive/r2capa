"""Collect a bounded analysis snapshot through radare2's JSON interface."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Protocol, cast

from r2capa.model import BasicBlock, Function, Instruction, Section, Snapshot, StringEntry, Symbol


class R2Client(Protocol):
    def cmd(self, command: str) -> str: ...

    def cmdj(self, command: str) -> Any: ...


class AnalysisRequiredError(RuntimeError):
    """Raised when r2 has no recovered functions to analyze."""


def _integer(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return default
    return default


def _optional_integer(value: Any) -> int | None:
    if value is None:
        return None
    result = _integer(value, default=-1)
    return None if result < 0 else result


def _first_present(*values: Any) -> Any:
    """Use fallback fields only when absent; zero is a valid address."""
    return next((value for value in values if value is not None), None)


def _records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [cast(dict[str, Any], record) for record in value if isinstance(record, dict)]


def _hash_file(path: str) -> tuple[str, str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with Path(path).open("rb") as stream:
            while block := stream.read(1024 * 1024):
                md5.update(block)
                sha1.update(block)
                sha256.update(block)
    except OSError:
        return "", "", ""
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def _format_name(bin_info: dict[str, Any]) -> str:
    description = " ".join(
        str(bin_info.get(key, "")) for key in ("class", "bintype", "rclass", "type")
    ).lower()
    if "pe" in description:
        return "pe"
    if "elf" in description:
        return "elf"
    return "unknown"


def _arch_name(bin_info: dict[str, Any]) -> tuple[str, int]:
    arch = str(bin_info.get("arch", "")).lower()
    bits = _integer(bin_info.get("bits"))
    if arch in {"x86", "i386"} and bits == 64:
        return "amd64", bits
    if arch in {"x86", "i386"} and bits == 32:
        return "i386", bits
    return arch or "unknown", bits


class SnapshotBuilder:
    """Build a consistent Python model from stable r2 JSON commands."""

    def __init__(self, r2: R2Client, *, collect_data_bytes: bool = True):
        self.r2 = r2
        self.collect_data_bytes = collect_data_bytes

    def build(self) -> Snapshot:
        info = self.r2.cmdj("ij") or {}
        if not isinstance(info, dict):
            info = {}
        core_info = info.get("core", {}) if isinstance(info.get("core"), dict) else {}
        bin_info = info.get("bin", {}) if isinstance(info.get("bin"), dict) else {}
        path = str(core_info.get("file") or bin_info.get("file") or "<radare2-session>")
        arch, bits = _arch_name(bin_info)

        sections = self._sections()
        imports = self._symbols("iij", import_symbols=True)
        exports = self._symbols("iEj", import_symbols=False)
        strings = self._strings()
        functions = self._functions()
        if not functions:
            raise AnalysisRequiredError("no functions found; run 'aaa' in radare2 first")

        data = self._referenced_data(functions, strings, sections)
        md5, sha1, sha256 = _hash_file(path)
        return Snapshot(
            path=path,
            base_address=_integer(_first_present(bin_info.get("baddr"), core_info.get("baseaddr"))),
            format=_format_name(bin_info),
            arch=arch,
            bits=bits,
            os=str(bin_info.get("os") or "unknown").lower(),
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            sections=sections,
            imports=imports,
            exports=exports,
            strings=strings,
            functions=functions,
            data=data,
            analyst_apis=self._analyst_apis(),
        )

    def _sections(self) -> tuple[Section, ...]:
        result = []
        for record in _records(self.r2.cmdj("iSj")):
            result.append(
                Section(
                    name=str(record.get("name", "")),
                    vaddr=_integer(record.get("vaddr")),
                    paddr=_integer(record.get("paddr"), default=-1),
                    size=_integer(record.get("vsize") or record.get("size")),
                )
            )
        return tuple(result)

    def _symbols(self, command: str, *, import_symbols: bool) -> tuple[Symbol, ...]:
        result = []
        for record in _records(self.r2.cmdj(command)):
            primary = record.get("plt") if import_symbols else record.get("vaddr")
            alternate = record.get("vaddr") if import_symbols else None
            result.append(
                Symbol(
                    name=str(record.get("name") or record.get("realname") or ""),
                    address=_integer(primary or record.get("paddr")),
                    module=str(record.get("libname") or record.get("lib") or ""),
                    alternate_address=_optional_integer(alternate),
                )
            )
        return tuple(symbol for symbol in result if symbol.name)

    def _strings(self) -> tuple[StringEntry, ...]:
        return tuple(
            StringEntry(
                value=str(record.get("string", "")),
                vaddr=_integer(record.get("vaddr")),
                paddr=_integer(record.get("paddr"), default=-1),
            )
            for record in _records(self.r2.cmdj("izj"))
            if record.get("string")
        )

    def _functions(self) -> tuple[Function, ...]:
        functions = []
        for record in _records(self.r2.cmdj("aflj")):
            address = _integer(_first_present(record.get("addr"), record.get("offset")))
            size = _integer(record.get("size"))
            operations = self._operations(address)
            blocks = self._blocks(address, operations)
            functions.append(
                Function(
                    address=address,
                    size=size,
                    name=str(record.get("name") or f"fcn.{address:x}"),
                    blocks=blocks,
                )
            )
        return tuple(functions)

    def _operations(self, function_address: int) -> tuple[Instruction, ...]:
        result = self.r2.cmdj(f"pdfj @ {function_address:#x}") or {}
        raw_operations = result.get("ops", []) if isinstance(result, dict) else []
        operations = []
        for record in _records(raw_operations):
            opcode = str(record.get("opcode") or record.get("disasm") or "")
            mnemonic = str(record.get("mnemonic") or opcode.partition(" ")[0]).lower()
            opex = record.get("opex") if isinstance(record.get("opex"), dict) else {}
            operations.append(
                Instruction(
                    address=_integer(_first_present(record.get("addr"), record.get("offset"))),
                    size=_integer(record.get("size"), default=1),
                    mnemonic=mnemonic,
                    opcode=opcode,
                    kind=str(record.get("type") or "").lower(),
                    jump=_optional_integer(record.get("jump")),
                    ptr=_optional_integer(record.get("ptr")),
                    value=_optional_integer(record.get("val")),
                    opex=cast(dict[str, Any], opex),
                )
            )
        return tuple(operations)

    def _blocks(
        self, function_address: int, operations: tuple[Instruction, ...]
    ) -> tuple[BasicBlock, ...]:
        result = []
        records = _records(self.r2.cmdj(f"afbj @ {function_address:#x}"))
        if not records and operations:
            start = operations[0].address
            end = max(instruction.address + instruction.size for instruction in operations)
            records = [{"addr": start, "size": end - start}]
        for record in records:
            address = _integer(_first_present(record.get("addr"), record.get("offset")))
            size = _integer(record.get("size"))
            block_operations = tuple(
                operation
                for operation in operations
                if address <= operation.address < address + size
            )
            result.append(
                BasicBlock(
                    address=address,
                    size=size,
                    jump=_optional_integer(record.get("jump")),
                    fail=_optional_integer(record.get("fail")),
                    instructions=block_operations,
                )
            )
        return tuple(result)

    def _referenced_data(
        self,
        functions: tuple[Function, ...],
        strings: tuple[StringEntry, ...],
        sections: tuple[Section, ...],
    ) -> dict[int, bytes]:
        if not self.collect_data_bytes:
            return {}
        string_addresses = {entry.vaddr for entry in strings}
        pointers = {
            instruction.ptr
            for function in functions
            for instruction in function.instructions
            if instruction.ptr is not None
            and instruction.ptr not in string_addresses
            and any(section.contains(instruction.ptr) for section in sections)
        }
        data = {}
        for pointer in sorted(pointers):
            raw = self.r2.cmdj(f"pxj 32 @ {pointer:#x}")
            if isinstance(raw, list) and raw:
                values = [_integer(value) & 0xFF for value in raw]
                data[pointer] = bytes(values)
        return data

    def _analyst_apis(self) -> dict[int, str]:
        result = {}
        for record in _records(self.r2.cmdj("fj")):
            name = str(record.get("name", ""))
            if name.startswith("capa.api."):
                result[_integer(record.get("offset"))] = name.removeprefix("capa.api.")
        return result
