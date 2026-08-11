#!/usr/bin/env python3
# Copyright 2026 Mocktail Project Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Derive a fail-closed HostAbi profile from one exact approved payload.

The analyzer never executes guest code and never marks a payload supported.
It accepts only an exact reference sidecar bound to the reference ELF digest,
matches native boundaries structurally, and emits an experimental manifest for
an isolated updater probation run.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile
from typing import Any, Iterator, Sequence

try:
    import capstone
    from capstone import x86 as capstone_x86
except ImportError:  # The CLI turns this into one explicit fail-closed error.
    capstone = None
    capstone_x86 = None


MAX_ELF_BYTES = 512 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024
MAX_RELOCATIONS = 4 * 1024 * 1024
MAX_INIT_ARRAY_ENTRIES = 64 * 1024
SHA256_CHUNK_BYTES = 1024 * 1024
REGISTRY_INITIALIZER_MAX_BYTES = 0x1000
ELF_BUILD_ID_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PAYLOAD_ID_PATTERN = re.compile(r"^[1-9][0-9]*-[0-9a-f]{40}$")
RVA_PATTERN = re.compile(r"^0x[1-9a-f][0-9a-f]*$")

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL_ENTRY = struct.Struct("<IBBHQQ")
NOTE_HEADER = struct.Struct("<III")

ELF_CLASS_64 = 2
ELF_DATA_LITTLE_ENDIAN = 1
ELF_VERSION_CURRENT = 1
ELF_TYPE_SHARED_OBJECT = 3
ELF_MACHINE_X86_64 = 62
PT_LOAD = 1
PF_EXECUTE = 1
PF_WRITE = 2
PF_READ = 4
SHF_WRITE = 1
SHF_ALLOC = 2
SHF_EXECINSTR = 4
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_NOTE = 7
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_ANDROID_RELA = 0x60000002
R_X86_64_RELATIVE = 8

APS2_GROUPED_BY_INFO = 1
APS2_GROUPED_BY_OFFSET_DELTA = 2
APS2_GROUPED_BY_ADDEND = 4
APS2_GROUP_HAS_ADDEND = 8

REQUIRED_EXPORTS = frozenset(
    {
        "JNI_OnLoad",
        "Java_com_roblox_engine_jni_NativeGLInterface_nativeGameGlobalInit",
        "Java_com_roblox_engine_jni_NativeGLInterface_nativeUpdateAdapterInit",
        "Java_com_roblox_engine_jni_NativeGLInterface_nativeAppBridgeV2InitWithParams",
        "Java_com_roblox_engine_jni_NativeGLInterface_nativeAppBridgeStartLuaAppDM",
        "Java_com_roblox_engine_jni_NativeGLInterface_nativeAppBridgeV2StartAppWithParams",
        "Java_com_roblox_engine_jni_NativeGLInterface_nativeCallMessagesFromMainThread",
    }
)

PRIMARY_TOOLCHAIN_MARKERS = (
    b"Android (13624864, +pgo, +bolt, +lto, +mlgo, based on r530567e) "
    b"clang version 19.0.1",
    b"Linker: LLD 19.0.1",
)


class AnalyzerError(RuntimeError):
    """One deterministic fail-closed analysis error."""


@dataclass(frozen=True)
class Segment:
    offset: int
    virtual_address: int
    file_size: int
    memory_size: int
    flags: int

    def contains_memory(self, rva: int, size: int = 1) -> bool:
        return (
            size >= 0
            and self.virtual_address <= rva
            and rva + size <= self.virtual_address + self.memory_size
        )

    def contains_file_data(self, rva: int, size: int = 1) -> bool:
        return (
            size >= 0
            and self.virtual_address <= rva
            and rva + size <= self.virtual_address + self.file_size
        )


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    section_type: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    entry_size: int


@dataclass(frozen=True)
class Relocation:
    offset: int
    info: int
    addend: int


@dataclass(frozen=True)
class SignatureSpec:
    name: str
    reference_rva: int
    instruction_count: int
    allow_registry_object_size_change: bool = False
    minimum_anchor_bytes: int = 6


@dataclass(frozen=True)
class SignatureMatch:
    rva: int
    reference_instructions: tuple[Any, ...]
    candidate_instructions: tuple[Any, ...]


class Sleb128Reader:
    def __init__(self, encoded: bytes):
        self._encoded = encoded
        self.position = 0

    def pop(self) -> int:
        value = 0
        shift = 0
        while True:
            if self.position >= len(self._encoded) or shift >= 70:
                raise AnalyzerError("invalid or truncated APS2 SLEB128 value")
            byte = self._encoded[self.position]
            self.position += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if (byte & 0x80) == 0:
                break
        if shift < 64 and (byte & 0x40):
            value -= 1 << shift
        if not -(1 << 63) <= value < (1 << 64):
            raise AnalyzerError("APS2 SLEB128 value exceeds 64-bit bounds")
        return value

    def at_end(self) -> bool:
        return self.position == len(self._encoded)


def sha256_file(file_object: Any) -> str:
    digest = hashlib.sha256()
    while True:
        try:
            chunk = file_object.read(SHA256_CHUNK_BYTES)
        except OSError as error:
            raise AnalyzerError("cannot hash ELF file") from error
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


class ElfImage:
    def __init__(self, path: Path):
        self.path = path
        self._file = None
        self.data = None
        self.file_size = 0
        self.sha256 = ""
        self.sections: dict[str, Section] = {}
        self.sections_by_index: tuple[Section, ...] = ()
        self.segments: tuple[Segment, ...] = ()
        self.build_id = ""

    def __enter__(self) -> "ElfImage":
        try:
            file_status = os.lstat(self.path)
        except OSError as error:
            raise AnalyzerError(f"cannot stat ELF file: {self.path}") from error
        if stat.S_ISLNK(file_status.st_mode) or not stat.S_ISREG(file_status.st_mode):
            raise AnalyzerError(f"ELF input must be a regular non-symlink: {self.path}")
        if file_status.st_size < ELF_HEADER.size or file_status.st_size > MAX_ELF_BYTES:
            raise AnalyzerError(f"ELF input has an invalid size: {self.path}")
        self.file_size = file_status.st_size
        try:
            self._file = self.path.open("rb")
            self.sha256 = sha256_file(self._file)
            self._file.seek(0)
            self.data = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
            self._parse()
        except AnalyzerError:
            self.__exit__(None, None, None)
            raise
        except (OSError, ValueError, struct.error) as error:
            self.__exit__(None, None, None)
            raise AnalyzerError(f"cannot parse ELF file: {self.path}") from error
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        if self.data is not None:
            self.data.close()
            self.data = None
        if self._file is not None:
            self._file.close()
            self._file = None

    def _checked_range(self, offset: int, size: int, description: str) -> None:
        if offset < 0 or size < 0 or offset > self.file_size - size:
            raise AnalyzerError(f"ELF {description} exceeds file bounds")

    def bytes_at(self, offset: int, size: int, description: str) -> bytes:
        self._checked_range(offset, size, description)
        return self.data[offset : offset + size]

    def section_bytes(self, section: Section) -> bytes:
        return self.bytes_at(section.offset, section.size, f"section {section.name}")

    def _parse(self) -> None:
        header = ELF_HEADER.unpack_from(self.data, 0)
        identification = header[0]
        if (
            identification[:4] != b"\x7fELF"
            or identification[4] != ELF_CLASS_64
            or identification[5] != ELF_DATA_LITTLE_ENDIAN
            or identification[6] != ELF_VERSION_CURRENT
            or header[1] != ELF_TYPE_SHARED_OBJECT
            or header[2] != ELF_MACHINE_X86_64
            or header[3] != ELF_VERSION_CURRENT
        ):
            raise AnalyzerError("candidate must be a little-endian x86-64 ET_DYN ELF")

        program_offset = header[5]
        section_offset = header[6]
        program_entry_size = header[9]
        program_count = header[10]
        section_entry_size = header[11]
        section_count = header[12]
        section_names_index = header[13]
        if (
            program_entry_size != PROGRAM_HEADER.size
            or section_entry_size != SECTION_HEADER.size
            or program_count == 0
            or section_count == 0
            or section_names_index == 0
            or section_names_index >= section_count
        ):
            raise AnalyzerError("ELF header tables use an unsupported layout")
        self._checked_range(
            program_offset, program_count * program_entry_size, "program headers"
        )
        self._checked_range(
            section_offset, section_count * section_entry_size, "section headers"
        )

        segments = []
        for index in range(program_count):
            values = PROGRAM_HEADER.unpack_from(
                self.data, program_offset + index * program_entry_size
            )
            if values[0] != PT_LOAD:
                continue
            segment = Segment(
                offset=values[2],
                virtual_address=values[3],
                file_size=values[5],
                memory_size=values[6],
                flags=values[1],
            )
            self._checked_range(segment.offset, segment.file_size, "PT_LOAD data")
            if segment.file_size > segment.memory_size:
                raise AnalyzerError("ELF PT_LOAD file size exceeds memory size")
            segments.append(segment)
        if not segments:
            raise AnalyzerError("ELF has no PT_LOAD segments")
        self.segments = tuple(segments)

        raw_sections = [
            SECTION_HEADER.unpack_from(
                self.data, section_offset + index * section_entry_size
            )
            for index in range(section_count)
        ]
        names_header = raw_sections[section_names_index]
        self._checked_range(names_header[4], names_header[5], "section-name table")
        names = self.data[names_header[4] : names_header[4] + names_header[5]]

        parsed_sections = []
        by_name = {}
        for index, values in enumerate(raw_sections):
            name_offset = values[0]
            if name_offset >= len(names):
                raise AnalyzerError("ELF section name exceeds string table")
            name_end = names.find(b"\0", name_offset)
            if name_end < 0:
                raise AnalyzerError("ELF section name is not terminated")
            try:
                name = names[name_offset:name_end].decode("ascii")
            except UnicodeDecodeError as error:
                raise AnalyzerError("ELF section name is not ASCII") from error
            section = Section(
                index=index,
                name=name,
                section_type=values[1],
                flags=values[2],
                address=values[3],
                offset=values[4],
                size=values[5],
                link=values[6],
                entry_size=values[9],
            )
            if section.section_type != 8:  # SHT_NOBITS has no file bytes.
                self._checked_range(section.offset, section.size, f"section {name}")
            if name and name in by_name:
                raise AnalyzerError(f"ELF contains duplicate section {name}")
            if name:
                by_name[name] = section
            parsed_sections.append(section)
        self.sections = by_name
        self.sections_by_index = tuple(parsed_sections)

        self._validate_required_sections()
        self.build_id = self._read_build_id()

    def _require_section(
        self, name: str, section_type: int, required_flags: int = 0
    ) -> Section:
        section = self.sections.get(name)
        if section is None or section.section_type != section_type:
            raise AnalyzerError(f"ELF is missing required {name} section")
        if section.flags & required_flags != required_flags:
            raise AnalyzerError(f"ELF {name} section has invalid flags")
        return section

    def _validate_required_sections(self) -> None:
        text = self._require_section(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR)
        if text.flags & SHF_WRITE:
            raise AnalyzerError("ELF .text section is writable")
        init_array = self._require_section(
            ".init_array", SHT_INIT_ARRAY, SHF_ALLOC | SHF_WRITE
        )
        if init_array.flags & SHF_EXECINSTR or init_array.entry_size not in (0, 8):
            raise AnalyzerError("ELF .init_array section has invalid flags or stride")
        if (
            init_array.size == 0
            or init_array.size % 8 != 0
            or init_array.size // 8 > MAX_INIT_ARRAY_ENTRIES
        ):
            raise AnalyzerError("ELF .init_array size is invalid")
        self._require_section(".rela.dyn", SHT_ANDROID_RELA, SHF_ALLOC)
        dynsym = self._require_section(".dynsym", SHT_DYNSYM, SHF_ALLOC)
        self._require_section(".dynstr", SHT_STRTAB, SHF_ALLOC)
        self._require_section(".note.gnu.build-id", SHT_NOTE, SHF_ALLOC)
        self._require_section(".comment", SHT_PROGBITS)
        if dynsym.entry_size != SYMBOL_ENTRY.size:
            raise AnalyzerError("ELF .dynsym entry size is invalid")
        self.require_code_rva(text.address, text.size)
        self.require_writable_rva(init_array.address, init_array.size)

    def _read_build_id(self) -> str:
        section = self.sections[".note.gnu.build-id"]
        encoded = self.section_bytes(section)
        offset = 0
        matches = []
        while offset < len(encoded):
            if len(encoded) - offset < NOTE_HEADER.size:
                raise AnalyzerError("GNU Build ID note is truncated")
            name_size, descriptor_size, note_type = NOTE_HEADER.unpack_from(
                encoded, offset
            )
            offset += NOTE_HEADER.size
            name_end = offset + name_size
            descriptor_offset = (name_end + 3) & ~3
            descriptor_end = descriptor_offset + descriptor_size
            next_note = (descriptor_end + 3) & ~3
            if name_end > len(encoded) or next_note > len(encoded):
                raise AnalyzerError("GNU Build ID note exceeds section bounds")
            name = encoded[offset:name_end]
            descriptor = encoded[descriptor_offset:descriptor_end]
            if name == b"GNU\0" and note_type == 3:
                matches.append(descriptor)
            offset = next_note
        if len(matches) != 1 or len(matches[0]) != 20:
            raise AnalyzerError("ELF must contain one 20-byte GNU Build ID")
        return matches[0].hex()

    def segment_for_rva(self, rva: int, size: int = 1) -> Segment | None:
        matches = [
            segment for segment in self.segments if segment.contains_memory(rva, size)
        ]
        return matches[0] if len(matches) == 1 else None

    def require_code_rva(self, rva: int, size: int = 1) -> None:
        segment = self.segment_for_rva(rva, size)
        if (
            segment is None
            or segment.flags & (PF_READ | PF_EXECUTE) != (PF_READ | PF_EXECUTE)
            or segment.flags & PF_WRITE
            or not segment.contains_file_data(rva, size)
        ):
            raise AnalyzerError(f"RVA 0x{rva:x} is not in a read/execute segment")

    def require_writable_rva(self, rva: int, size: int = 1) -> None:
        segment = self.segment_for_rva(rva, size)
        if (
            segment is None
            or segment.flags & (PF_READ | PF_WRITE) != (PF_READ | PF_WRITE)
            or segment.flags & PF_EXECUTE
        ):
            raise AnalyzerError(f"RVA 0x{rva:x} is not in a non-executable RW segment")

    def rva_to_offset(self, rva: int, size: int = 1) -> int:
        matches = [
            segment
            for segment in self.segments
            if segment.contains_file_data(rva, size)
        ]
        if len(matches) != 1:
            raise AnalyzerError(f"RVA 0x{rva:x} has no unique file mapping")
        segment = matches[0]
        offset = segment.offset + rva - segment.virtual_address
        self._checked_range(offset, size, "RVA mapping")
        return offset

    def validate_toolchain(self) -> None:
        comment = self.section_bytes(self.sections[".comment"])
        for marker in PRIMARY_TOOLCHAIN_MARKERS:
            if marker not in comment:
                raise AnalyzerError(
                    "ELF compiler/linker family differs from the approved reference"
                )

    def exported_functions(self) -> dict[str, int]:
        dynsym = self.sections[".dynsym"]
        if dynsym.link >= len(self.sections_by_index):
            raise AnalyzerError("ELF .dynsym has an invalid string-table link")
        dynstr = self.sections_by_index[dynsym.link]
        if dynstr.name != ".dynstr" or dynstr.section_type != SHT_STRTAB:
            raise AnalyzerError("ELF .dynsym does not reference .dynstr")
        strings = self.section_bytes(dynstr)
        symbols = self.section_bytes(dynsym)
        if len(symbols) % SYMBOL_ENTRY.size != 0:
            raise AnalyzerError("ELF .dynsym has a truncated entry")
        result: dict[str, int] = {}
        for offset in range(0, len(symbols), SYMBOL_ENTRY.size):
            name_offset, info, _other, section_index, value, size = (
                SYMBOL_ENTRY.unpack_from(symbols, offset)
            )
            if name_offset >= len(strings):
                raise AnalyzerError("ELF dynamic symbol name exceeds .dynstr")
            name_end = strings.find(b"\0", name_offset)
            if name_end < 0:
                raise AnalyzerError("ELF dynamic symbol name is not terminated")
            symbol_type = info & 0x0F
            symbol_binding = info >> 4
            if symbol_type != 2 or symbol_binding not in (1, 2) or section_index == 0:
                continue
            try:
                name = strings[name_offset:name_end].decode("ascii")
            except UnicodeDecodeError as error:
                raise AnalyzerError("ELF dynamic symbol name is not ASCII") from error
            if not name:
                continue
            self.require_code_rva(value, max(1, min(size, 16)))
            if name in result and result[name] != value:
                raise AnalyzerError(f"ELF contains ambiguous export {name}")
            result[name] = value
        return result

    def init_array_relocations(self) -> tuple[int, ...]:
        init_array = self.sections[".init_array"]
        relocations = decode_aps2_relocations(
            self.section_bytes(self.sections[".rela.dyn"])
        )
        selected: dict[int, int] = {}
        end = init_array.address + init_array.size
        for relocation in relocations:
            if not init_array.address <= relocation.offset < end:
                continue
            if (
                relocation.offset % 8 != 0
                or relocation.info & 0xFFFFFFFF != R_X86_64_RELATIVE
                or relocation.info >> 32 != 0
            ):
                raise AnalyzerError(".init_array contains a non-relative relocation")
            index = (relocation.offset - init_array.address) // 8
            if index in selected:
                raise AnalyzerError(".init_array relocation is duplicated")
            self.require_code_rva(relocation.addend)
            selected[index] = relocation.addend
        count = init_array.size // 8
        if sorted(selected) != list(range(count)):
            raise AnalyzerError(".init_array is not fully covered by APS2 relocations")
        return tuple(selected[index] for index in range(count))


def decode_aps2_relocations(encoded: bytes) -> Iterator[Relocation]:
    if not encoded.startswith(b"APS2"):
        raise AnalyzerError(".rela.dyn does not use the required APS2 encoding")
    reader = Sleb128Reader(encoded[4:])
    relocation_count = reader.pop()
    relocation_offset = reader.pop()
    if relocation_count < 0 or relocation_count > MAX_RELOCATIONS:
        raise AnalyzerError("APS2 relocation count is invalid")
    relocation_info = 0
    relocation_addend = 0
    emitted = 0
    while emitted < relocation_count:
        group_size = reader.pop()
        group_flags = reader.pop()
        if (
            group_size <= 0
            or group_size > relocation_count - emitted
            or group_flags < 0
            or group_flags & ~0x0F
        ):
            raise AnalyzerError("APS2 relocation group is invalid")
        offset_delta = reader.pop() if group_flags & APS2_GROUPED_BY_OFFSET_DELTA else 0
        if group_flags & APS2_GROUPED_BY_INFO:
            relocation_info = reader.pop()
        addend_mode = group_flags & (APS2_GROUP_HAS_ADDEND | APS2_GROUPED_BY_ADDEND)
        if addend_mode == (APS2_GROUP_HAS_ADDEND | APS2_GROUPED_BY_ADDEND):
            relocation_addend += reader.pop()
        elif addend_mode != APS2_GROUP_HAS_ADDEND:
            relocation_addend = 0
        for _index in range(group_size):
            relocation_offset += (
                offset_delta
                if group_flags & APS2_GROUPED_BY_OFFSET_DELTA
                else reader.pop()
            )
            if not group_flags & APS2_GROUPED_BY_INFO:
                relocation_info = reader.pop()
            if addend_mode == APS2_GROUP_HAS_ADDEND:
                relocation_addend += reader.pop()
            if (
                relocation_offset < 0
                or relocation_info < 0
                or relocation_addend < 0
                or relocation_offset >= 1 << 64
                or relocation_info >= 1 << 64
                or relocation_addend >= 1 << 64
            ):
                raise AnalyzerError("APS2 relocation exceeds unsigned 64-bit bounds")
            emitted += 1
            yield Relocation(relocation_offset, relocation_info, relocation_addend)
    if not reader.at_end():
        raise AnalyzerError("APS2 relocation stream contains trailing bytes")


def require_capstone() -> None:
    if capstone is None or capstone_x86 is None:
        raise AnalyzerError(
            "Python capstone 5 is required for fail-closed HostAbi analysis"
        )
    try:
        version = capstone.cs_version()
    except (AttributeError, TypeError, ValueError) as error:
        raise AnalyzerError("Python capstone version cannot be verified") from error
    if (
        not isinstance(version, tuple)
        or len(version) < 2
        or not all(isinstance(component, int) for component in version[:2])
        or version[0] != 5
    ):
        raise AnalyzerError("Python capstone major version 5 is required")


def parse_rva(value: Any, description: str) -> int:
    if not isinstance(value, str) or RVA_PATTERN.fullmatch(value) is None:
        raise AnalyzerError(f"{description} must be a canonical nonzero hex RVA")
    return int(value, 16)


def format_rva(value: int) -> str:
    if value <= 0:
        raise AnalyzerError("cannot encode a zero or negative RVA")
    return f"0x{value:x}"


def read_json_object(path: Path, description: str) -> dict[str, Any]:
    try:
        file_status = os.lstat(path)
    except OSError as error:
        raise AnalyzerError(f"cannot stat {description}: {path}") from error
    if stat.S_ISLNK(file_status.st_mode) or not stat.S_ISREG(file_status.st_mode):
        raise AnalyzerError(f"{description} must be a regular non-symlink")
    if file_status.st_size <= 0 or file_status.st_size > MAX_JSON_BYTES:
        raise AnalyzerError(f"{description} has an invalid size")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AnalyzerError(f"cannot parse {description}") from error
    if not isinstance(value, dict):
        raise AnalyzerError(f"{description} must contain one JSON object")
    return value


def require_exact_keys(
    value: dict[str, Any], expected: set[str], description: str
) -> None:
    if set(value) != expected:
        raise AnalyzerError(f"{description} has unknown or missing fields")


def validated_sidecar(path: Path) -> dict[str, Any]:
    sidecar = read_json_object(path, "reference HostAbi sidecar")
    require_exact_keys(
        sidecar,
        {
            "schema_version",
            "elf_build_id",
            "payload_sha256",
            "payload_id",
            "payload_path",
            "reference",
            "profile",
            "derivation_anchors",
        },
        "reference HostAbi sidecar",
    )
    build_id = sidecar.get("elf_build_id")
    payload_sha256 = sidecar.get("payload_sha256")
    payload_id = sidecar.get("payload_id")
    payload_path = sidecar.get("payload_path")
    profile = sidecar.get("profile")
    anchors = sidecar.get("derivation_anchors")
    reference = sidecar.get("reference")
    if sidecar.get("schema_version") != 1:
        raise AnalyzerError("reference HostAbi sidecar schema is unsupported")
    if (
        not isinstance(build_id, str)
        or ELF_BUILD_ID_PATTERN.fullmatch(build_id) is None
    ):
        raise AnalyzerError("reference sidecar ELF Build ID is invalid")
    if (
        not isinstance(payload_sha256, str)
        or SHA256_PATTERN.fullmatch(payload_sha256) is None
    ):
        raise AnalyzerError("reference sidecar payload SHA-256 is invalid")
    if (
        not isinstance(payload_id, str)
        or PAYLOAD_ID_PATTERN.fullmatch(payload_id) is None
    ):
        raise AnalyzerError("reference sidecar payload ID is invalid")
    if (
        payload_id.split("-", 1)[1] != build_id
        or payload_path != f"payloads/{payload_id}"
    ):
        raise AnalyzerError("reference sidecar payload identity is inconsistent")
    if not isinstance(profile, dict) or profile.get("elf_build_id") != build_id:
        raise AnalyzerError("reference sidecar profile identity is inconsistent")
    if not isinstance(anchors, dict) or anchors.get("signature_version") != 1:
        raise AnalyzerError("reference sidecar derivation anchors are unavailable")
    if not isinstance(reference, dict):
        raise AnalyzerError("reference sidecar provenance is unavailable")
    require_exact_keys(
        reference,
        {"elf_build_id", "payload_sha256"},
        "reference sidecar provenance",
    )
    if (
        not isinstance(reference.get("elf_build_id"), str)
        or ELF_BUILD_ID_PATTERN.fullmatch(reference["elf_build_id"]) is None
        or not isinstance(reference.get("payload_sha256"), str)
        or SHA256_PATTERN.fullmatch(reference["payload_sha256"]) is None
        or reference["elf_build_id"] == build_id
        or reference["payload_sha256"] == payload_sha256
    ):
        raise AnalyzerError("reference sidecar provenance identity is invalid")
    validate_profile_shape(profile, anchors)
    return sidecar


def require_positive_integer(value: Any, description: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise AnalyzerError(f"{description} must be a positive integer")
    return value


def validated_ranges(value: Any, description: str, count: int) -> list[dict[str, int]]:
    if not isinstance(value, list) or not value:
        raise AnalyzerError(f"{description} must contain constructor ranges")
    previous_end = 0
    result = []
    for item in value:
        if not isinstance(item, dict):
            raise AnalyzerError(f"{description} contains a non-object range")
        require_exact_keys(item, {"begin", "end_exclusive"}, description)
        begin = item.get("begin")
        end = item.get("end_exclusive")
        if (
            not isinstance(begin, int)
            or isinstance(begin, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or begin < 0
            or begin >= end
            or end > count
            or begin < previous_end
        ):
            raise AnalyzerError(f"{description} contains an invalid range")
        previous_end = end
        result.append({"begin": begin, "end_exclusive": end})
    return result


def validate_profile_shape(profile: dict[str, Any], anchors: dict[str, Any]) -> None:
    require_exact_keys(
        profile,
        {
            "elf_build_id",
            "bridge_entries",
            "data_seeds",
            "native_allocator",
            "init_array_offset",
            "init_array_count",
            "constructor_run_ranges",
            "native_mimalloc_constructor_run_ranges",
            "native_mimalloc_thread_initializer_after_constructor",
            "native_pre_jni_bootstrap",
            "default_allocator_strategy",
        },
        "reference profile",
    )
    require_exact_keys(
        anchors,
        {
            "signature_version",
            "allocator_object_initializer_rva",
            "empty_string_initializer_rva",
            "jni_singleton_initializer_rva",
            "constructor_rvas",
        },
        "reference derivation anchors",
    )
    bridge_entries = profile.get("bridge_entries")
    if not isinstance(bridge_entries, list) or len(bridge_entries) != 6:
        raise AnalyzerError("reference profile must contain six allocator bridges")
    required_bridge_labels = {
        "small-allocate": "allocate",
        "usable-size": "usable_size",
        "reallocate": "reallocate",
        "allocate": "allocate",
        "aligned-allocate-direct": "aligned_allocate",
        "free": "free",
    }
    seen_labels = set()
    seen_rvas = set()
    for entry in bridge_entries:
        if not isinstance(entry, dict):
            raise AnalyzerError("reference bridge entry must be an object")
        require_exact_keys(entry, {"rva", "kind", "label"}, "reference bridge")
        label = entry.get("label")
        if (
            label not in required_bridge_labels
            or entry.get("kind") != required_bridge_labels[label]
        ):
            raise AnalyzerError("reference bridge entry kind/label is invalid")
        rva = parse_rva(entry.get("rva"), f"bridge {label}")
        seen_labels.add(label)
        seen_rvas.add(rva)
    if seen_labels != set(required_bridge_labels):
        raise AnalyzerError("reference bridge labels are incomplete")
    if len(seen_rvas) != len(bridge_entries):
        raise AnalyzerError("reference bridge RVAs are not unique")

    data_seeds = profile.get("data_seeds")
    if not isinstance(data_seeds, dict):
        raise AnalyzerError("reference data seeds are unavailable")
    require_exact_keys(
        data_seeds,
        {
            "allocator_object_slot",
            "empty_string_slot",
            "jni_singleton_slot",
            "jni_singleton_bytes",
            "arena_initializer",
            "allocator_thread_initializer",
            "arena_guard_slot",
            "arena_table_slot",
            "arena_table_slot_count",
        },
        "reference data seeds",
    )
    for name in (
        "allocator_object_slot",
        "empty_string_slot",
        "jni_singleton_slot",
        "arena_initializer",
        "allocator_thread_initializer",
        "arena_guard_slot",
        "arena_table_slot",
    ):
        parse_rva(data_seeds.get(name), f"data seed {name}")
    require_positive_integer(
        data_seeds.get("jni_singleton_bytes"), "JNI singleton size"
    )
    require_positive_integer(
        data_seeds.get("arena_table_slot_count"), "arena slot count"
    )

    native_allocator = profile.get("native_allocator")
    if not isinstance(native_allocator, dict):
        raise AnalyzerError("reference native allocator is unavailable")
    require_exact_keys(
        native_allocator,
        {"allocate", "deallocate"},
        "reference native allocator",
    )
    parse_rva(native_allocator.get("allocate"), "native allocator allocate")
    parse_rva(native_allocator.get("deallocate"), "native allocator deallocate")
    init_count = require_positive_integer(
        profile.get("init_array_count"), "init-array count"
    )
    parse_rva(profile.get("init_array_offset"), "init-array offset")
    validated_ranges(
        profile.get("constructor_run_ranges"), "constructor ranges", init_count
    )
    validated_ranges(
        profile.get("native_mimalloc_constructor_run_ranges"),
        "native mimalloc constructor ranges",
        init_count,
    )
    thread_index = profile.get("native_mimalloc_thread_initializer_after_constructor")
    if (
        not isinstance(thread_index, int)
        or isinstance(thread_index, bool)
        or not 0 <= thread_index < init_count
    ):
        raise AnalyzerError("reference native mimalloc thread boundary is invalid")
    bootstrap = profile.get("native_pre_jni_bootstrap")
    if not isinstance(bootstrap, dict):
        raise AnalyzerError("reference native pre-JNI bootstrap is unavailable")
    require_exact_keys(
        bootstrap,
        {"registry_initializer", "registry_slot"},
        "reference native pre-JNI bootstrap",
    )
    parse_rva(bootstrap.get("registry_initializer"), "registry initializer")
    parse_rva(bootstrap.get("registry_slot"), "registry slot")
    if profile.get("default_allocator_strategy") != "native_mimalloc":
        raise AnalyzerError("reference profile must retain native mimalloc")

    for name in (
        "allocator_object_initializer_rva",
        "empty_string_initializer_rva",
        "jni_singleton_initializer_rva",
    ):
        parse_rva(anchors.get(name), f"derivation anchor {name}")
    constructor_rvas = anchors.get("constructor_rvas")
    if not isinstance(constructor_rvas, dict) or set(constructor_rvas) != {
        "2",
        "3",
        "4",
        "5",
    }:
        raise AnalyzerError("reference constructor derivation anchors are incomplete")
    for index, value in constructor_rvas.items():
        parse_rva(value, f"constructor {index} anchor")


def validated_payload_metadata(
    path: Path, candidate_path: Path, candidate: ElfImage
) -> dict[str, Any]:
    metadata = read_json_object(path, "payload metadata")
    if path.parent.resolve() != candidate_path.parent.resolve():
        raise AnalyzerError("payload metadata and candidate ELF must share a directory")
    version_name = metadata.get("version_name")
    version_code = metadata.get("version_code")
    build_id = metadata.get("elf_build_id")
    sha = metadata.get("sha256")
    expected_sha = sha.get("libroblox") if isinstance(sha, dict) else None
    if (
        metadata.get("schema_version") != 1
        or metadata.get("package") != "com.roblox.client"
        or metadata.get("abi") != "x86_64"
        or not isinstance(version_name, str)
        or not version_name
        or not isinstance(version_code, int)
        or isinstance(version_code, bool)
        or version_code <= 0
        or not isinstance(build_id, str)
        or ELF_BUILD_ID_PATTERN.fullmatch(build_id) is None
        or not isinstance(expected_sha, str)
        or SHA256_PATTERN.fullmatch(expected_sha) is None
    ):
        raise AnalyzerError("payload metadata identity is incomplete or invalid")
    if build_id != candidate.build_id or expected_sha != candidate.sha256:
        raise AnalyzerError("payload metadata does not match candidate ELF bytes")
    payload_id = f"{version_code}-{build_id}"
    if candidate_path.parent.name != payload_id:
        raise AnalyzerError("candidate ELF parent is not the canonical payload ID")
    return metadata


def disassemble(image: ElfImage, rva: int, instruction_count: int) -> tuple[Any, ...]:
    require_capstone()
    if instruction_count <= 0 or instruction_count > 256:
        raise AnalyzerError("signature instruction count is invalid")
    image.require_code_rva(rva)
    offset = image.rva_to_offset(rva)
    available = min(4096, image.file_size - offset)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    instructions = tuple(
        decoder.disasm(image.bytes_at(offset, available, "code signature"), rva)
    )[:instruction_count]
    if len(instructions) != instruction_count or instructions[0].address != rva:
        raise AnalyzerError(
            f"cannot decode {instruction_count} instructions at 0x{rva:x}"
        )
    expected_address = rva
    for instruction in instructions:
        if instruction.address != expected_address or instruction.size <= 0:
            raise AnalyzerError(f"non-contiguous instruction signature at 0x{rva:x}")
        expected_address += instruction.size
    image.require_code_rva(rva, expected_address - rva)
    return instructions


def signature_bytes(
    image: ElfImage, rva: int, instructions: Sequence[Any]
) -> tuple[bytes, bytes]:
    end = instructions[-1].address + instructions[-1].size
    offset = image.rva_to_offset(rva, end - rva)
    encoded = bytearray(image.bytes_at(offset, end - rva, "code signature"))
    mask = bytearray(b"\x01" * len(encoded))
    for instruction in instructions:
        base = instruction.address - rva
        for operand_offset, operand_size in (
            (instruction.imm_offset, instruction.imm_size),
            (instruction.disp_offset, instruction.disp_size),
        ):
            if operand_size == 0:
                continue
            if operand_offset <= 0 or operand_offset + operand_size > instruction.size:
                raise AnalyzerError(
                    "Capstone returned an invalid operand encoding range"
                )
            for index in range(operand_offset, operand_offset + operand_size):
                mask[base + index] = 0
    return bytes(encoded), bytes(mask)


def longest_fixed_anchor(
    encoded: bytes, mask: bytes, minimum_bytes: int = 6
) -> tuple[int, bytes]:
    best_offset = -1
    best = b""
    start = None
    for index, enabled in enumerate(mask + b"\x00"):
        if enabled and start is None:
            start = index
        elif not enabled and start is not None:
            if index - start > len(best):
                best_offset = start
                best = encoded[start:index]
            start = None
    if best_offset < 0 or len(best) < minimum_bytes:
        raise AnalyzerError("normalized signature has no selective fixed anchor")
    return best_offset, best


def semantic_operand(
    instruction: Any, operand: Any, wildcard_size: bool
) -> tuple[Any, ...]:
    if operand.type == capstone_x86.X86_OP_REG:
        return ("reg", instruction.reg_name(operand.reg), operand.size)
    if operand.type == capstone_x86.X86_OP_IMM:
        is_control_flow = instruction.group(capstone.CS_GRP_CALL) or instruction.group(
            capstone.CS_GRP_JUMP
        )
        if is_control_flow:
            value: Any = "control-flow-target"
        elif wildcard_size:
            value = "registry-object-size"
        else:
            value = operand.imm
        return ("imm", value, operand.size)
    if operand.type == capstone_x86.X86_OP_MEM:
        memory = operand.mem
        base = instruction.reg_name(memory.base) if memory.base else ""
        index = instruction.reg_name(memory.index) if memory.index else ""
        displacement: Any = (
            "rip-target" if memory.base == capstone_x86.X86_REG_RIP else memory.disp
        )
        return (
            "mem",
            instruction.reg_name(memory.segment) if memory.segment else "",
            base,
            index,
            memory.scale,
            displacement,
            operand.size,
        )
    raise AnalyzerError("normalized signature contains an unsupported operand")


def semantic_shape(
    instruction: Any, wildcard_registry_object_size: bool = False
) -> tuple[Any, ...]:
    return (
        instruction.mnemonic,
        tuple(
            semantic_operand(instruction, operand, wildcard_registry_object_size)
            for operand in instruction.operands
        ),
    )


def validate_semantic_match(
    reference: Sequence[Any],
    candidate: Sequence[Any],
    allow_registry_object_size_change: bool,
) -> None:
    if len(reference) != len(candidate):
        raise AnalyzerError("normalized signature instruction count changed")
    for index, (reference_instruction, candidate_instruction) in enumerate(
        zip(reference, candidate)
    ):
        wildcard_size = allow_registry_object_size_change and index in (8, 12)
        if semantic_shape(reference_instruction, wildcard_size) != semantic_shape(
            candidate_instruction, wildcard_size
        ):
            raise AnalyzerError(
                f"normalized instruction semantics changed at signature index {index}"
            )
    if allow_registry_object_size_change:
        sizes = []
        for index in (8, 12):
            operands = candidate[index].operands
            if len(operands) != 2 or operands[1].type != capstone_x86.X86_OP_IMM:
                raise AnalyzerError("registry initializer size operands changed")
            sizes.append(operands[1].imm)
        if (
            sizes[0] != sizes[1]
            or sizes[0] < 0x100
            or sizes[0] > 0x1000
            or sizes[0] % 8
        ):
            raise AnalyzerError("registry initializer object size is inconsistent")


def find_signature_match(
    reference: ElfImage, candidate: ElfImage, spec: SignatureSpec
) -> SignatureMatch:
    reference_instructions = disassemble(
        reference, spec.reference_rva, spec.instruction_count
    )
    encoded, mask = signature_bytes(
        reference, spec.reference_rva, reference_instructions
    )
    anchor_offset, anchor = longest_fixed_anchor(
        encoded, mask, spec.minimum_anchor_bytes
    )
    text = candidate.sections[".text"]
    text_begin = text.offset
    text_end = text.offset + text.size
    matches = []
    search_offset = text_begin
    while True:
        anchor_position = candidate.data.find(anchor, search_offset, text_end)
        if anchor_position < 0:
            break
        signature_offset = anchor_position - anchor_offset
        if (
            text_begin <= signature_offset
            and signature_offset + len(encoded) <= text_end
        ):
            candidate_bytes = candidate.data[
                signature_offset : signature_offset + len(encoded)
            ]
            if all(
                not mask[index] or candidate_bytes[index] == encoded[index]
                for index in range(len(encoded))
            ):
                segment = candidate.segment_for_rva(
                    text.address + signature_offset - text.offset, len(encoded)
                )
                if (
                    segment is not None
                    and segment.flags & PF_EXECUTE
                    and not segment.flags & PF_WRITE
                ):
                    matches.append(signature_offset)
        search_offset = anchor_position + 1
    if len(matches) != 1:
        raise AnalyzerError(
            f"signature {spec.name} matched {len(matches)} candidate locations"
        )
    match_rva = text.address + matches[0] - text.offset
    candidate_instructions = disassemble(candidate, match_rva, spec.instruction_count)
    validate_semantic_match(
        reference_instructions,
        candidate_instructions,
        spec.allow_registry_object_size_change,
    )
    return SignatureMatch(match_rva, reference_instructions, candidate_instructions)


def rip_targets(instruction: Any) -> tuple[int, ...]:
    targets = []
    for operand in instruction.operands:
        if (
            operand.type == capstone_x86.X86_OP_MEM
            and operand.mem.base == capstone_x86.X86_REG_RIP
        ):
            targets.append(instruction.address + instruction.size + operand.mem.disp)
    return tuple(targets)


def mapped_rip_target(
    match: SignatureMatch, reference_target: int, description: str
) -> int:
    candidate_targets = []
    for reference_instruction, candidate_instruction in zip(
        match.reference_instructions, match.candidate_instructions
    ):
        if reference_target in rip_targets(reference_instruction):
            targets = rip_targets(candidate_instruction)
            if len(targets) != len(rip_targets(reference_instruction)):
                raise AnalyzerError(f"{description} RIP-relative operand count changed")
            reference_positions = [
                index
                for index, target in enumerate(rip_targets(reference_instruction))
                if target == reference_target
            ]
            candidate_targets.extend(targets[index] for index in reference_positions)
    if not candidate_targets or len(set(candidate_targets)) != 1:
        raise AnalyzerError(f"{description} has no unique mapped RIP target")
    return candidate_targets[0]


def derive_registry_slot(candidate: ElfImage, initializer_rva: int) -> int:
    # The initializer publishes its newly allocated registry immediately
    # before its first return. Do not infer that slot from adjacent functions:
    # future link layouts may place unrelated registry users after this body.
    candidate.require_code_rva(initializer_rva)
    offset = candidate.rva_to_offset(initializer_rva)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    window = candidate.bytes_at(
        offset,
        min(REGISTRY_INITIALIZER_MAX_BYTES, candidate.file_size - offset),
        "registry initializer",
    )
    stores = []
    expected_address = initializer_rva
    found_return = False
    for instruction in decoder.disasm(window, initializer_rva):
        if instruction.address != expected_address or instruction.size <= 0:
            raise AnalyzerError("registry initializer disassembly is not contiguous")
        expected_address += instruction.size
        operands = instruction.operands
        if (
            instruction.mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == capstone_x86.X86_OP_MEM
            and operands[0].mem.base == capstone_x86.X86_REG_RIP
            and operands[0].size == 8
            and operands[1].type == capstone_x86.X86_OP_REG
            and operands[1].reg == capstone_x86.X86_REG_RBX
        ):
            stores.append(instruction.address + instruction.size + operands[0].mem.disp)
        if instruction.group(capstone.CS_GRP_RET):
            found_return = True
            break
    if not found_return:
        raise AnalyzerError("pre-JNI registry initializer has no bounded return")
    if len(stores) != 1:
        raise AnalyzerError(
            "pre-JNI registry initializer does not publish one unique slot"
        )
    slot = stores[0]
    if slot % 8:
        raise AnalyzerError("pre-JNI registry slot is not pointer-aligned")
    candidate.require_writable_rva(slot, 8)
    return slot


def validate_reference_registry_slot(
    reference: ElfImage, bootstrap: dict[str, Any]
) -> None:
    initializer = parse_rva(
        bootstrap["registry_initializer"], "reference registry initializer"
    )
    expected_slot = parse_rva(bootstrap["registry_slot"], "reference registry slot")
    if derive_registry_slot(reference, initializer) != expected_slot:
        raise AnalyzerError(
            "reference registry slot does not match its ELF initializer"
        )


def bridge_map(profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["label"]: entry for entry in profile["bridge_entries"]}


def create_signature_specs(
    profile: dict[str, Any], anchors: dict[str, Any]
) -> list[SignatureSpec]:
    bridges = bridge_map(profile)
    data_seeds = profile["data_seeds"]
    bootstrap = profile["native_pre_jni_bootstrap"]
    constructor_rvas = anchors["constructor_rvas"]
    return [
        SignatureSpec(
            "small-allocate",
            parse_rva(bridges["small-allocate"]["rva"], "small allocate"),
            24,
        ),
        SignatureSpec(
            "usable-size", parse_rva(bridges["usable-size"]["rva"], "usable size"), 24
        ),
        SignatureSpec(
            "reallocate", parse_rva(bridges["reallocate"]["rva"], "reallocate"), 24
        ),
        SignatureSpec(
            "allocate", parse_rva(bridges["allocate"]["rva"], "allocate"), 24
        ),
        SignatureSpec(
            "aligned-allocate-direct",
            parse_rva(bridges["aligned-allocate-direct"]["rva"], "aligned allocate"),
            24,
        ),
        SignatureSpec("free", parse_rva(bridges["free"]["rva"], "free"), 24),
        SignatureSpec(
            "arena-initializer",
            parse_rva(data_seeds["arena_initializer"], "arena initializer"),
            24,
        ),
        SignatureSpec(
            "allocator-thread-initializer",
            parse_rva(data_seeds["allocator_thread_initializer"], "thread initializer"),
            24,
        ),
        SignatureSpec(
            "registry-initializer",
            parse_rva(bootstrap["registry_initializer"], "registry initializer"),
            20,
            True,
        ),
        SignatureSpec(
            "allocator-object-initializer",
            parse_rva(
                anchors["allocator_object_initializer_rva"], "allocator object anchor"
            ),
            19,
        ),
        SignatureSpec(
            "empty-string-initializer",
            parse_rva(anchors["empty_string_initializer_rva"], "empty string anchor"),
            23,
        ),
        SignatureSpec(
            "jni-singleton-initializer",
            parse_rva(anchors["jni_singleton_initializer_rva"], "JNI singleton anchor"),
            11,
        ),
        SignatureSpec(
            "constructor-2", parse_rva(constructor_rvas["2"], "constructor 2"), 24
        ),
        SignatureSpec(
            "constructor-3", parse_rva(constructor_rvas["3"], "constructor 3"), 24
        ),
        SignatureSpec(
            "constructor-4",
            parse_rva(constructor_rvas["4"], "constructor 4"),
            24,
            minimum_anchor_bytes=3,
        ),
    ]


def adjusted_ranges(
    ranges: list[dict[str, int]], reference_count: int, candidate_count: int
) -> list[dict[str, int]]:
    result = []
    for item in ranges:
        end = (
            candidate_count
            if item["end_exclusive"] == reference_count
            else item["end_exclusive"]
        )
        if end > candidate_count:
            raise AnalyzerError(
                "reference constructor range cannot fit candidate init-array"
            )
        result.append({"begin": item["begin"], "end_exclusive": end})
    return validated_ranges(result, "derived constructor ranges", candidate_count)


def derive_profile(
    reference: ElfImage,
    candidate: ElfImage,
    reference_sidecar: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    require_capstone()
    if (
        reference.build_id != reference_sidecar["elf_build_id"]
        or reference.sha256 != reference_sidecar["payload_sha256"]
    ):
        raise AnalyzerError(
            "reference ELF bytes do not match the exact sidecar identity"
        )
    if candidate.build_id == reference.build_id or candidate.sha256 == reference.sha256:
        raise AnalyzerError("candidate must be a distinct Roblox payload")
    reference.validate_toolchain()
    candidate.validate_toolchain()
    missing_exports = REQUIRED_EXPORTS - candidate.exported_functions().keys()
    if missing_exports:
        raise AnalyzerError(
            "candidate is missing required JNI exports: "
            + ", ".join(sorted(missing_exports))
        )

    reference_profile = reference_sidecar["profile"]
    anchors = reference_sidecar["derivation_anchors"]
    matches = {
        spec.name: find_signature_match(reference, candidate, spec)
        for spec in create_signature_specs(reference_profile, anchors)
    }
    reference_init = reference.init_array_relocations()
    candidate_init = candidate.init_array_relocations()
    if len(reference_init) != reference_profile["init_array_count"]:
        raise AnalyzerError(
            "reference sidecar init-array count differs from ELF metadata"
        )
    if len(candidate_init) < 8:
        raise AnalyzerError("candidate init-array is unexpectedly short")
    for index in (2, 3, 4):
        match = matches[f"constructor-{index}"]
        if (
            reference_init[index] != match.reference_instructions[0].address
            or candidate_init[index] != match.rva
        ):
            raise AnalyzerError(
                f"constructor {index} moved outside its verified init-array boundary"
            )
    singleton_match = matches["jni-singleton-initializer"]
    if (
        reference_init[5] != singleton_match.reference_instructions[0].address
        or candidate_init[5] != singleton_match.rva
    ):
        raise AnalyzerError("JNI singleton initializer is not constructor index 5")

    candidate_bridge_entries = []
    for entry in reference_profile["bridge_entries"]:
        candidate_bridge_entries.append(
            {
                "rva": format_rva(matches[entry["label"]].rva),
                "kind": entry["kind"],
                "label": entry["label"],
            }
        )
    candidate_bridge_map = {entry["label"]: entry for entry in candidate_bridge_entries}

    reference_seeds = reference_profile["data_seeds"]
    allocator_slot = mapped_rip_target(
        matches["allocator-object-initializer"],
        parse_rva(reference_seeds["allocator_object_slot"], "allocator object slot"),
        "allocator object slot",
    )
    empty_string_slot = mapped_rip_target(
        matches["empty-string-initializer"],
        parse_rva(reference_seeds["empty_string_slot"], "empty string slot"),
        "empty string slot",
    )
    jni_singleton_slot = mapped_rip_target(
        matches["jni-singleton-initializer"],
        parse_rva(reference_seeds["jni_singleton_slot"], "JNI singleton slot"),
        "JNI singleton slot",
    )
    arena_guard_slot = mapped_rip_target(
        matches["arena-initializer"],
        parse_rva(reference_seeds["arena_guard_slot"], "arena guard slot"),
        "arena guard slot",
    )
    arena_table_slot = mapped_rip_target(
        matches["usable-size"],
        parse_rva(reference_seeds["arena_table_slot"], "arena table slot"),
        "arena table slot",
    )
    for slot in (
        allocator_slot,
        empty_string_slot,
        jni_singleton_slot,
        arena_guard_slot,
        arena_table_slot,
    ):
        candidate.require_writable_rva(slot, 8)

    validate_reference_registry_slot(
        reference, reference_profile["native_pre_jni_bootstrap"]
    )

    registry_initializer = matches["registry-initializer"].rva
    registry_slot = derive_registry_slot(candidate, registry_initializer)
    allocate_rva = parse_rva(
        candidate_bridge_map["allocate"]["rva"], "derived allocate"
    )
    free_rva = parse_rva(candidate_bridge_map["free"]["rva"], "derived free")
    registry_call = matches["registry-initializer"].candidate_instructions[9]
    if (
        len(registry_call.operands) != 1
        or registry_call.operands[0].type != capstone_x86.X86_OP_IMM
        or registry_call.operands[0].imm != allocate_rva
    ):
        raise AnalyzerError(
            "registry initializer no longer calls the derived native allocator"
        )

    init_section = candidate.sections[".init_array"]
    reference_count = reference_profile["init_array_count"]
    candidate_count = len(candidate_init)
    constructor_ranges = adjusted_ranges(
        validated_ranges(
            reference_profile["constructor_run_ranges"],
            "reference constructor ranges",
            reference_count,
        ),
        reference_count,
        candidate_count,
    )
    native_ranges = adjusted_ranges(
        validated_ranges(
            reference_profile["native_mimalloc_constructor_run_ranges"],
            "reference native constructor ranges",
            reference_count,
        ),
        reference_count,
        candidate_count,
    )
    thread_boundary = reference_profile[
        "native_mimalloc_thread_initializer_after_constructor"
    ]
    if thread_boundary != 2 or not any(
        item["begin"] <= thread_boundary < item["end_exclusive"]
        for item in native_ranges
    ):
        raise AnalyzerError("native allocator TLS boundary is no longer verified")

    profile = {
        "elf_build_id": candidate.build_id,
        "bridge_entries": candidate_bridge_entries,
        "data_seeds": {
            "allocator_object_slot": format_rva(allocator_slot),
            "empty_string_slot": format_rva(empty_string_slot),
            "jni_singleton_slot": format_rva(jni_singleton_slot),
            "jni_singleton_bytes": reference_seeds["jni_singleton_bytes"],
            "arena_initializer": format_rva(matches["arena-initializer"].rva),
            "allocator_thread_initializer": format_rva(
                matches["allocator-thread-initializer"].rva
            ),
            "arena_guard_slot": format_rva(arena_guard_slot),
            "arena_table_slot": format_rva(arena_table_slot),
            "arena_table_slot_count": reference_seeds["arena_table_slot_count"],
        },
        "native_allocator": {
            "allocate": format_rva(allocate_rva),
            "deallocate": format_rva(free_rva),
        },
        "init_array_offset": format_rva(init_section.address),
        "init_array_count": candidate_count,
        "constructor_run_ranges": constructor_ranges,
        "native_mimalloc_constructor_run_ranges": native_ranges,
        "native_mimalloc_thread_initializer_after_constructor": thread_boundary,
        "native_pre_jni_bootstrap": {
            "registry_initializer": format_rva(registry_initializer),
            "registry_slot": format_rva(registry_slot),
        },
        "default_allocator_strategy": "native_mimalloc",
    }
    derived_anchors = {
        "signature_version": 1,
        "allocator_object_initializer_rva": format_rva(
            matches["allocator-object-initializer"].rva
        ),
        "empty_string_initializer_rva": format_rva(
            matches["empty-string-initializer"].rva
        ),
        "jni_singleton_initializer_rva": format_rva(singleton_match.rva),
        "constructor_rvas": {
            "2": format_rva(candidate_init[2]),
            "3": format_rva(candidate_init[3]),
            "4": format_rva(candidate_init[4]),
            "5": format_rva(candidate_init[5]),
        },
    }
    validate_profile_shape(profile, derived_anchors)
    return profile, derived_anchors


def output_documents(
    candidate: ElfImage,
    metadata: dict[str, Any],
    reference_sidecar: dict[str, Any],
    profile: dict[str, Any],
    anchors: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    version_code = metadata["version_code"]
    payload_id = f"{version_code}-{candidate.build_id}"
    sidecar = {
        "schema_version": 1,
        "elf_build_id": candidate.build_id,
        "payload_sha256": candidate.sha256,
        "payload_id": payload_id,
        "payload_path": f"payloads/{payload_id}",
        "reference": {
            "elf_build_id": reference_sidecar["elf_build_id"],
            "payload_sha256": reference_sidecar["payload_sha256"],
        },
        "profile": profile,
        "derivation_anchors": anchors,
    }
    manifest = {
        "schema_version": 1,
        "profiles": [
            {
                "version_name": metadata["version_name"],
                "version_code": version_code,
                "elf_build_id": candidate.build_id,
                "status": "experimental",
                "default_allowed": True,
                "allow_legacy_binary_patches": False,
                "allow_host_abi_bridges": True,
                "allow_host_constructor_replay": True,
                "reason": (
                    "Machine-derived exact-Build-ID profile for isolated "
                    "probation only; it is not supported until the updater "
                    "records a successful no-recovery Tier C canary."
                ),
            }
        ],
    }
    return sidecar, manifest


def encode_json(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_json_atomic(destination: str, document: dict[str, Any]) -> None:
    encoded = encode_json(document)
    if destination == "-":
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
        return
    path = Path(destination)
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise AnalyzerError(f"output parent must be a non-symlink directory: {parent}")
    temporary_path = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=parent
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    except OSError as error:
        raise AnalyzerError(f"cannot atomically write output: {path}") from error
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def analyze(arguments: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    reference_path = Path(arguments.reference_lib)
    candidate_path = Path(arguments.candidate_lib)
    metadata_path = Path(arguments.payload_metadata)
    sidecar_path = Path(arguments.reference_profile)
    reference_sidecar = validated_sidecar(sidecar_path)
    with ElfImage(reference_path) as reference, ElfImage(candidate_path) as candidate:
        metadata = validated_payload_metadata(metadata_path, candidate_path, candidate)
        profile, anchors = derive_profile(reference, candidate, reference_sidecar)
        return output_documents(
            candidate, metadata, reference_sidecar, profile, anchors
        )


def parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Derive an exact experimental Roblox HostAbi sidecar for isolated probation"
        )
    )
    parser.add_argument("--reference-lib", required=True, metavar="REF")
    parser.add_argument("--reference-profile", required=True, metavar="REFJSON")
    parser.add_argument("--candidate-lib", required=True, metavar="LIB")
    parser.add_argument("--payload-metadata", required=True, metavar="META")
    parser.add_argument("--output", required=True, metavar="PROFILE")
    parser.add_argument("--compatibility-output", required=True, metavar="MANIFEST")
    arguments = parser.parse_args(argv)
    if arguments.output == "-" and arguments.compatibility_output == "-":
        parser.error("only one output may use stdout")
    if (
        arguments.output != "-"
        and arguments.compatibility_output != "-"
        and Path(arguments.output).resolve()
        == Path(arguments.compatibility_output).resolve()
    ):
        parser.error("profile and compatibility outputs must differ")
    return arguments


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        sidecar, manifest = analyze(arguments)
        write_json_atomic(arguments.output, sidecar)
        write_json_atomic(arguments.compatibility_output, manifest)
    except AnalyzerError as error:
        print(f"derive-host-abi-profile: error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
