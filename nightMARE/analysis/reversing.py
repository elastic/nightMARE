# coding: utf-8

from __future__ import annotations

import typing
import tempfile
import pathlib
import secrets
import enum
import hashlib

import r2pipe

from nightMARE.core import cast

CACHE: dict[str, Radare2] = {}


class Radare2:
    class PatternType(enum.Enum):
        STRING_PATTERN = enum.auto()
        WIDE_STRING_PATTERN = enum.auto()
        HEX_PATTERN = enum.auto()

    def __del__(self):
        if self.__is_r2_loaded:
            self.__radare.cmd("o--")
            self.__tmp_binary_path.unlink()

    def __do_analysis(self) -> None:
        if not self.__is_analyzed:
            self.__radare.cmd("aaa")
            self.__is_analyzed = True

    def __load_r2(self) -> None:
        if not self.__is_r2_loaded:
            self.__tmp_binary_path.write_bytes(self.__binary)
            self.__radare = r2pipe.open(str(self.__tmp_binary_path))
            self.__is_r2_loaded = True

    def __init__(self, binary: bytes):
        self.__binary = binary
        self.__file_info: dict[str, typing.Any] = {}
        self.__is_r2_loaded = False
        self.__is_analyzed = False
        self.__tmp_binary_path = pathlib.Path(tempfile.gettempdir()).joinpath(
            secrets.token_hex(24)
        )

    def disassemble(self, offset: int, size: int) -> list[dict[str, typing.Any]]:
        self.__load_r2()
        return self.__radare.cmdj(f"aoj {size} @{offset}")

    def disassemble_previous_instruction(self, offset: int) -> dict[str, typing.Any]:
        self.__load_r2()
        return self.disassemble(self.get_previous_instruction_offset(offset), 1)[0]

    def disassemble_next_instruction(self, offset: int) -> dict[str, typing.Any]:
        self.__load_r2()
        return self.disassemble(self.get_next_instruction_offset(offset), 1)[0]

    @property
    def file_info(self) -> dict[str, typing.Any]:
        self.__load_r2()
        if not self.__file_info:
            self.__file_info = self.__radare.cmdj("ij")
        return self.__file_info

    def find_pattern(
        self, pattern: str, pattern_type: Radare2.PatternType
    ) -> typing.Iterable[int]:
        self.__load_r2()
        match pattern_type:
            case Radare2.PatternType.STRING_PATTERN:
                return self.__radare.cmdj(f"/j {pattern}")
            case Radare2.PatternType.WIDE_STRING_PATTERN:
                return self.__radare.cmdj(f"/wj {pattern}")
            case Radare2.PatternType.HEX_PATTERN:
                return self.__radare.cmdj(f"/xj {pattern.replace('?', '.')}")

    def get_data(self, offset: int, size: int | None = None) -> bytes:
        if self.__is_r2_loaded and self.file_info["core"]["format"] != "any":
            return self.get_virtual_data(offset, size)
        return self.get_raw_data(offset, size)

    def get_raw_data(self, offset: int, size: int | None = None) -> bytes:
        if size:
            return self.__binary[offset : offset + size]
        return self.__binary[offset:]

    def get_virtual_data(self, offset: int, size: int | None = None) -> bytes:
        self.__load_r2()
        if not size:
            if not (section_info := self.get_section_info_from_va(offset)):
                raise RuntimeError(
                    f"Virtual address {offset:08x} not found in sections"
                )
            size = section_info["vsize"] - (offset - section_info["vaddr"])

        return bytes(self.__radare.cmdj(f"pxj {size} @{offset}"))

    def get_function_start_offset(self, offset: int) -> int:
        self.__load_r2()
        self.__do_analysis()
        return self.__radare.cmdj(f"afoj @ {offset}")["address"]

    def get_function_end_offset(self, offset: int) -> int:
        self.__load_r2()
        self.__do_analysis()
        function_info = self.__radare.cmdj(f"afij @ {offset}")
        return function_info[0]["offset"] + function_info[0]["size"]

    def get_basic_block_end_offset(self, offset: int) -> int:
        self.__load_r2()
        self.__do_analysis()
        basicblock_info = self.__radare.cmdj(f"afbj. @ {offset}")
        return basicblock_info[0]["addr"] + basicblock_info[0]["size"]

    def get_previous_instruction_offset(self, offset: int) -> int:
        self.__load_r2()
        return self.__radare.cmdj(f"pdj -1 @ {offset}")[0]["offset"]

    def get_next_instruction_offset(self, offset: int) -> int:
        self.__load_r2()
        return self.__radare.cmdj(f"pdj 2 @ {offset}")[1]["offset"]

    def get_xrefs_to(self, offset: int) -> list:
        self.__load_r2()
        references_info = self.__radare.cmdj(f"axtj @ {offset}")
        return [entry["from"] for entry in references_info]

    def get_section(self, name: str) -> bytes:
        self.__load_r2()
        rsrc_info = self.get_section_info(name)
        return self.get_data(rsrc_info["vaddr"], rsrc_info["vsize"])

    def get_section_info(self, name: str) -> dict[str, typing.Any] | None:
        self.__load_r2()
        sections = self.__radare.cmdj(f"iSj")
        for s in sections:
            if s["name"] == name:
                return s
        else:
            return None

    def get_section_info_from_va(self, va: int) -> dict[str, typing.Any] | None:
        self.__load_r2()
        for section_info in self.__radare.cmdj(f"iSj"):
            if (
                section_info["vaddr"]
                <= va
                <= section_info["vaddr"] + section_info["size"]
            ):
                return section_info
        return None

    def get_strings(self, offset: int) -> bytes:
        self.__load_r2()
        return bytes(self.__radare.cmdj(f"psj @ {offset}")["string"], "utf-8")

    def get_u8(self, offset: int) -> int:
        return cast.u8(self.get_data(offset, 1))

    def get_u16(self, offset: int) -> int:
        return cast.u16(self.get_data(offset, 2))

    def get_u32(self, offset: int) -> int:
        return cast.u32(self.get_data(offset, 4))

    def get_u64(self, offset: int) -> int:
        return cast.u64(self.get_data(offset, 8))

    @staticmethod
    def load(binary: bytes) -> Radare2:
        global CACHE

        hash = hashlib.sha256(binary).hexdigest()
        if x := CACHE.get(hash, None):
            return x

        x = Radare2(binary)
        CACHE[hash] = x
        return x

    def set_arch(self, arch: str) -> None:
        self.__radare.cmd(f"e asm.arch = {arch}")

    def set_bits(self, bits: int) -> None:
        self.__radare.cmd(f"e asm.bits = {bits}")
