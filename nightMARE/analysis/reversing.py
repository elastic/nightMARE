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

R2_CACHE: dict[str, Radare2] = dict()


class Radare2:
    class PatternType(enum.Enum):
        STRING_PATTERN = enum.auto()
        WIDE_STRING_PATTERN = enum.auto()
        HEX_PATTERN = enum.auto()

    @staticmethod
    def load(binary: bytes) -> Radare2:
        global R2_CACHE

        hash = hashlib.sha256(binary).hexdigest()
        if x := R2_CACHE.get(hash, None):
            return x

        x = Radare2(binary)
        R2_CACHE[hash] = x
        return x

    def __init__(self, binary: bytes):
        self.__binary_path = pathlib.Path(tempfile.gettempdir()).joinpath(
            secrets.token_hex(24)
        )
        self.__binary_path.write_bytes(binary)

        self.radare = r2pipe.open(str(self.__binary_path))
        self.file_info = self.radare.cmdj("ij")
        self.is_analyzed = False

    def disassemble(self, offset: int, size: int) -> list[dict[str, typing.Any]]:
        return self.radare.cmdj(f"aoj {size} @{offset}")

    def disassemble_previous_instruction(self, offset: int) -> dict[str, typing.Any]:
        return self.disassemble(self.get_previous_instruction_offset(offset), 1)[0]

    def disassemble_next_instruction(self, offset: int) -> dict[str, typing.Any]:
        return self.disassemble(self.get_next_instruction_offset(offset), 1)[0]

    def do_analysis(self) -> None:
        if not self.is_analyzed:
            self.radare.cmd("aaa")
        self.is_analyzed = True

    def get_data(self, offset: int, size: int | None = None) -> bytes:
        if not size:
            if self.file_info["core"]["format"] == "any":
                size = self.file_info["core"]["size"] - offset
            else:
                if not (section_info := self.get_section_info_from_va(offset)):
                    raise RuntimeError(
                        f"Virtual address {offset:08x} not found in sections"
                    )
                size = section_info["vsize"] - (offset - section_info["vaddr"])

        return bytes(self.radare.cmdj(f"pxj {size} @{offset}"))

    def find_pattern(
        self, pattern: str, pattern_type: Radare2.PatternType
    ) -> typing.Iterable[int]:
        match pattern_type:
            case Radare2.PatternType.STRING_PATTERN:
                return self.radare.cmdj(f"/j {pattern}")
            case Radare2.PatternType.WIDE_STRING_PATTERN:
                return self.radare.cmdj(f"/wj {pattern}")
            case Radare2.PatternType.HEX_PATTERN:
                return self.radare.cmdj(f"/xj {pattern.replace('?', '.')}")

    def get_function_start_offset(self, offset: int) -> int:
        self.do_analysis()
        return self.radare.cmdj(f"afoj @ {offset}")["address"]

    def get_function_end_offset(self, offset: int) -> int:
        self.do_analysis()
        function_info = self.radare.cmdj(f"afij @ {offset}")
        return function_info[0]["offset"] + function_info[0]["size"]

    def get_basic_block_end_offset(self, offset: int) -> int:
        self.do_analysis()
        basicblock_info = self.radare.cmdj(f"afbj. @ {offset}")
        return basicblock_info[0]["addr"] + basicblock_info[0]["size"]

    def get_previous_instruction_offset(self, offset: int) -> int:
        return self.radare.cmdj(f"pdj -1 @ {offset}")[0]["offset"]

    def get_next_instruction_offset(self, offset: int) -> int:
        return self.radare.cmdj(f"pdj 2 @ {offset}")[1]["offset"]

    def get_references_to(self, offset: int) -> list:
        references_info = self.radare.cmdj(f"axtj @ {offset}")
        return [entry["from"] for entry in references_info]

    def get_section(self, name: str) -> bytes:
        rsrc_info = self.get_section_info(name)
        return self.get_data(rsrc_info["vaddr"], rsrc_info["vsize"])

    def get_section_info(self, name: str) -> dict[str, typing.Any] | None:
        sections = self.radare.cmdj(f"iSj")
        for s in sections:
            if s["name"] == name:
                return s
        else:
            return None

    def get_section_info_from_va(
        self, virtual_address: int
    ) -> dict[str, typing.Any] | None:
        for section_info in self.radare.cmdj(f"iSj"):
            if (
                section_info["vaddr"]
                <= virtual_address
                <= section_info["vaddr"] + section_info["size"]
            ):
                return section_info
        return None

    def get_string(self, offset: int) -> bytes:
        return bytes(self.radare.cmdj(f"psj @ {offset}")["string"], "utf-8")

    def get_strings_info_data_sections(self) -> list[dict[str, typing.Any]]:
        return self.radare.cmdj("izj")

    def get_u8(self, offset: int) -> int:
        return cast.u8(self.get_data(offset, 1))

    def get_u16(self, offset: int) -> int:
        return cast.u16(self.get_data(offset, 2))

    def get_u32(self, offset: int) -> int:
        return cast.u32(self.get_data(offset, 4))

    def get_u64(self, offset: int) -> int:
        return cast.u64(self.get_data(offset, 8))

    def __del__(self):
        self.radare.cmd("o--")
        self.__binary_path.unlink()
