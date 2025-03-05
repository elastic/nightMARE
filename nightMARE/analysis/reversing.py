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

    def disassemble(self, offset: int, size: int) -> list[dict[str, typing.Any]]:
        return self.radare.cmdj(f"pdj {size} @{offset}")

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

    def get_u8(self, offset: int) -> int:
        return cast.u8(self.get_data(offset, 1))

    def get_16(self, offset: int) -> int:
        return cast.u16(self.get_data(offset, 2))

    def get_u32(self, offset: int) -> int:
        return cast.u32(self.get_data(offset, 4))

    def get_u64(self, offset: int) -> int:
        return cast.u64(self.get_data(offset, 8))

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

    def get_section_info(self, name: str) -> dict[str, typing.Any] | None:
        sections = self.radare.cmdj(f"iSj")
        for s in sections:
            if s["name"] == name:
                return s
        else:
            return None

    def get_section(self, name: str) -> bytes:
        rsrc_info = self.get_section_info(name)
        return self.get_data(rsrc_info["vaddr"], rsrc_info["vsize"])

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

    def __del__(self):
        self.radare.cmd("o--")
        self.__binary_path.unlink()
