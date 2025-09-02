# coding: utf-8

"""
TODO
- remove get_data
- fix modules accordingly
"""

from __future__ import annotations

import typing
import tempfile
import pathlib
import secrets
import enum
import hashlib
import rzpipe

from nightMARE.core import cast

CACHE: dict[str, Rizin] = {}


class Rizin:
    class PatternType(enum.Enum):
        """
        Enum defining pattern types for searching within a binary.

        :var STRING_PATTERN: Represents a regular ASCII string pattern
        :var WIDE_STRING_PATTERN: Represents a wide (UTF-16) string pattern
        :var HEX_PATTERN: Represents a hexadecimal pattern
        """

        STRING_PATTERN = enum.auto()
        WIDE_STRING_PATTERN = enum.auto()
        HEX_PATTERN = enum.auto()

    def __del__(self):
        """
        Destructor that cleans up resources when the Rizin instance is deleted.
        """
        if self.__rizin:
            self.__rizin.nonblocking = False
            self.__rizin.cmd("o--")
        self.__tmp_binary_path.unlink()

    def __init__(self, binary: bytes):
        """
        Initializes a Rizin instance with the provided binary data.

        :param binary: The binary data to analyze
        """

        self.__binary = binary
        self.__file_info: dict[str, typing.Any] = {}
        self.__rizin: rzpipe.open | None = None
        self.__tmp_binary_path = pathlib.Path(tempfile.gettempdir()).joinpath(
            secrets.token_hex(24)
        )

    def disassemble(self, offset: int, size: int) -> list[dict[str, typing.Any]]:
        """
        Disassembles instructions at the specified offset for a given size.

        :param offset: The starting offset to disassemble from
        :param size: The number of instructions to disassemble
        :return: A list of dictionaries containing disassembly information
        """

        return self.rizin.cmdj(f"aoj {size} @ {offset}")

    def disassemble_previous_instruction(self, offset: int) -> dict[str, typing.Any]:
        """
        Disassembles the instruction immediately preceding the given offset.

        :param offset: The offset to find the previous instruction for
        :return: A dictionary containing the previous instruction's disassembly info
        """

        return self.disassemble(self.get_previous_instruction_offset(offset), 1)[0]

    def disassemble_next_instruction(self, offset: int) -> dict[str, typing.Any]:
        """
        Disassembles the instruction immediately following the given offset.

        :param offset: The offset to find the next instruction for
        :return: A dictionary containing the next instruction's disassembly info
        """

        return self.disassemble(self.get_next_instruction_offset(offset), 1)[0]

    @property
    def file_info(self) -> dict[str, typing.Any]:
        """
        Retrieves file information about the loaded binary.

        :return: A dictionary containing file metadata
        """

        if not self.__file_info:
            self.__file_info = self.rizin.cmdj("ij")
        return self.__file_info

    def find_pattern(
        self, pattern: str, pattern_type: Rizin.PatternType
    ) -> list[dict[str, typing.Any]]:
        """
        Searches for a pattern in the binary based on the specified type.

        :param pattern: The pattern to search for (string or hex)
        :param pattern_type: The type of pattern (STRING_PATTERN, WIDE_STRING_PATTERN, HEX_PATTERN)
        :return: A list of offsets where the pattern is found
        """

        match pattern_type:
            case Rizin.PatternType.STRING_PATTERN:
                return self.rizin.cmdj(f"/zj {pattern} l ascii")
            case Rizin.PatternType.WIDE_STRING_PATTERN:
                return self.rizin.cmdj(f"/zj {pattern} l utf16le")
            case Rizin.PatternType.HEX_PATTERN:
                return self.rizin.cmdj(
                    f"/xj {pattern.replace('?', '.').replace(' ', '')}"
                )

    def find_first_pattern(
        self, patterns: list[str], pattern_type: Rizin.PatternType
    ) -> int:
        """
        Find the offset of the first matching pattern in a binary

        :param pattern: The pattern to search for (string or hex)
        :param pattern_type: The type of pattern (STRING_PATTERN, WIDE_STRING_PATTERN, HEX_PATTERN)
        :return: The first offset where the pattern is found
        :raise: Raise RuntimeError if pattern is not found
        """

        for x in patterns:
            if result := self.find_pattern(x, pattern_type):
                return result[0]["address"]
        raise RuntimeError("Pattern not found")

    def get_basic_block_end(self, offset: int) -> int:
        """
        Retrieves the ending offset of the basic block containing the given offset.

        :param offset: The offset within a basic block
        :return: The ending address of the basic block
        """

        basicblock_info = self.rizin.cmdj(f"afbj. @ {offset}")
        return basicblock_info[0]["addr"] + basicblock_info[0]["size"]

    def get_data(self, offset: int, size: int | None = None) -> bytes:
        """
        Retrieves data from the binary, choosing between virtual or raw data based on format.

        :param offset: The offset to start reading data from
        :param size: The number of bytes to read (optional)
        :return: The requested data as bytes
        """

        if self.file_info["core"]["format"] != "any":
            return self.get_data_va(offset, size)
        return self.get_data_raw(offset, size)

    def get_data_raw(self, offset: int, size: int | None) -> bytes:
        if size:
            return self.__binary[offset : offset + size]
        return self.__binary[offset:]

    def get_data_rva(self, rva: int, size: int | None) -> bytes:
        return self.get_data_va(self.get_image_base() + rva, size)

    def get_data_va(self, va: int, size: int | None) -> bytes:
        if not size:
            if not (section_info := self.get_section_info_from_va(va)):
                raise RuntimeError(f"Virtual address {va:08x} not found in sections")
            size = section_info["vsize"] - (va - section_info["vaddr"])

        return bytes(self.rizin.cmdj(f"pxj {size} @ {va}"))

    def get_functions(self) -> list[dict[str, typing.Any]]:
        """
        Retrieve a list of functions from the loaded binary.

        :return: A list of dictionaries containing function information
        """

        return self.rizin.cmdj("aflj")

    def get_image_base(self) -> int:
        return self.rizin.cmdj("ij")["bin"]["baddr"]

    def get_image_size(self) -> int:
        return [
            int(x["comment"], 16)
            for x in self.rizin.cmdj("ihj")
            if x["name"] == "SizeOfImage"
        ][0]

    def get_imports(self) -> list[dict[str, typing.Any]]:
        return self.rizin.cmdj("iij")

    def get_function_end(self, offset: int) -> int:
        """
        Retrieves the ending offset of the function containing the given offset.

        :param offset: The offset within a function
        :return: The ending address of the function
        """

        function_info = self.rizin.cmdj(f"afij @ {offset}")
        return function_info[0]["offset"] + function_info[0]["size"]

    def get_function_references(
        self, function_offset: int
    ) -> list[dict[str, typing.Any]]:
        """
        Get references to a function at the specified offset.

        :param function_offset: The offset of the function to find references for
        :return: A list of dictionaries containing reference information
        """

        return self.rizin.cmdj(f"afxj @ {function_offset}")

    def get_function_start(self, offset: int) -> int | None:
        """
        Retrieves the starting offset of the function containing the given offset.

        :param offset: The offset within a function
        :return: The starting address of the function or None if the offset isn't within a function
        """

        return self.rizin.cmdj(f"afoj @ {offset}").get("address", None)

    def get_next_instruction_offset(self, offset: int) -> int:
        """
        Retrieves the offset of the instruction immediately following the given offset.

        :param offset: The current instruction offset
        :return: The offset of the next instruction
        """

        return self.rizin.cmdj(f"pdj 2 @ {offset}")[1]["offset"]

    def get_previous_instruction_offset(self, offset: int) -> int:
        """
        Retrieves the offset of the instruction immediately preceding the given offset.

        :param offset: The current instruction offset
        :return: The offset of the previous instruction
        """

        return self.rizin.cmdj(f"pdj -1 @ {offset}")[0]["offset"]

    def get_section(self, name: str) -> bytes:
        """
        Retrieves the content of a named section from the binary.

        :param name: The name of the section to retrieve
        :return: The section data as bytes
        """

        rsrc_info = self.get_section_info(name)
        return self.get_data(rsrc_info["vaddr"], rsrc_info["vsize"])

    def get_sections(self) -> dict[str, typing.Any]:
        return self.rizin.cmdj("iSj")

    def get_section_info(self, name: str) -> dict[str, typing.Any] | None:
        """
        Retrieves metadata about a named section in the binary.

        :param name: The name of the section to retrieve info for
        :return: A dictionary with section info or None if not found
        """

        for s in self.get_sections():
            if s["name"] == name:
                return s
        else:
            return None

    def get_section_info_from_va(self, va: int) -> dict[str, typing.Any] | None:
        """
        Retrieves section metadata for a given virtual address.

        :param va: The virtual address to find the section for
        :return: A dictionary with section info or None if not found
        """

        for section_info in self.rizin.cmdj(f"iSj"):
            if (
                section_info["vaddr"]
                <= va
                <= section_info["vaddr"] + section_info["size"]
            ):
                return section_info
        return None

    def get_string(self, offset: int) -> bytes:
        """
        Retrieves a string located at the given offset.

        :param offset: The offset where the string is located
        :return: The string data
        """

        return bytes(self.rizin.cmdj(f"psj ascii @ {offset}")["string"], "utf-8")

    def get_strings(self) -> list[dict[str, typing.Any]]:
        """
        Retrieves all string in the binary.

        :return: A dictionnary describing each strings found in the binary
        """

        return self.rizin.cmdj(f"izj")

    def get_u8(self, offset: int) -> int:
        """
        Retrieves an unsigned 8-bit integer from the given offset.

        :param offset: The offset to read the value from
        :return: The unsigned 8-bit integer value
        """

        return cast.u8(self.get_data(offset, 1))

    def get_u16(self, offset: int) -> int:
        """
        Retrieves an unsigned 16-bit integer from the given offset.

        :param offset: The offset to read the value from
        :return: The unsigned 16-bit integer value
        """

        return cast.u16(self.get_data(offset, 2))

    def get_u32(self, offset: int) -> int:
        """
        Retrieves an unsigned 32-bit integer from the given offset.

        :param offset: The offset to read the value from
        :return: The unsigned 32-bit integer value
        """

        return cast.u32(self.get_data(offset, 4))

    def get_u64(self, offset: int) -> int:
        """
        Retrieves an unsigned 64-bit integer from the given offset.

        :param offset: The offset to read the value from
        :return: The unsigned 64-bit integer value
        """

        return cast.u64(self.get_data(offset, 8))

    def get_xrefs_from(self, offset: int) -> list:
        """
        Get a list of cross-reference destinations from a specified offset.

        :param offset: The offset to find cross-references from
        :return: A list of destination offsets referenced from the given offset
        """

        return [x["to"] for x in self.rizin.cmdj(f"axfj @ {offset}")]

    def get_xrefs_to(self, offset: int) -> list[int]:
        """
        Retrieves a list of cross-references pointing to the given offset.

        :param offset: The offset to find references to
        :return: A list of offsets that reference the given offset
        """

        return [x["from"] for x in self.rizin.cmdj(f"axtj @ {offset}")]

    def get_wide_string(self, offset: int) -> bytes:
        """
        Retrieves a wide string located at the given offset.

        :param offset: The offset where the wide string is located
        :return: The wide string data
        """

        return bytes(self.rizin.cmdj(f"psj utf16le @ {offset}")["string"], "utf-16-le")

    @property
    def is_rz_loaded(self) -> bool:
        return self.is_rz_loaded

    @staticmethod
    def load(binary: bytes) -> Rizin:
        """
        Load a Rizin instance from a binary, using a cache to avoid duplicates.

        :param binary: The binary data to load
        :return: A Rizin instance
        """

        global CACHE

        hash = hashlib.sha256(binary).hexdigest()
        if x := CACHE.get(hash, None):
            return x

        x = Rizin(binary)
        CACHE[hash] = x
        return x

    @property
    def rizin(self) -> rzpipe.open:
        if not self.__rizin:
            self.__tmp_binary_path.write_bytes(self.__binary)
            self.__rizin = rzpipe.open(str(self.__tmp_binary_path))
            self.__rizin.cmd("aaaa")
        return self.__rizin

    def set_arch(self, arch: str) -> None:
        """
        Sets the architecture for Rizin analysis.

        :param arch: The architecture to set (e.g., "x86", "arm")
        """

        self.rizin.cmd(f"e asm.arch = {arch}")

    def set_bits(self, bits: int) -> None:
        """
        Sets the bit width for Rizin analysis.

        :param bits: The bit width to set (e.g., 32, 64)
        """

        self.rizin.cmd(f"e asm.bits = {bits}")
