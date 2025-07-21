# coding: utf-8

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

        if self.__is_rz_loaded:
            self.__rizin.cmd("o--")
            self.__tmp_binary_path.unlink()

    def __do_analysis(self) -> None:
        """
        Performs analysis on the binary if it hasn't been analyzed yet.
        """

        if not self.__is_analyzed:
            self.__rizin.cmd("aaaa")
            self.__is_analyzed = True

    def __load_rz(self) -> None:
        """
        Loads the Rizin instance with the binary if it hasn't been loaded yet.
        """

        if not self.__is_rz_loaded:
            self.__tmp_binary_path.write_bytes(self.__binary)
            self.__rizin = rzpipe.open(str(self.__tmp_binary_path))
            self.__is_rz_loaded = True

    def __init__(self, binary: bytes):
        """
        Initializes a Rizin instance with the provided binary data.

        :param binary: The binary data to analyze
        """

        self.__binary = binary
        self.__file_info: dict[str, typing.Any] = {}
        self.__is_rz_loaded = False
        self.__is_analyzed = False
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

        self.__load_rz()
        return self.__rizin.cmdj(f"aoj {size} @ {offset}")

    def disassemble_previous_instruction(self, offset: int) -> dict[str, typing.Any]:
        """
        Disassembles the instruction immediately preceding the given offset.

        :param offset: The offset to find the previous instruction for
        :return: A dictionary containing the previous instruction's disassembly info
        """

        self.__load_rz()
        self.__do_analysis()
        return self.disassemble(self.get_previous_instruction_offset(offset), 1)[0]

    def disassemble_next_instruction(self, offset: int) -> dict[str, typing.Any]:
        """
        Disassembles the instruction immediately following the given offset.

        :param offset: The offset to find the next instruction for
        :return: A dictionary containing the next instruction's disassembly info
        """

        self.__load_rz()
        return self.disassemble(self.get_next_instruction_offset(offset), 1)[0]

    @property
    def file_info(self) -> dict[str, typing.Any]:
        """
        Retrieves file information about the loaded binary.

        :return: A dictionary containing file metadata
        """

        self.__load_rz()
        if not self.__file_info:
            self.__file_info = self.__rizin.cmdj("ij")
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

        self.__load_rz()
        match pattern_type:
            case Rizin.PatternType.STRING_PATTERN:
                return self.__rizin.cmdj(f"/zj {pattern} l ascii")
            case Rizin.PatternType.WIDE_STRING_PATTERN:
                return self.__rizin.cmdj(f"/zj {pattern} l utf16le")
            case Rizin.PatternType.HEX_PATTERN:
                return self.__rizin.cmdj(
                    f"/xj {pattern.replace('?', '.').replace(' ', '')}"
                )

    def find_first_pattern(
        self,
        patterns: list[str],
        pattern_type: Rizin.PatternType.HEX_PATTERN,
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

    def get_data(self, offset: int, size: int | None = None) -> bytes:
        """
        Retrieves data from the binary, choosing between virtual or raw data based on format.

        :param offset: The offset to start reading data from
        :param size: The number of bytes to read (optional)
        :return: The requested data as bytes
        """

        if self.__is_rz_loaded and self.file_info["core"]["format"] != "any":
            return self.get_virtual_data(offset, size)
        return self.get_raw_data(offset, size)

    def get_functions(self) -> list[dict[str, typing.Any]]:
        """
        Retrieve a list of functions from the loaded binary.

        :return: A list of dictionaries containing function information
        """

        self.__load_rz()
        self.__do_analysis()
        return self.__rizin.cmdj("aflj")

    def get_raw_data(self, offset: int, size: int | None = None) -> bytes:
        """
        Retrieves raw data directly from the binary buffer.

        :param offset: The offset to start reading data from
        :param size: The number of bytes to read (optional, defaults to rest of binary)
        :return: The raw data as bytes
        """

        if size:
            return self.__binary[offset : offset + size]
        return self.__binary[offset:]

    def get_virtual_data(self, offset: int, size: int | None = None) -> bytes:
        """
        Retrieves virtual data from the binary using Rizin's memory mapping.

        :param offset: The virtual address to start reading data from
        :param size: The number of bytes to read (optional)
        :return: The virtual data as bytes
        :raise: RuntimeError: If the virtual address is not found in any section
        """

        self.__load_rz()
        if not size:
            if not (section_info := self.get_section_info_from_va(offset)):
                raise RuntimeError(
                    f"Virtual address {offset:08x} not found in sections"
                )
            size = section_info["vsize"] - (offset - section_info["vaddr"])

        return bytes(self.__rizin.cmdj(f"pxj {size} @ {offset}"))

    def get_function_start(self, offset: int) -> int | None:
        """
        Retrieves the starting offset of the function containing the given offset.

        :param offset: The offset within a function
        :return: The starting address of the function or None if the offset isn't within a function
        """

        self.__load_rz()
        self.__do_analysis()
        return self.__rizin.cmdj(f"afoj @ {offset}").get("address", None)

    def get_function_end(self, offset: int) -> int:
        """
        Retrieves the ending offset of the function containing the given offset.

        :param offset: The offset within a function
        :return: The ending address of the function
        """

        self.__load_rz()
        self.__do_analysis()
        function_info = self.__rizin.cmdj(f"afij @ {offset}")
        return function_info[0]["offset"] + function_info[0]["size"]

    def get_basic_block_end(self, offset: int) -> int:
        """
        Retrieves the ending offset of the basic block containing the given offset.

        :param offset: The offset within a basic block
        :return: The ending address of the basic block
        """

        self.__load_rz()
        self.__do_analysis()
        basicblock_info = self.__rizin.cmdj(f"afbj. @ {offset}")
        return basicblock_info[0]["addr"] + basicblock_info[0]["size"]

    def get_function_references(
        self, function_offset: int
    ) -> list[dict[str, typing.Any]]:
        """
        Get references to a function at the specified offset.

        :param function_offset: The offset of the function to find references for
        :return: A list of dictionaries containing reference information
        """

        self.__load_rz()
        self.__do_analysis()
        return self.__rizin.cmdj(f"afxj @ {function_offset}")

    def get_previous_instruction_offset(self, offset: int) -> int:
        """
        Retrieves the offset of the instruction immediately preceding the given offset.

        :param offset: The current instruction offset
        :return: The offset of the previous instruction
        """

        self.__load_rz()
        return self.__rizin.cmdj(f"pdj -1 @ {offset}")[0]["offset"]


    def get_next_instruction_offset(self, offset: int) -> int:
        """
        Retrieves the offset of the instruction immediately following the given offset.

        :param offset: The current instruction offset
        :return: The offset of the next instruction
        """

        self.__load_rz()
        return self.__rizin.cmdj(f"pdj 2 @ {offset}")[1]["offset"]

    def get_xrefs_from(self, offset: int) -> list:
        """
        Get a list of cross-reference destinations from a specified offset.

        :param offset: The offset to find cross-references from
        :return: A list of destination offsets referenced from the given offset
        """

        self.__load_rz()
        self.__do_analysis()
        return [x["to"] for x in self.__rizin.cmdj(f"axfj @ {offset}")]

    def get_xrefs_to(self, offset: int) -> list[int]:
        """
        Retrieves a list of cross-references pointing to the given offset.

        :param offset: The offset to find references to
        :return: A list of offsets that reference the given offset
        """

        self.__load_rz()
        self.__do_analysis()
        return [x["from"] for x in self.__rizin.cmdj(f"axtj @ {offset}")]

    def get_section(self, name: str) -> bytes:
        """
        Retrieves the content of a named section from the binary.

        :param name: The name of the section to retrieve
        :return: The section data as bytes
        """

        self.__load_rz()
        rsrc_info = self.get_section_info(name)
        return self.get_data(rsrc_info["vaddr"], rsrc_info["vsize"])

    def get_section_info(self, name: str) -> dict[str, typing.Any] | None:
        """
        Retrieves metadata about a named section in the binary.

        :param name: The name of the section to retrieve info for
        :return: A dictionary with section info or None if not found
        """

        self.__load_rz()
        sections = self.__rizin.cmdj(f"iSj")
        for s in sections:
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

        self.__load_rz()
        for section_info in self.__rizin.cmdj(f"iSj"):
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

        self.__load_rz()
        return bytes(self.__rizin.cmdj(f"psj ascii @ {offset}")["string"], "utf-8")

    def get_wide_string(self, offset: int) -> bytes:
        """
        Retrieves a wide string located at the given offset.

        :param offset: The offset where the wide string is located
        :return: The wide string data
        """

        self.__load_rz()
        return bytes(
            self.__rizin.cmdj(f"psj utf16le @ {offset}")["string"], "utf-16-le"
        )

    def get_strings(self) -> list[dict[str, typing.Any]]:
        """
        Retrieves all string in the binary.

        :return: A dictionnary describing each strings found in the binary
        """

        self.__load_rz()
        self.__do_analysis()
        return self.__rizin.cmdj(f"izj")

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
        return self.__rizin

    def set_arch(self, arch: str) -> None:
        """
        Sets the architecture for Rizin analysis.

        :param arch: The architecture to set (e.g., "x86", "arm")
        """

        self.__rizin.cmd(f"e asm.arch = {arch}")

    def set_bits(self, bits: int) -> None:
        """
        Sets the bit width for Rizin analysis.

        :param bits: The bit width to set (e.g., 32, 64)
        """

        self.__rizin.cmd(f"e asm.bits = {bits}")
