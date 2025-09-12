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
    """
    A wrapper for the Rizin reverse engineering framework.
    """

    class PatternType(enum.Enum):
        """
        Defines the types of patterns that can be searched for in a binary.
        """

        STRING_PATTERN = enum.auto()
        WIDE_STRING_PATTERN = enum.auto()
        HEX_PATTERN = enum.auto()

    def __del__(self):
        """
        Cleans up resources by closing the Rizin instance and deleting the temporary binary file.
        """

        if self.__rizin:
            self.__rizin.nonblocking = False
            self.__rizin.cmd("o--")
        self.__tmp_binary_path.unlink()

    def __init__(self, binary: bytes):
        """
        Initializes a Rizin instance to analyze the provided binary data.

        :param binary: The binary content to be analyzed.
        """

        self.__binary = binary
        self.__file_info: dict[str, typing.Any] = {}
        self.__rizin: rzpipe.open | None = None
        self.__tmp_binary_path = pathlib.Path(tempfile.gettempdir()).joinpath(
            secrets.token_hex(24)
        )

    def disassemble(self, offset: int, size: int) -> list[dict[str, typing.Any]]:
        """
        Disassembles a specified number of instructions starting from a given offset.

        :param offset: The address or offset to begin disassembly.
        :param size: The number of instructions to disassemble.
        :return: A list of dictionaries, where each dictionary represents a disassembled instruction.
        """

        return self.rizin.cmdj(f"aoj {size} @ {offset}")

    def disassemble_previous_instruction(self, offset: int) -> dict[str, typing.Any]:
        """
        Disassembles the single instruction immediately preceding a given offset.

        :param offset: The reference offset from which to find the previous instruction.
        :return: A dictionary containing the details of the disassembled previous instruction.
        """

        return self.disassemble(self.get_previous_instruction_offset(offset), 1)[0]

    def disassemble_next_instruction(self, offset: int) -> dict[str, typing.Any]:
        """
        Disassembles the single instruction immediately following a given offset.

        :param offset: The reference offset from which to find the next instruction.
        :return: A dictionary containing the details of the disassembled next instruction.
        """

        return self.disassemble(self.get_next_instruction_offset(offset), 1)[0]

    @property
    def file_info(self) -> dict[str, typing.Any]:
        """
        Retrieves and caches detailed information about the loaded binary.

        :return: A dictionary containing metadata about the binary file.
        """

        if not self.__file_info:
            self.__file_info = self.rizin.cmdj("ij")
        return self.__file_info

    def find_pattern(
        self, pattern: str, pattern_type: Rizin.PatternType
    ) -> list[dict[str, typing.Any]]:
        """
        Searches for a specific pattern within the binary.

        :param pattern: The pattern to search for, as a string or hex value.
        :param pattern_type: The type of pattern to search for (e.g., STRING_PATTERN, HEX_PATTERN).
        :return: A list of dictionaries, each containing the address of a found pattern.
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
        Finds the first occurrence of any pattern from a list within the binary.

        :param patterns: A list of patterns to search for.
        :param pattern_type: The type of the patterns in the list.
        :return: The address of the first matched pattern.
        :exception RuntimeError: If no pattern from the list is found.
        """

        for x in patterns:
            if result := self.find_pattern(x, pattern_type):
                return result[0]["address"]
        raise RuntimeError("Pattern not found")

    def get_basic_block_end(self, offset: int) -> int:
        """
        Finds the end address of the basic block that contains the given offset.

        :param offset: An address contained within a basic block.
        :return: The end address of the basic block.
        """

        basicblock_info = self.rizin.cmdj(f"afbj. @ {offset}")
        return basicblock_info[0]["addr"] + basicblock_info[0]["size"]

    def get_data(self, offset: int, size: int | None = None) -> bytes:
        """
        Reads data from the binary, automatically selecting between virtual address or raw offset.

        :param offset: The offset or virtual address to read from.
        :param size: The number of bytes to read.
        :return: The requested data as a bytes object.
        """

        if self.file_info["core"]["format"] != "any":
            return self.get_data_va(offset, size)
        return self.get_data_raw(offset, size)

    def get_data_raw(self, offset: int, size: int | None) -> bytes:
        """
        Reads data from the raw binary at a specific file offset.

        :param offset: The file offset to start reading from.
        :param size: The number of bytes to read. If None, reads to the end of the binary.
        :return: The requested data as a bytes object.
        """

        if size:
            return self.__binary[offset : offset + size]
        return self.__binary[offset:]

    def get_data_rva(self, rva: int, size: int | None) -> bytes:
        """
        Reads data from a relative virtual address (RVA) by adding the image base.

        :param rva: The relative virtual address to read from.
        :param size: The number of bytes to read.
        :return: The requested data as a bytes object.
        """

        return self.get_data_va(self.get_image_base() + rva, size)

    def get_data_va(self, va: int, size: int | None) -> bytes:
        """
        Reads data from a specific virtual address (VA) in the analyzed binary.

        :param va: The virtual address to read from.
        :param size: The number of bytes to read. If None, reads until the end of the section.
        :return: The requested data as a bytes object.
        :exception RuntimeError: If the virtual address is not found in any section.
        """

        if not size:
            if not (section_info := self.get_section_info_from_va(va)):
                raise RuntimeError(f"Virtual address {va:08x} not found in sections")
            size = section_info["vsize"] - (va - section_info["vaddr"])

        return bytes(self.rizin.cmdj(f"pxj {size} @ {va}"))

    def get_functions(self) -> list[dict[str, typing.Any]]:
        """
        Retrieves a list of all functions analyzed in the binary.

        :return: A list of dictionaries, each containing information about a function.
        """

        return self.rizin.cmdj("aflj")

    def get_image_base(self) -> int:
        """
        Retrieves the base address of the loaded binary image.

        :return: The image base address as an integer.
        """

        return self.rizin.cmdj("ij")["bin"]["baddr"]

    def get_image_size(self) -> int:
        """
        Retrieves the total size of the binary image as defined in its headers.

        :return: The image size in bytes as an integer.
        """

        return [
            int(x["comment"], 16)
            for x in self.rizin.cmdj("ihj")
            if x["name"] == "SizeOfImage"
        ][0]

    def get_imports(self) -> list[dict[str, typing.Any]]:
        """
        Retrieves a list of all imported functions from the binary.

        :return: A list of dictionaries, each containing information about an imported function.
        """

        return self.rizin.cmdj("iij")

    def get_function_end(self, offset: int) -> int:
        """
        Finds the end address of the function that contains the given offset.

        :param offset: An address contained within a function.
        :return: The end address of the function.
        """

        function_info = self.rizin.cmdj(f"afij @ {offset}")
        return function_info[0]["offset"] + function_info[0]["size"]

    def get_function_references(
        self, function_offset: int
    ) -> list[dict[str, typing.Any]]:
        """
        Retrieves all cross-references originating from a specific function.

        :param function_offset: The starting offset of the function.
        :return: A list of dictionaries, each describing a cross-reference from the function.
        """

        return self.rizin.cmdj(f"afxj @ {function_offset}")

    def get_function_start(self, offset: int) -> int | None:
        """
        Finds the start address of the function that contains the given offset.

        :param offset: An address contained within a function.
        :return: The starting address of the function, or None if not within a function.
        """

        return self.rizin.cmdj(f"afoj @ {offset}").get("address", None)

    def get_next_instruction_offset(self, offset: int) -> int:
        """
        Determines the offset of the instruction immediately following the given offset.

        :param offset: The offset of the current instruction.
        :return: The offset of the next instruction.
        """

        return self.rizin.cmdj(f"pdj 2 @ {offset}")[1]["offset"]

    def get_previous_instruction_offset(self, offset: int) -> int:
        """
        Determines the offset of the instruction immediately preceding the given offset.

        :param offset: The offset of the current instruction.
        :return: The offset of the previous instruction.
        """

        return self.rizin.cmdj(f"pdj -1 @ {offset}")[0]["offset"]

    def get_section(self, name: str) -> bytes:
        """
        Retrieves the raw content of a binary section by its name.

        :param name: The name of the section (e.g., '.text').
        :return: The section's data as a bytes object.
        """

        rsrc_info = self.get_section_info(name)
        return self.get_data(rsrc_info["vaddr"], rsrc_info["vsize"])

    def get_sections(self) -> dict[str, typing.Any]:
        """
        Retrieves information about all sections in the binary.

        :return: A list of dictionaries, each describing a section.
        """

        return self.rizin.cmdj("iSj")

    def get_section_info(self, name: str) -> dict[str, typing.Any] | None:
        """
        Retrieves metadata for a specific section by its name.

        :param name: The name of the section.
        :return: A dictionary containing the section's metadata, or None if not found.
        """

        for s in self.get_sections():
            if s["name"] == name:
                return s
        else:
            return None

    def get_section_info_from_va(self, va: int) -> dict[str, typing.Any] | None:
        """
        Finds the section that contains a given virtual address.

        :param va: The virtual address to locate within a section.
        :return: A dictionary containing the section's metadata, or None if the address is not in any section.
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
        Reads a null-terminated ASCII string from a given offset.

        :param offset: The address where the string begins.
        :return: The string as a bytes object.
        """

        return bytes(self.rizin.cmdj(f"psj ascii @ {offset}")["string"], "utf-8")

    def get_strings(self) -> list[dict[str, typing.Any]]:
        """
        Retrieves all strings found within the binary.

        :return: A list of dictionaries, each describing a found string and its location.
        """

        return self.rizin.cmdj(f"izj")

    def get_u8(self, offset: int) -> int:
        """
        Reads an 8-bit unsigned integer from a given offset.

        :param offset: The offset to read from.
        :return: The 8-bit unsigned integer value.
        """

        return cast.u8(self.get_data(offset, 1))

    def get_u16(self, offset: int) -> int:
        """
        Reads a 16-bit unsigned integer from a given offset.

        :param offset: The offset to read from.
        :return: The 16-bit unsigned integer value.
        """

        return cast.u16(self.get_data(offset, 2))

    def get_u32(self, offset: int) -> int:
        """
        Reads a 32-bit unsigned integer from a given offset.

        :param offset: The offset to read from.
        :return: The 32-bit unsigned integer value.
        """

        return cast.u32(self.get_data(offset, 4))

    def get_u64(self, offset: int) -> int:
        """
        Reads a 64-bit unsigned integer from a given offset.

        :param offset: The offset to read from.
        :return: The 64-bit unsigned integer value.
        """

        return cast.u64(self.get_data(offset, 8))

    def get_xrefs_from(self, offset: int) -> list:
        """
        Retrieves all cross-references originating from a specific address.

        :param offset: The address to find references from.
        :return: A list of destination addresses that are referenced from the given offset.
        """

        return [x["to"] for x in self.rizin.cmdj(f"axfj @ {offset}")]

    def get_xrefs_to(self, offset: int) -> list[int]:
        """
        Retrieves all cross-references pointing to a specific address.

        :param offset: The address to find references to.
        :return: A list of source addresses that reference the given offset.
        """

        return [x["from"] for x in self.rizin.cmdj(f"axtj @ {offset}")]

    def get_wide_string(self, offset: int) -> bytes:
        """
        Reads a null-terminated wide (UTF-16-LE) string from a given offset.

        :param offset: The address where the wide string begins.
        :return: The wide string as a bytes object.
        """

        return bytes(self.rizin.cmdj(f"psj utf16le @ {offset}")["string"], "utf-16-le")

    @property
    def is_rz_loaded(self) -> bool:
        """
        Checks if the Rizin core instance has been loaded and is active.

        :return: A boolean indicating if the Rizin instance is loaded.
        """

        return self.is_rz_loaded

    @staticmethod
    def load(binary: bytes) -> Rizin:
        """
        Loads a binary for analysis, using a cache to avoid re-analyzing the same file.

        :param binary: The binary content to load.
        :return: A Rizin instance for the given binary.
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
        """
        Provides access to the underlying `rzpipe` instance, initializing it on first use.

        :return: The active `rzpipe.open` object for interacting with the Rizin core.
        """

        if not self.__rizin:
            self.__tmp_binary_path.write_bytes(self.__binary)
            self.__rizin = rzpipe.open(str(self.__tmp_binary_path))
            self.__rizin.cmd("aaaa")
        return self.__rizin

    def set_arch(self, arch: str) -> None:
        """
        Sets the architecture for the analysis session.

        :param arch: The architecture name as a string (e.g., 'x86', 'arm').
        """

        self.rizin.cmd(f"e asm.arch = {arch}")

    def set_bits(self, bits: int) -> None:
        """
        Sets the bitness (e.g., 32 or 64) for the analysis session.

        :param bits: The number of bits as an integer.
        """

        self.rizin.cmd(f"e asm.bits = {bits}")
