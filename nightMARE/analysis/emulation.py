# coding: utf-8

from __future__ import annotations

import typing
import functools

import unicorn
import lief


class WindowsEmulator(object):
    """
    Windows x86/x64 emulator based on the unicorn engine
    Implements several high-level functions as well as direct access to the unicorn instance.
    """

    def __call_iat_hook(self, address: int, args) -> None:
        """
        Calls an IAT hook if it exists for the given address.

        :param address: The memory address to check for an IAT hook
        :param args: Arguments to pass to the hook function
        """

        if address in self.__iat_hooks:
            self.__iat_hooks[address](self, *args)

    def __call_hook(self, *args, **kwargs) -> None:
        """
        Invokes a hook function with the provided arguments.

        :param args: Variable arguments to pass to the hook
        :param kwargs: Keyword arguments, including the 'hook' callable
        """

        hook = kwargs["hook"]
        hook(self, *args[1:])

    def __dispatch_iat_hook(self, *args) -> None:
        """
        Dispatches an IAT hook by printing it and calling it with the provided arguments.

        :param args: Variable arguments including the address to dispatch
        """

        address = args[1]
        self.__print_iat_hook(address)
        self.__call_iat_hook(address, args[1:])

    def __enable_iat_hooking(self) -> None:
        """
        Enables IAT hooking by adding a block hook to the unicorn engine.
        """

        self.unicorn.hook_add(unicorn.UC_HOOK_BLOCK, self.__dispatch_iat_hook)

    def __find_free_memory(self, size: int) -> int:
        """
        Finds a free memory block of the specified size in the emulator.

        :param size: The size of memory to find
        :return: The starting address of the free memory block
        :raise: RuntimeError: If no free memory is found
        """

        address = 0x10000
        while self.__is_memory_mapped(address, size):
            if address >= 2 ** (32 if self.__is_x86 else 64) - 1:
                raise RuntimeError("Failed to find free memory")
            address += 0x10000
        return address

    def __init__(self, is_x86: bool) -> None:
        """
        Initializes the Windows emulator with either x86 or x64 architecture.

        :param is_x86: Flag that is used to create an x86 or x64 emulator
        """

        self.unicorn = unicorn.Uc(
            unicorn.UC_ARCH_X86, unicorn.UC_MODE_32 if is_x86 else unicorn.UC_MODE_64
        )
        self.__is_x86 = is_x86
        self.__pointer_size = 4 if is_x86 else 8
        self.__iat: dict[str, int] = {}
        self.__inv_iat: dict[int, str] = {}
        self.__iat_hooks: dict[int, typing.Optional[typing.Callable]] = {}
        self.__is_pe_loaded = False

    def __is_memory_mapped(self, address: int, size: int) -> bool:
        """
        Checks if a memory region is already mapped in the emulator.

        :param address: The starting address to check
        :param size: The size of the memory region to check
        :return: True if the memory is mapped, False otherwise
        """

        for region in self.unicorn.mem_regions():
            if region[0] <= (address + size) <= region[0] + region[1]:
                return True
        return False

    def __init_iat(self, pe: lief.PE.Binary) -> None:
        """
        Initializes the Import Address Table (IAT) for a given PE binary.

        :param pe: The PE binary object to initialize the IAT from
        """

        address = self.allocate_memory(0x10000)
        for _import in pe.imports:
            for function in _import.entries:
                self.__iat[_import.name + "!" + function.name] = address
                self.unicorn.mem_write(
                    pe.imagebase + function.iat_address,
                    address.to_bytes(self.__pointer_size, "little"),
                )
                address += self.__pointer_size
        self.__inv_iat = {v: k for k, v in self.__iat.items()}

    def __init_stack(self, stack_size: int) -> int:
        """
        Initializes the stack with the specified size and sets the stack pointer.

        :param stack_size: The size of the stack to initialize
        :return: The starting address of the stack
        """

        address = self.allocate_memory(stack_size)
        self.unicorn.reg_write(
            unicorn.x86_const.UC_X86_REG_ESP, address + (stack_size // 2)
        )
        return address

    def __map_pe(self, pe: lief.PE.Binary) -> None:
        """
        Maps a PE binary into the emulator's memory.

        :param pe: The PE binary object to map into memory
        """

        self.unicorn.mem_map(pe.imagebase, pe.virtual_size)
        for section in pe.sections:
            self.unicorn.mem_write(
                pe.imagebase + section.virtual_address, bytes(section.content)
            )

    def __print_iat_hook(self, address: int) -> None:
        """
        Prints information about an IAT hook if it exists.

        :param address: The address of the IAT hook to print
        """

        if address in self.__inv_iat:
            hook_name = (
                self.__iat_hooks[address]
                if address in self.__iat_hooks
                else "Not Implemented"
            )
            print(f"[+] {self.__inv_iat[address]} -> {hook_name}")

    def allocate_memory(self, size: int) -> int:
        """
        Allocates a block of memory in the emulator.

        :param size: Amount of bytes to allocate
        :return: Address of the newly allocated memory in the emulator
        """

        address = self.__find_free_memory(size)
        self.unicorn.mem_map(address, size)
        return address

    @property
    def ip(self) -> int:
        """
        Gets the current instruction pointer (EIP for x86, RIP for x64).

        :return: The current instruction pointer (EIP/RIP)
        """

        return self.unicorn.reg_read(
            unicorn.x86_const.UC_X86_REG_EIP
            if self.__is_x86
            else unicorn.x86_const.UC_X86_REG_RIP
        )

    @property
    def sp(self) -> int:
        """
        Gets the current stack pointer (ESP for x86, RSP for x64).

        :return: The current stack pointer (ESP/RSP)
        """

        return self.unicorn.reg_read(
            unicorn.x86_const.UC_X86_REG_ESP
            if self.__is_x86
            else unicorn.x86_const.UC_X86_REG_RSP
        )

    @ip.setter
    def ip(self, x: int) -> None:
        """
        Sets the instruction pointer (EIP for x86, RIP for x64).

        :param x: The value to set the instruction pointer to
        """

        self.unicorn.reg_write(
            (
                unicorn.x86_const.UC_X86_REG_EIP
                if self.__is_x86
                else unicorn.x86_const.UC_X86_REG_RIP
            ),
            x,
        )

    @sp.setter
    def sp(self, x: int) -> None:
        """
        Sets the stack pointer (ESP for x86, RSP for x64).

        :param x: The value to set the stack pointer to
        """

        self.unicorn.reg_write(
            (
                unicorn.x86_const.UC_X86_REG_ESP
                if self.__is_x86
                else unicorn.x86_const.UC_X86_REG_RSP
            ),
            x,
        )

    def free_memory(self, address: int, size: int) -> None:
        """
        Frees a previously allocated memory block in the emulator.

        :param address: Address of the memory to free
        :param size: Size of the memory to free
        """

        self.unicorn.mem_unmap(address, size)

    def do_return(self, cleaning_size: int = 0) -> None:
        """
        Emulates a return instruction by updating the instruction and stack pointers.

        :param cleaning_size: Optional amount of bytes to clean after return, defaults to 0
        """

        self.ip = int.from_bytes(
            self.unicorn.mem_read(self.sp, self.__pointer_size), "little"
        )
        self.sp += self.__pointer_size + cleaning_size

    def set_iat_hook(
        self,
        function_name: bytes,
        hook: typing.Callable[[WindowsEmulator, tuple, dict[str, typing.Any]], None],
    ) -> None:
        """
        Sets or unsets a hook for a PE's import address table entry.

        :param function_name: Name of the import (e.g., b"CreateRemoteThread")
        :param hook: Callback function to set, or None to unset the hook
        :raise: RuntimeError: If the function name doesn't exist in the IAT
        """

        if function_name not in self.__iat:
            raise RuntimeError("Failed to set IAT hook, function doesn't exist")
        self.__iat_hooks[self.__iat[function_name]] = hook

    def set_hook(
        self,
        hook_type: int,
        hook: typing.Callable[[WindowsEmulator, tuple, dict[str, typing.Any]], None],
    ) -> int:
        """
        Sets a generic hook in the emulator using the unicorn engine.

        :param hook_type: Unicorn hook type (e.g., UC_HOOK_BLOCK)
        :param hook: Callback function to be invoked when the hook triggers
        :return: The hook handle assigned by the unicorn engine
        """

        return self.unicorn.hook_add(
            hook_type, functools.partial(self.__call_hook, hook=hook)
        )

    def load_pe(self, pe: lief.PE.Binary, stack_size: int) -> None:
        """
        Loads a PE binary into the emulator, initializing memory and stack.

        :param pe: PE binary object to load
        :param stack_size: The size of the PE's stack to be mapped in the emulator
        :raise: RuntimeError: If a PE is already loaded
        """

        if self.__is_pe_loaded:
            raise RuntimeError("PE is already loaded")

        self.__map_pe(pe)
        self.__init_iat(pe)
        self.__enable_iat_hooking()
        self.__init_stack(stack_size)
        self.__is_pe_loaded = True
