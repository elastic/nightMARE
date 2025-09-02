# coding: utf-8

from __future__ import annotations

import typing
import functools
import unicorn

from nightMARE.analysis import reversing
from nightMARE.core import utils


class WindowsEmulator(object):
    """
    Windows x86/x64 emulator based on the unicorn engine
    Implements several high-level functions as well as direct access to the unicorn instance.
    """

    def require(field_name: str) -> typing.Callable:
        def decorator(f: typing.Callable):
            @functools.wraps(f)
            def wrapper(self, *args, **kwargs):
                field = getattr(self, field_name)
                if not field:
                    raise RuntimeError(
                        f'Can\'t call method ".{f.__name__}()", require ".{field_name} true"'
                    )
                return f(self, *args, **kwargs)

            return wrapper

        return decorator

    def __call_hook(self, *args, **kwargs) -> None:
        """
        Invokes a hook function with the provided arguments.

        :param args: Variable arguments to pass to the hook
        :param kwargs: Keyword arguments, including the 'hook' callable
        """

        hook = kwargs["hook"]
        hook(self, *args[1:])

    def __call_iat_hook(self, address: int, args) -> None:
        """
        Calls an IAT hook if it exists for the given address.

        :param address: The memory address to check for an IAT hook
        :param args: Arguments to pass to the hook function
        """

        if address in self.__iat_hooks:
            self.__iat_hooks[address](self, *args)

    def __dispatch_iat_hook(self, *args) -> None:
        """
        Dispatches an IAT hook by printing it and calling it with the provided arguments.

        :param args: Variable arguments including the address to dispatch
        """

        address = args[1]
        self.__print_iat_hook(address)
        self.__call_iat_hook(address, args[1:])

    def __find_free_memory(self, size: int) -> int:
        """
        Finds a free memory block of the specified size in the emulator.

        :param size: The size of memory to find
        :return: The starting address of the free memory block
        :raise: RuntimeError: If no free memory is found
        """
        memory_regions = list(self.__unicorn.mem_regions())
        if not memory_regions:
            return utils.PAGE_SIZE

        for i, memory_region in enumerate(memory_regions):
            if 0 == i:
                if utils.PAGE_SIZE + size <= memory_region[0]:
                    return utils.PAGE_SIZE

            else:
                if (memory_region[0] - memory_regions[i - 1][1]) >= size:
                    return memory_regions[i - 1][1] + 1

        return memory_regions[-1][1] + 1

    def __init__(self, is_x86: bool) -> None:
        """
        Initializes the Windows emulator with either x86 or x64 architecture.

        :param is_x86: Flag that is used to create an x86 or x64 emulator
        """

        self.__iat: dict[str, int] = {}
        self.__iat_hooks: dict[int, typing.Optional[typing.Callable]] = {}
        self.__image_base: int | None = None
        self.__image_size: int | None = None
        self.__inverted_iat: dict[int, str] = {}
        self.__pointer_size = 4 if is_x86 else 8
        self.__is_iat_hooking_enabled = False
        self.__is_pe_loaded = False
        self.__is_stack_initialized = False
        self.__is_x86 = is_x86
        self.__unicorn = unicorn.Uc(
            unicorn.UC_ARCH_X86, unicorn.UC_MODE_32 if is_x86 else unicorn.UC_MODE_64
        )

    def __init_iat(self, pe: bytes) -> None:
        """
        Initializes the Import Address Table (IAT) for a given PE binary.

        :param pe: The PE binary object to initialize the IAT from
        """

        rz = reversing.Rizin.load(pe)
        address = self.allocate_memory(0x10000)
        for import_ in rz.get_imports():
            self.__iat["{}!{}".format(import_["libname"], import_["name"]).lower()] = (
                address
            )
            self.__unicorn.mem_write(
                import_["plt"], address.to_bytes(self.__pointer_size, "little")
            )
            address += self.__pointer_size

        self.__inverted_iat = {v: k for k, v in self.__iat.items()}

    def __map_pe(self, pe: bytes) -> None:
        """
        Maps a PE binary into the emulator's memory.

        :param pe: The PE binary object to map into memory
        """

        rz = reversing.Rizin.load(pe)
        self.__image_base = rz.get_image_base()
        self.__image_size = rz.get_image_size()

        self.__unicorn.mem_map(self.__image_base, self.__image_size)
        for section in rz.get_sections():
            section_virtual_address = section["vaddr"]
            self.__unicorn.mem_write(
                section_virtual_address,
                rz.get_data_va(section_virtual_address, section["vsize"]),
            )

    def __print_iat_hook(self, address: int) -> None:
        """
        Prints information about an IAT hook if it exists.

        :param address: The address of the IAT hook to print
        """

        if address in self.__inverted_iat:
            hook_name = (
                self.__iat_hooks[address]
                if address in self.__iat_hooks
                else "Not Implemented"
            )
            print(f"[IAT Hook]: {self.__inverted_iat[address]} -> {hook_name}")

    def allocate_memory(self, size: int) -> int:
        """
        Allocates a block of memory in the emulator.

        :param size: Amount of bytes to allocate
        :return: Address of the newly allocated memory in the emulator
        """

        size = utils.page_align(size)
        address = self.__find_free_memory(size)
        self.__unicorn.mem_map(address, size)
        return address

    @require("is_stack_initialized")
    def do_call(self, address: int, return_address: int) -> None:
        self.push(return_address)
        self.ip = address

    @require("is_stack_initialized")
    def do_return(self, cleaning_size: int = 0) -> None:
        """
        Emulates a return instruction by updating the instruction and stack pointers.

        :param cleaning_size: Optional amount of bytes to clean after return, defaults to 0
        """
        self.ip = self.pop()
        self.sp += cleaning_size

    def enable_iat_hooking(self) -> None:
        """
        Enables IAT hooking by adding a block hook to the unicorn engine.
        """
        if self.__is_iat_hooking_enabled:
            raise RuntimeError("IAT hooking is already enabled")

        self.__unicorn.hook_add(unicorn.UC_HOOK_BLOCK, self.__dispatch_iat_hook)
        self.__is_iat_hooking_enabled = True

    def free_memory(self, address: int, size: int) -> None:
        """
        Frees a previously allocated memory block in the emulator.

        :param address: Address of the memory to free
        :param size: Size of the memory to free
        """

        self.__unicorn.mem_unmap(address, utils.page_align(size))

    @property
    @require("is_pe_loaded")
    def image_base(self) -> int:
        return self.__image_base

    @property
    @require("is_pe_loaded")
    def image_size(self) -> int:
        return self.__image_size

    def init_stack(self, size: int) -> int:
        """
        Initializes the stack with the specified size and sets the stack pointer.

        :param size: The size of the stack to initialize
        :return: The starting address of the stack
        """

        if self.__is_stack_initialized:
            raise RuntimeError("Stack is already initialized")

        address = self.allocate_memory(size)
        self.__unicorn.reg_write(
            unicorn.x86_const.UC_X86_REG_ESP, address + (size // 2)
        )
        self.__is_stack_initialized = True
        return address

    @property
    def ip(self) -> int:
        """
        Gets the current instruction pointer (EIP for x86, RIP for x64).

        :return: The current instruction pointer (EIP/RIP)
        """

        return self.__unicorn.reg_read(
            unicorn.x86_const.UC_X86_REG_EIP
            if self.__is_x86
            else unicorn.x86_const.UC_X86_REG_RIP
        )

    @ip.setter
    def ip(self, x: int) -> None:
        """
        Sets the instruction pointer (EIP for x86, RIP for x64).

        :param x: The value to set the instruction pointer to
        """

        self.__unicorn.reg_write(
            (
                unicorn.x86_const.UC_X86_REG_EIP
                if self.__is_x86
                else unicorn.x86_const.UC_X86_REG_RIP
            ),
            x,
        )

    @property
    def is_iat_hooking_enabled(self):
        return self.__is_iat_hooking_enabled

    @property
    def is_pe_loaded(self):
        return self.__is_pe_loaded

    @property
    def is_stack_initialized(self):
        return self.__is_stack_initialized

    def load_pe(self, pe: bytes, stack_size: int) -> None:
        """
        Loads a PE binary into the emulator, initializing memory and stack.

        :param pe: PE binary object to load
        :param stack_size: The size of the PE's stack to be mapped in the emulator
        :raise: RuntimeError: If a PE is already loaded
        """

        if self.__is_pe_loaded:
            raise RuntimeError("PE is already loaded")

        self.init_stack(stack_size)
        self.__map_pe(pe)
        self.__init_iat(pe)
        self.__is_pe_loaded = True

    @require("is_stack_initialized")
    def push(self, x: int) -> None:
        self.sp -= self.__pointer_size
        self.__unicorn.mem_write(self.sp, x.to_bytes(self.__pointer_size, "little"))

    @require("is_stack_initialized")
    def pop(self) -> int:
        x = int.from_bytes(
            self.__unicorn.mem_read(self.sp, self.__pointer_size), "little"
        )
        self.sp += self.__pointer_size
        return x

    @property
    @require("is_stack_initialized")
    def sp(self) -> int:
        """
        Gets the current stack pointer (ESP for x86, RSP for x64).

        :return: The current stack pointer (ESP/RSP)
        """

        return self.__unicorn.reg_read(
            unicorn.x86_const.UC_X86_REG_ESP
            if self.__is_x86
            else unicorn.x86_const.UC_X86_REG_RSP
        )

    @sp.setter
    @require("is_stack_initialized")
    def sp(self, x: int) -> None:
        """
        Sets the stack pointer (ESP for x86, RSP for x64).

        :param x: The value to set the stack pointer to
        """

        self.__unicorn.reg_write(
            (
                unicorn.x86_const.UC_X86_REG_ESP
                if self.__is_x86
                else unicorn.x86_const.UC_X86_REG_RSP
            ),
            x,
        )

    def set_hook(self, hook_type: int, hook: typing.Callable) -> int:
        """
        Sets a generic hook in the emulator using the unicorn engine.

        :param hook_type: Unicorn hook type (e.g., UC_HOOK_BLOCK)
        :param hook: Callback function to be invoked when the hook triggers
        :return: The hook handle assigned by the unicorn engine
        """

        return self.__unicorn.hook_add(
            hook_type, functools.partial(self.__call_hook, hook=hook)
        )

    @require("is_pe_loaded")
    @require("is_iat_hooking_enabled")
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

        function_name = function_name.lower()
        if function_name not in self.__iat:
            raise RuntimeError("Failed to set IAT hook, function doesn't exist")
        self.__iat_hooks[self.__iat[function_name]] = hook

    @property
    def unicorn(self) -> unicorn.Uc:
        return self.__unicorn
