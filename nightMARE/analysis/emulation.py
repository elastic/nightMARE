# coding: utf-8

from __future__ import annotations

import typing
import functools
import unicorn

from nightMARE.analysis import reversing
from nightMARE.core import utils


class WindowsEmulator(object):
    """
    A Windows x86/x64 emulator based on the Unicorn engine.
    """

    @staticmethod
    def require(field_name: str) -> typing.Callable:
        """
        Creates a decorator that checks if a required instance attribute is True.

        :param field_name: The name of the instance attribute to check.
        :return: A decorator function.
        :exception RuntimeError: If the required attribute is not True.
        """

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
        Invokes a user-defined hook, passing the emulator instance as the first argument.

        :param args: Positional arguments provided by the Unicorn engine callback.
        :param kwargs: Keyword arguments which must contain the 'hook' callable.
        """

        hook = kwargs["hook"]
        hook(self, *args[1:])

    def __call_iat_hook(self, address: int, args) -> None:
        """
        Executes a registered IAT hook if one exists for the given address.

        :param address: The memory address of the IAT entry to check for a hook.
        :param args: Arguments to be passed to the hook function.
        """

        if h := self.__iat_hooks.get(address):
            h(self, *args)

    def __dispatch_iat_hook(self, *args) -> None:
        """
        Acts as the main callback for IAT hooking, printing and calling the registered hook.

        :param args: Arguments from the Unicorn engine hook, where `args[1]` is the address.
        """

        address = args[1]
        self.__print_iat_hook(address)
        self.__call_iat_hook(address, args[1:])

    def __find_free_memory(self, size: int) -> int:
        """
        Finds a contiguous block of free memory of a specified size.

        :param size: The required size of the memory block in bytes.
        :return: The starting address of a suitable free memory block.
        :exception RuntimeError: If no contiguous free memory block of the specified size is found.
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
        Initializes the Windows emulator for either x86 (32-bit) or x64 (64-bit) architecture.

        :param is_x86: If True, sets up a 32-bit emulator; otherwise, sets up a 64-bit emulator.
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
        Parses a PE file's import table and populates the IAT mapping in memory.

        :param pe: A bytes object representing the PE file.
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
        Maps the sections of a PE file into the emulator's memory space.

        :param pe: A bytes object representing the PE file.
        """

        rz = reversing.Rizin.load(pe)
        self.__image_base = rz.get_image_base()
        self.__image_size = rz.get_image_size()

        self.__unicorn.mem_map(self.__image_base, self.__image_size)
        for section in rz.get_sections():
            section_virtual_address: int = section["vaddr"]
            self.__unicorn.mem_write(
                section_virtual_address,
                rz.get_data_va(section_virtual_address, section["vsize"]),
            )

    def __print_iat_hook(self, address: int) -> None:
        """
        Prints the name of the function corresponding to a hooked IAT address.

        :param address: The memory address of the IAT entry.
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
        Allocates a new, page-aligned block of memory in the emulator.

        :param size: The amount of memory to allocate in bytes.
        :return: The starting address of the newly allocated memory block.
        """

        size = utils.page_align(size)
        address = self.__find_free_memory(size)
        self.__unicorn.mem_map(address, size)
        return address

    @require("is_stack_initialized")
    def do_call(self, address: int, return_address: int) -> None:
        """
        Emulates a function call by pushing the return address and jumping to the target address.

        :param address: The address of the function to call.
        :param return_address: The address to return to after the function completes.
        """

        self.push(return_address)
        self.ip = address

    @require("is_stack_initialized")
    def do_return(self, cleaning_size: int = 0) -> None:
        """
        Emulates a function return by popping the return address and cleaning the stack.

        :param cleaning_size: The number of bytes to remove from the stack after returning.
        """

        self.ip = self.pop()
        self.sp += cleaning_size

    def enable_iat_hooking(self) -> None:
        """
        Activates Import Address Table (IAT) hooking for the emulator.

        :exception RuntimeError: If IAT hooking has already been enabled.
        """

        if self.__is_iat_hooking_enabled:
            raise RuntimeError("IAT hooking is already enabled")

        self.__unicorn.hook_add(unicorn.UC_HOOK_BLOCK, self.__dispatch_iat_hook)
        self.__is_iat_hooking_enabled = True

    def free_memory(self, address: int, size: int) -> None:
        """
        Frees a previously allocated block of memory in the emulator.

        :param address: The starting address of the memory block to free.
        :param size: The size of the memory block to free in bytes.
        """

        self.__unicorn.mem_unmap(address, utils.page_align(size))

    @property
    @require("is_pe_loaded")
    def image_base(self) -> int:
        """
        Gets the base address of the loaded PE image.

        :return: The image base address.
        """

        return self.__image_base

    @property
    @require("is_pe_loaded")
    def image_size(self) -> int:
        """
        Gets the total memory size of the loaded PE image.

        :return: The image size in bytes.
        """

        return self.__image_size

    def init_stack(self, size: int) -> int:
        """
        Allocates memory for the stack and initializes the stack pointer.

        :param size: The size of the stack to allocate in bytes.
        :return: The base address of the newly allocated stack memory.
        :exception RuntimeError: If the stack has already been initialized.
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
        Gets the current value of the instruction pointer register (EIP/RIP).

        :return: The instruction pointer value.
        """

        return self.__unicorn.reg_read(
            unicorn.x86_const.UC_X86_REG_EIP
            if self.__is_x86
            else unicorn.x86_const.UC_X86_REG_RIP
        )

    @ip.setter
    def ip(self, x: int) -> None:
        """
        Sets the value of the instruction pointer register (EIP/RIP).

        :param x: The new value for the instruction pointer.
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
        """
        Checks if IAT hooking is currently enabled.

        :return: True if IAT hooking is enabled, False otherwise.
        """

        return self.__is_iat_hooking_enabled

    @property
    def is_pe_loaded(self):
        """
        Checks if a PE file has been loaded into the emulator.

        :return: True if a PE is loaded, False otherwise.
        """

        return self.__is_pe_loaded

    @property
    def is_stack_initialized(self):
        """
        Checks if the stack has been initialized.

        :return: True if the stack is initialized, False otherwise.
        """

        return self.__is_stack_initialized

    def load_pe(self, pe: bytes, stack_size: int) -> None:
        """
        Loads a PE file into the emulator, initializing its memory, stack, and IAT.

        :param pe: A bytes object representing the PE file.
        :param stack_size: The size of the stack to allocate for the PE file in bytes.
        :exception RuntimeError: If a PE file has already been loaded.
        """

        if self.__is_pe_loaded:
            raise RuntimeError("PE is already loaded")

        self.init_stack(stack_size)
        self.__map_pe(pe)
        self.__init_iat(pe)
        self.__is_pe_loaded = True

    @require("is_stack_initialized")
    def push(self, x: int) -> None:
        """
        Pushes a value onto the stack.

        :param x: The integer value to push.
        """

        self.sp -= self.__pointer_size
        self.__unicorn.mem_write(self.sp, x.to_bytes(self.__pointer_size, "little"))

    @require("is_stack_initialized")
    def pop(self) -> int:
        """
        Pops a value from the top of the stack.

        :return: The integer value popped from the stack.
        """

        x = int.from_bytes(
            self.__unicorn.mem_read(self.sp, self.__pointer_size), "little"
        )
        self.sp += self.__pointer_size
        return x

    @property
    @require("is_stack_initialized")
    def sp(self) -> int:
        """
        Gets the current value of the stack pointer register (ESP/RSP).

        :return: The stack pointer value.
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
        Sets the value of the stack pointer register (ESP/RSP).

        :param x: The new value for the stack pointer.
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
        Adds a generic Unicorn engine hook to the emulator.

        :param hook_type: The type of hook, as defined by Unicorn constants (e.g., UC_HOOK_CODE).
        :param hook: The callback function to be executed when the hook is triggered.
        :return: The handle for the newly registered hook.
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
        Sets or unsets a hook for a specific function in the PE's Import Address Table.

        :param function_name: The name of the imported function to hook (e.g., b"kernel32.dll!CreateFileW").
        :param hook: The callback function to handle the API call, or None to remove an existing hook.
        :exception RuntimeError: If the specified function name does not exist in the IAT.
        """

        function_name = function_name.lower()
        if function_name not in self.__iat:
            raise RuntimeError("Failed to set IAT hook, function doesn't exist")
        self.__iat_hooks[self.__iat[function_name]] = hook

    @property
    def unicorn(self) -> unicorn.Uc:
        """
        Provides direct access to the underlying Unicorn engine instance.

        :return: The `unicorn.Uc` object.
        """

        return self.__unicorn
