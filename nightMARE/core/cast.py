# coding: utf-8


def u64(x: bytes):
    """
    Converts the first 8 bytes of a byte sequence into a 64-bit unsigned integer.

    :param x: The byte sequence to convert.
    :return: The resulting 64-bit unsigned integer.
    :exception IndexError: If the byte sequence is empty.
    """

    return int.from_bytes(x[0:8], "little")


def u32(x: bytes):
    """
    Converts the first 4 bytes of a byte sequence into a 32-bit unsigned integer.

    :param x: The byte sequence to convert.
    :return: The resulting 32-bit unsigned integer.
    :exception IndexError: If the byte sequence is empty.
    """

    return int.from_bytes(x[0:4], "little")


def u16(x: bytes):
    """
    Converts the first 2 bytes of a byte sequence into a 16-bit unsigned integer.

    :param x: The byte sequence to convert.
    :return: The resulting 16-bit unsigned integer.
    :exception IndexError: If the byte sequence is empty.
    """

    return int.from_bytes(x[0:2], "little")


def u8(x: bytes):
    """
    Converts the first byte of a byte sequence into an 8-bit unsigned integer.

    :param x: The byte sequence to convert.
    :return: The resulting 8-bit unsigned integer.
    :exception IndexError: If the byte sequence is empty.
    """

    return int.from_bytes(x[0:1], "little")


def p64(x: int):
    """
    Converts an integer into a 64-bit (8-byte) little-endian byte sequence.

    :param x: The integer to convert.
    :return: An 8-byte sequence representing the integer.
    :exception OverflowError: If the integer is too large to fit in 8 bytes.
    """

    return x.to_bytes(8, "little")


def p32(x: int):
    """
    Converts an integer into a 32-bit (4-byte) little-endian byte sequence.

    :param x: The integer to convert.
    :return: A 4-byte sequence representing the integer.
    :exception OverflowError: If the integer is too large to fit in 4 bytes.
    """

    return x.to_bytes(4, "little")


def p16(x: int):
    """
    Converts an integer into a 16-bit (2-byte) little-endian byte sequence.

    :param x: The integer to convert.
    :return: A 2-byte sequence representing the integer.
    :exception OverflowError: If the integer is too large to fit in 2 bytes.
    """

    return x.to_bytes(2, "little")


def p8(x: int):
    """
    Converts an integer into an 8-bit (1-byte) little-endian byte sequence.

    :param x: The integer to convert.
    :return: A 1-byte sequence representing the integer.
    :exception OverflowError: If the integer is too large to fit in 1 byte.
    """

    return x.to_bytes(1, "little")
