# coding: utf-8


def u64(x: bytes):
    """
    Converts the first 8 bytes of a byte sequence to an unsigned 64-bit integer.

    :param x: The byte sequence to convert
    :return: The unsigned 64-bit integer value
    :raise: ValueError: If fewer than 8 bytes are provided
    """

    return int.from_bytes(x[0:8], "little")


def u32(x: bytes):
    """
    Converts the first 4 bytes of a byte sequence to an unsigned 32-bit integer.

    :param x: The byte sequence to convert
    :return: The unsigned 32-bit integer value
    :raise: ValueError: If fewer than 4 bytes are provided
    """

    return int.from_bytes(x[0:4], "little")


def u16(x: bytes):
    """
    Converts the first 2 bytes of a byte sequence to an unsigned 16-bit integer.

    :param x: The byte sequence to convert
    :return: The unsigned 16-bit integer value
    :raise: ValueError: If fewer than 2 bytes are provided
    """

    return int.from_bytes(x[0:2], "little")


def u8(x: bytes):
    """
    Converts the first byte of a byte sequence to an unsigned 8-bit integer.

    :param x: The byte sequence to convert
    :return: The unsigned 8-bit integer value
    :raise: ValueError: If no bytes are provided
    """

    return int.from_bytes(x[0:1], "little")


def p64(x: int):
    """
    Converts an integer to an 8-byte little-endian byte sequence.

    :param x: The integer to convert
    :return: The 8-byte little-endian representation
    :raise: OverflowError: If the integer cannot fit in 8 bytes
    """

    return x.to_bytes(8, "little")


def p32(x: int):
    """
    Converts an integer to a 4-byte little-endian byte sequence.

    :param x: The integer to convert
    :return: The 4-byte little-endian representation
    :raise: OverflowError: If the integer cannot fit in 4 bytes
    """

    return x.to_bytes(4, "little")


def p16(x: int):
    """
    Converts an integer to a 2-byte little-endian byte sequence.

    :param x: The integer to convert
    :return: The 2-byte little-endian representation
    :raise: OverflowError: If the integer cannot fit in 2 bytes
    """

    return x.to_bytes(2, "little")


def p8(x: int):
    """
    Converts an integer to a 1-byte little-endian byte sequence.

    :param x: The integer to convert
    :return: The 1-byte little-endian representation
    :raise: OverflowError: If the integer cannot fit in 1 byte
    """

    return x.to_bytes(1, "little")
