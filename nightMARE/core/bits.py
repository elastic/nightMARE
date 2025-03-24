# coding: utf-8


def rol(x: int, n: int, max_bits: int) -> int:
    """
    Performs a bitwise rotate left operation on the input number.

    :param x: The input number to rotate
    :param n: Number of bits to rotate left
    :param max_bits: The size in bits of the input number
    :return: The result of the left rotation

    """
    return (x << n % max_bits) & (2**max_bits - 1) | (
        (x & (2**max_bits - 1)) >> (max_bits - (n % max_bits))
    )


def ror(x: int, n: int, max_bits: int) -> int:
    """
    Performs a bitwise rotate right operation on the input number.

    :param x: The input number to rotate
    :param n: Number of bits to rotate right
    :param max_bits: The size in bits of the input number
    :return: The result of the right rotation
    """

    return ((x & (2**max_bits - 1)) >> n % max_bits) | (
        x << (max_bits - (n % max_bits)) & (2**max_bits - 1)
    )


def rol8(x: int, n: int):
    """
    Performs a bitwise 8-bit rotate left operation on the input number.

    :param x: The 8-bit input number to rotate
    :param n: Number of bits to rotate left
    :return: The result of the 8-bit left rotation
    """

    return rol(x, n, 8)


def rol16(x: int, n: int):
    """
    Performs a bitwise 16-bit rotate left operation on the input number.

    :param x: The 16-bit input number to rotate
    :param n: Number of bits to rotate left
    :return: The result of the 16-bit left rotation
    """

    return rol(x, n, 16)


def rol32(x: int, n: int):
    """
    Performs a bitwise 32-bit rotate left operation on the input number.

    :param x: The 32-bit input number to rotate
    :param n: Number of bits to rotate left
    :return: The result of the 32-bit left rotation
    """

    return rol(x, n, 32)


def rol64(x: int, n: int):
    """
    Performs a bitwise 64-bit rotate left operation on the input number.

    :param x: The 64-bit input number to rotate
    :param n: Number of bits to rotate left
    :return: The result of the 64-bit left rotation
    """

    return rol(x, n, 64)


def ror8(x: int, n: int):
    """
    Performs a bitwise 8-bit rotate right operation on the input number.

    :param x: The 8-bit input number to rotate
    :param n: Number of bits to rotate right
    :return: The result of the 8-bit right rotation
    """

    return ror(x, n, 8)


def ror16(x: int, n: int):
    """
    Performs a bitwise 16-bit rotate right operation on the input number.

    :param x: The 16-bit input number to rotate
    :param n: Number of bits to rotate right
    :return: The result of the 16-bit right rotation
    """

    return ror(x, n, 16)


def ror32(x: int, n: int):
    """
    Performs a bitwise 32-bit rotate right operation on the input number.

    :param x: The 32-bit input number to rotate
    :param n: Number of bits to rotate right
    :return: The result of the 32-bit right rotation
    """

    return ror(x, n, 32)


def ror64(x: int, n: int):
    """
    Performs a bitwise 64-bit rotate right operation on the input number.

    :param x: The 64-bit input number to rotate
    :param n: Number of bits to rotate right
    :return: The result of the 64-bit right rotation
    """

    return ror(x, n, 64)


def swap32(x: int):
    """
    Performs a byte swap on a 32-bit input number.

    :param x: The 32-bit input number to swap
    :return: The result of the 32-bit byte swap
    """

    return (rol32(x, 8) & 0x00FF00FF) | (rol32(x, 24) & 0xFF00FF00)


def xor(data: bytes, key: bytes) -> bytes:
    """
    Performs a bitwise XOR operation between data and a repeating key.

    :param data: The input data to XOR
    :param key: The key to XOR with, repeated as necessary
    :return: The XORed result as bytes
    """

    data = bytearray(data)
    for i in range(len(data)):
        data[i] ^= key[i % len(key)]
    return bytes(data)
