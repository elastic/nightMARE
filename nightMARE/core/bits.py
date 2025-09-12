# coding: utf-8


def rol(x: int, n: int, max_bits: int) -> int:
    """
    Performs a bitwise rotate left (ROL) operation on an integer.

    :param x: The integer value to rotate.
    :param n: The number of positions to rotate left.
    :param max_bits: The maximum number of bits for the integer (e.g., 8, 16, 32, 64).
    :return: The result of the left rotation.
    """

    return (x << n % max_bits) & (2**max_bits - 1) | (
        (x & (2**max_bits - 1)) >> (max_bits - (n % max_bits))
    )


def ror(x: int, n: int, max_bits: int) -> int:
    """
    Performs a bitwise rotate right (ROR) operation on an integer.

    :param x: The integer value to rotate.
    :param n: The number of positions to rotate right.
    :param max_bits: The maximum number of bits for the integer (e.g., 8, 16, 32, 64).
    :return: The result of the right rotation.
    """

    return ((x & (2**max_bits - 1)) >> n % max_bits) | (
        x << (max_bits - (n % max_bits)) & (2**max_bits - 1)
    )


def rol8(x: int, n: int):
    """
    Performs an 8-bit rotate left operation.

    :param x: The 8-bit integer to rotate.
    :param n: The number of positions to rotate left.
    :return: The result of the 8-bit left rotation.
    """

    return rol(x, n, 8)


def rol16(x: int, n: int):
    """
    Performs a 16-bit rotate left operation.

    :param x: The 16-bit integer to rotate.
    :param n: The number of positions to rotate left.
    :return: The result of the 16-bit left rotation.
    """

    return rol(x, n, 16)


def rol32(x: int, n: int):
    """
    Performs a 32-bit rotate left operation.

    :param x: The 32-bit integer to rotate.
    :param n: The number of positions to rotate left.
    :return: The result of the 32-bit left rotation.
    """

    return rol(x, n, 32)


def rol64(x: int, n: int):
    """
    Performs a 64-bit rotate left operation.

    :param x: The 64-bit integer to rotate.
    :param n: The number of positions to rotate left.
    :return: The result of the 64-bit left rotation.
    """

    return rol(x, n, 64)


def ror8(x: int, n: int):
    """
    Performs an 8-bit rotate right operation.

    :param x: The 8-bit integer to rotate.
    :param n: The number of positions to rotate right.
    :return: The result of the 8-bit right rotation.
    """

    return ror(x, n, 8)


def ror16(x: int, n: int):
    """
    Performs a 16-bit rotate right operation.

    :param x: The 16-bit integer to rotate.
    :param n: The number of positions to rotate right.
    :return: The result of the 16-bit right rotation.
    """

    return ror(x, n, 16)


def ror32(x: int, n: int):
    """
    Performs a 32-bit rotate right operation.

    :param x: The 32-bit integer to rotate.
    :param n: The number of positions to rotate right.
    :return: The result of the 32-bit right rotation.
    """

    return ror(x, n, 32)


def ror64(x: int, n: int):
    """
    Performs a 64-bit rotate right operation.

    :param x: The 64-bit integer to rotate.
    :param n: The number of positions to rotate right.
    :return: The result of the 64-bit right rotation.
    """

    return ror(x, n, 64)


def swap32(x: int):
    """
    Swaps the byte order of a 32-bit integer (endianness conversion).

    :param x: The 32-bit integer to byte-swap.
    :return: The byte-swapped 32-bit integer.
    """

    return (rol32(x, 8) & 0x00FF00FF) | (rol32(x, 24) & 0xFF00FF00)


def xor(data: bytes, key: bytes) -> bytes:
    """
    Encrypts or decrypts data using a repeating XOR key.

    :param data: The input data as a bytes object.
    :param key: The key as a bytes object; it will be repeated to match the data length.
    :return: The result of the XOR operation as a bytes object.
    """

    data = bytearray(data)
    for i in range(len(data)):
        data[i] ^= key[i % len(key)]
    return bytes(data)
