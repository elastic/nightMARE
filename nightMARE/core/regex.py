# coding: utf-8

import enum
import re
import functools


class RegexOptions(enum.Enum):
    """
    An enumeration of identifiers for predefined regular expression patterns.
    """

    BASE64_REGEX = enum.auto()
    DOMAIN_REGEX = enum.auto()
    GUID_REGEX = enum.auto()
    HEX_STRING_REGEX = enum.auto()
    IP_REGEX = enum.auto()
    IP_PORT_REGEX = enum.auto()
    PORT_REGEX = enum.auto()
    PRINTABLE_STRING_REGEX = enum.auto()
    URL_REGEX = enum.auto()


MAP = {
    RegexOptions.BASE64_REGEX: r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$",
    RegexOptions.DOMAIN_REGEX: r"([\w.-]+\.[a-zA-Z]{2,})(?::(\d{1,5}))?",
    RegexOptions.GUID_REGEX: r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    RegexOptions.HEX_STRING_REGEX: r"^[0-9a-fA-F]+$",
    RegexOptions.IP_REGEX: r"((\d{1,3}\.){3}(\d{1,3}))",
    RegexOptions.IP_PORT_REGEX: r"((\d{1,3}\.){3}(\d{1,3})):(\d+)",
    RegexOptions.PORT_REGEX: r"^\d{1,5}$",
    RegexOptions.PRINTABLE_STRING_REGEX: r"[\x20-\x7E]{4,}",
    RegexOptions.URL_REGEX: r"(https?):\/\/([\w.-]+)(:(\d+))?(\/.+)?",
}


@functools.cache
def get_regex(option: RegexOptions, is_bytes: bool):
    """
    Retrieves a cached, compiled regular expression pattern as either string or bytes.

    :param option: The `RegexOptions` enum member specifying the desired pattern.
    :param is_bytes: If True, returns a compiled bytes pattern; otherwise, returns a string pattern.
    :return: A compiled regular expression object.
    """

    pattern = MAP[option]
    if is_bytes:
        pattern = pattern.encode("utf-8")
    return re.compile(pattern)
