# coding: utf-8

import re

BASE64_REGEX = re.compile(
    rb"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"
)

IP_ADDRESS_REGEX = rb"^([0-9]{1,3}\.){3}[0-9]{1,3}$"

PRINTABLE_STRING_REGEX = re.compile(rb"[\x20-\x7E]{4,}")

PORT_REGEX = rb"^[0-9]{1,5}$"

URL_REGEX = re.compile(
    rb"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
)
