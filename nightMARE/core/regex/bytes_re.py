# coding: utf-8

import re

BASE64_REGEX = re.compile(
    rb"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$"
)

DOMAIN_REGEX = re.compile(rb"([\w.-]+\.[a-zA-Z]{2,}):(\d{1,5})")

IP_REGEX = re.compile(rb"((\d{1,3}\.){3}(\d{1,3}))")

IP_PORT_REGEX = re.compile(rb"((\d{1,3}\.){3}(\d{1,3})):(\d+)")

PORT_REGEX = re.compile(rb"^[0-9]{1,5}$")

PRINTABLE_STRING_REGEX = re.compile(rb"[\x20-\x7E]{4,}")

URL_REGEX = re.compile(rb"(https?):\/\/([\w.-]+)(:(\d+))?(\/.+)?")
