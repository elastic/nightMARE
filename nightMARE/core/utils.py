# coding: utf-8

import pathlib
import typing
import requests
import base64

from nightMARE.core.regex import bytes_re

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
}


def convert_bytes_to_base64_in_dict(data: typing.Any) -> typing.Any:
    """
    Recursively converts bytes values to base64 strings within a dictionary.

    :param data: The dictionary containing values to convert
    :return: The dictionary with bytes values converted to base64 strings
    """

    t = type(data)
    if t == dict:
        for key, value in data.items():
            data[key] = convert_bytes_to_base64_in_dict(value)
        return data
    elif t == list:
        return [convert_bytes_to_base64_in_dict(x) for x in data]
    elif t == bytes:
        return str(base64.b64encode(data), "utf-8")
    else:
        return data


def download_aux(
    url: str, is_json: bool, *args, **kwargs
) -> dict[str, typing.Any] | bytes:
    """
    Downloads content from a URL, returning JSON or raw bytes based on the is_json flag.

    :param url: The URL to download from
    :param is_json: If True, returns JSON as a dictionary; if False, returns raw bytes
    :param args: Additional positional arguments for requests.get
    :param kwargs: Additional keyword arguments for requests.get
    :return: A dictionary if is_json is True, otherwise bytes
    :raise: RuntimeError: If the download fails with a non-OK status code
    """

    if not (response := requests.get(url, headers=HEADERS, *args, **kwargs)).ok:
        raise RuntimeError(f"Failed to download {url}, code:{response.status_code}")

    return response.json() if is_json else response.content


def download(url: str, *args, **kwargs) -> bytes:
    """
    Downloads raw content from a URL as bytes.

    :param url: The URL to download from
    :param args: Additional positional arguments for requests.get
    :param kwargs: Additional keyword arguments for requests.get
    :return: The downloaded content as bytes
    :raise: RuntimeError: If the download fails with a non-OK status code
    """

    return typing.cast(bytes, download_aux(url, False, *args, **kwargs))


def download_json(url: str, *args, **kwargs) -> dict[str, typing.Any]:
    """
    Downloads and parses JSON content from a URL.

    :param url: The URL to download JSON from
    :param args: Additional positional arguments for requests.get
    :param kwargs: Additional keyword arguments for requests.get
    :return: The parsed JSON content as a dictionary
    :raise: RuntimeError: If the download fails with a non-OK status code
    """

    return typing.cast(dict[str, typing.Any], download_aux(url, True, *args, **kwargs))


def is_base64(s: bytes) -> bool:
    """
    Checks if a byte sequence matches a base64 pattern.

    :param s: The byte sequence to check
    :return: True if the sequence is valid base64, False otherwise
    """

    return bool(bytes_re.BASE64_REGEX.fullmatch(s))


def is_url(s: bytes) -> bool:
    """
    Checks if a byte sequence matches a URL pattern.

    :param s: The byte sequence to check
    :return: True if the sequence is a valid URL, False otherwise
    """

    return bool(bytes_re.URL_REGEX.fullmatch(s))


def map_files_directory(
    path: pathlib.Path, function: typing.Callable[[pathlib.Path], typing.Any]
) -> list[tuple[pathlib.Path, typing.Any]]:
    """
    Recursively walks a directory and applies a function to each file.

    :param path: The root directory path to start walking from
    :param function: The function to call on each file, taking a pathlib.Path as input
    :return: A list of tuples containing each file path and the result of the function
    :raise: RuntimeError: If the provided path is not a directory
    """

    if not path.is_dir():
        raise RuntimeError("Path is not a directory")

    return [(x, function(x)) for x in path.rglob("*")]


def write_files(directory: pathlib.Path, files: dict[str, bytes]) -> None:
    """
    Writes files to a specified directory from a dictionary of filenames and data.

    :param directory: The directory where files will be written
    :param files: A dictionary mapping filenames to their byte content
    """

    for filename, data in files.items():
        directory.joinpath(filename).write_bytes(data)
