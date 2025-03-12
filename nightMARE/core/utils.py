# coding: utf-8

import pathlib
import typing
import requests

from nightMARE.core import cast
from nightMARE.core import common_regex

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
}


def convert_bytes_to_base64_in_dict(
    data: dict[str, typing.Any],
) -> dict[str, typing.Any]:
    """
    Recursively convert bytes value(s) to base64 in a dictionary.

    :param data: The dictionary to convert.
    :return: The converted dictionary.
    """

    t = type(data)
    if t == dict:
        for key, value in data.items():
            data[key] = convert_bytes_to_base64_in_dict(value)
        return data
    elif t == list:
        return [convert_bytes_to_base64_in_dict(x) for x in data]
    elif t == bytes:
        return cast.bytes_to_b64_str(data)
    else:
        return data


def download_aux(
    url: str, is_json: bool, *args, **kwargs
) -> dict[str, typing.Any] | bytes:
    if not (response := requests.get(url, headers=HEADERS, *args, **kwargs)).ok:
        raise RuntimeError(f"Failed to download {url}, code:{response.status_code}")

    return response.json() if is_json else response.content


def download(url: str, *args, **kwargs) -> bytes:
    return typing.cast(bytes, download_aux(url, False, *args, **kwargs))


def download_json(url: str, *args, **kwargs) -> dict[str, typing.Any]:
    return typing.cast(dict[str, typing.Any], download_aux(url, True, *args, **kwargs))


def map_files_directory(
    path: pathlib.Path, function: typing.Callable[[pathlib.Path], typing.Any]
) -> list[tuple[pathlib.Path, typing.Any]]:
    """
    The function recursively walk directory and call provided parameter function on each file
    :param path: Root directory path
    :function: Function that'll be called on each file
    :return: List of tuple containing the file path and the result returned by the provided function
    """
    if not path.is_dir():
        raise RuntimeError("Path is not a directory")

    return [(x, function(x)) for x in path.rglob("*")]


def write_files(directory: pathlib.Path, files: dict[str, bytes]) -> None:
    """
    The function write files in the given directory
    :param directory: Directory where the files will be written
    :param files: Dictionnary of file name and associated
    """

    for filename, data in files.items():
        directory.joinpath(filename).write_bytes(data)


def is_base64(s: bytes) -> bool:
    return bool(common_regex.BASE64_REGEX.fullmatch(s))


def is_url(s: bytes) -> bool:
    return bool(common_regex.URL_REGEX.fullmatch(s))
