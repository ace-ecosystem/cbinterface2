"""Helper functions for common actions.
"""

import re
import logging
from pathlib import PureWindowsPath, PurePosixPath
from typing import Union

# TODO:
# from .helpers import as_configured_timezone

LOGGER = logging.getLogger("cbinterface.helpers")

UUID_REGEX = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def is_uuid(uuid):
    """Returns True if the given string matches the UUID pattern."""
    return UUID_REGEX.match(uuid)


def get_os_independant_filepath(unknown_os_file_path: str) -> Union[PureWindowsPath, PurePosixPath]:
    """Return a proper os filepath object."""
    filepath = PureWindowsPath(unknown_os_file_path)
    nixfilepath = PurePosixPath(unknown_os_file_path)
    if len(nixfilepath.parts) > len(filepath.parts):
        filepath = nixfilepath
    return filepath
