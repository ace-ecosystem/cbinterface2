"""Helper functions for common actions.
"""

import os
import re
import logging
import datetime

from pathlib import PureWindowsPath, PurePosixPath
from typing import Union

from dateutil import tz
from dateutil.zoneinfo import get_zonefile_instance

LOGGER = logging.getLogger("cbinterface.helpers")

UUID_REGEX = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def is_uuid(uuid: str):
    """Returns True if the given string matches the UUID pattern."""
    return UUID_REGEX.match(uuid)


def get_os_independant_filepath(unknown_os_file_path: str) -> Union[PureWindowsPath, PurePosixPath]:
    """Return a proper os filepath object."""
    filepath = PureWindowsPath(unknown_os_file_path)
    nixfilepath = PurePosixPath(unknown_os_file_path)
    if len(nixfilepath.parts) > len(filepath.parts):
        filepath = nixfilepath
    return filepath


def as_configured_timezone(timestamp: Union[datetime.datetime, str], apply_time_format="%Y-%m-%d %H:%M:%S.%f%z") -> str:
    """Convert timestamp to the configured time zone."""
    from cbinterface.config import get_timezone

    if isinstance(timestamp, str):
        try:
            timestamp = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            LOGGER.warning(f"ValueError trying to parse '{timestamp}' with '%Y-%m-%d %H:%M:%S.%f'")
            return timestamp

    # the timestamps from CbR are not timezone aware, but they are GMT.
    timestamp = timestamp.replace(tzinfo=tz.gettz("GMT")) if timestamp.tzinfo is None else timestamp
    return timestamp.astimezone(get_timezone()).strftime(apply_time_format)


def utc_offset_to_potential_tz_names(utc_offset: datetime.timedelta):
    potential_zones = []
    utc_now = datetime.datetime.utcnow()
    for zone in list(get_zonefile_instance().zones):
        dt = utc_now.astimezone(tz.gettz(zone))
        if dt.utcoffset() == utc_offset:
            potential_zones.append(zone)

    return list(sorted(potential_zones))
