"""Helper functions for common actions.
"""

import os
import re
import sys
import signal
import logging
import datetime

from pathlib import PureWindowsPath, PurePosixPath
from typing import Union

from dateutil import tz
from dateutil.parser import isoparse
from dateutil.zoneinfo import get_zonefile_instance

LOGGER = logging.getLogger("cbinterface.helpers")

UUID_REGEX = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
PSC_GUID_REGEX = re.compile(r"[0-9A-Z]{8}-[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{15}", re.I)


def is_uuid(uuid: str):
    """Returns True if the given string matches the UUID pattern."""
    return UUID_REGEX.match(uuid)


def is_psc_guid(guid: str):
    """Returns True if the given string matches the format of a PSC GUID."""
    return PSC_GUID_REGEX.match(guid)


def input_with_timeout(prompt, default=None, timeout=30, stderr=True):
    """Wait up to timeout for user input"""

    def _log_and_exit(signum, frame):
        if stderr:
            sys.stderr.write("\n")
        else:
            sys.stdout.write("\n")
        LOGGER.error("Timeout reached waiting for input.")
        sys.exit()

    signal.signal(signal.SIGALRM, _log_and_exit)
    signal.alarm(timeout)
    if stderr:
        sys.stderr.write(prompt)
    else:
        sys.stdout.write(prompt)
    answer = input() or default
    signal.alarm(0)
    return answer


def clean_exit(signal, frame):
    print()
    LOGGER.info(f"caught KeyboardInterrupt. exiting.")
    sys.exit(0)


def get_os_independent_filepath(unknown_os_file_path: str) -> Union[PureWindowsPath, PurePosixPath]:
    """Return a proper os filepath object."""
    filepath = PureWindowsPath(unknown_os_file_path)
    nixfilepath = PurePosixPath(unknown_os_file_path)
    if len(nixfilepath.parts) > len(filepath.parts):
        filepath = nixfilepath
    return filepath


def as_configured_timezone(timestamp: Union[datetime.datetime, str], apply_time_format="%Y-%m-%d %H:%M:%S.%f%z") -> str:
    """Convert timestamp to the configured time zone."""
    from cbinterface.config import get_timezone

    if not timestamp:
        return timestamp

    if isinstance(timestamp, str):
        # psc
        try:
            timestamp = isoparse(timestamp)
        except ValueError:
            return ""

    if isinstance(timestamp, str):
        # legacy format
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


def create_histogram_string(data: dict) -> str:
    """A convenience function that creates a graph in the form of a string.
    Args:
        data: A dictionary, where the values are integers representing a count of the keys.
    Returns:
        A graph in string form, pre-formatted for raw printing.
    """

    assert isinstance(data, dict)
    for key in data.keys():
        assert isinstance(data[key], int)

    total_results = sum([value for value in data.values()])
    txt = ""

    # order keys for printing in order (purly ascetics)
    ordered_keys = sorted(data, key=lambda k: data[k])
    results = []

    # longest_key used to calculate how many white spaces should be printed
    # to make the graph columns line up with each other
    longest_key = 0
    for key in ordered_keys:
        value = data[key]
        longest_key = len(key) if len(key) > longest_key else longest_key
        # IMPOSING LIMITATION: truncating keys to 95 chars, keeping longest key 5 chars longer
        longest_key = 100 if longest_key > 100 else longest_key
        percent = value / total_results * 100
        results.append((key[:95], value, percent, "\u25A0" * (int(percent / 2))))

    # two for loops are ugly, but allowed us to count the longest_key -
    # so we loop through again to print the text
    for r in results:
        txt += "%s%s: %5s - %5s%% %s\n" % (
            int(longest_key - len(r[0])) * " ",
            r[0],
            r[1],
            str(r[2])[:4],
            "\u25A0" * (int(r[2] / 2)),
        )
    return txt
