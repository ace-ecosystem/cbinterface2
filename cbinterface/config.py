"""Configuration related items.
"""

import os
import logging

from configparser import ConfigParser
from dateutil import tz
from dateutil.zoneinfo import get_zonefile_instance

LOGGER = logging.getLogger("cbinterface.config")

HOME_PATH = os.path.dirname(os.path.abspath(__file__))

user_config_path = os.path.join(os.path.expanduser("~"), ".carbonblack", "cbinterface.ini")
CONFIG_SEARCH_PATHS = [
    "/etc/carbonblack/cbinterface.ini",
    user_config_path,
]

CONFIG = ConfigParser()
CONFIG.read(CONFIG_SEARCH_PATHS)

if not CONFIG.has_section("default"):
    CONFIG.add_section("default")

if not CONFIG.has_option("default", "max_recursive_depth"):
    CONFIG.set("default", "max_recursive_depth", "50")
MAX_RECURSIVE_DEPTH = CONFIG.getint("default", "max_recursive_depth")
# TODO need to actually use max recursive depth and max segments


def save_configuration(config: ConfigParser = CONFIG, save_path=user_config_path):
    """Write config to save_path."""
    if save_path == user_config_path:
        if not os.path.exists(user_config_path):
            os.mkdir(os.path.join(os.path.expanduser("~"), ".carbonblack"))
    try:
        with open(save_path, "w") as fp:
            config.write(fp)
    except FileNotFoundError:
        LOGGER.error(f"part of path does not exist: {save_path}")
    if os.path.exists(save_path):
        LOGGER.info(f"saved configuration to: {save_path}")


def _is_valid_time_zone(zone: str):
    """True if zone is a valid time zone."""
    if zone in list(get_zonefile_instance().zones):
        return True
    return False


def set_timezone(time_zone: str):
    if not _is_valid_time_zone(time_zone):
        LOGGER.error(f"Not a recongnized time zone: {time_zone}")
        return False
    os.environ["CBINTERFACE_TIMEZONE"] = time_zone
    CONFIG.set("default", "time_zone", time_zone)
    return True


def get_timezone():
    return tz.gettz(os.environ.get("CBINTERFACE_TIMEZONE", "GMT"))


if "CBINTERFACE_TIMEZONE" not in os.environ:
    # timestamps from Cb are not timezone aware, but they are GMT.
    set_timezone(CONFIG.get("default", "time_zone", fallback="GMT"))
