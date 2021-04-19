"""Configuration related items.
"""

import os
import logging
import glob

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
        try:
            if not os.path.exists(user_config_path):
                os.mkdir(os.path.join(os.path.expanduser("~"), ".carbonblack"))
        except FileExistsError:
            pass
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


# begin cbinterface timezone
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

# begin CbAPI product
def set_default_cbapi_product(env_product: str):
    os.environ["CBINTERFACE_DEFAULT_CBAPI_PRODUCT"] = env_product
    CONFIG.set("default", "cbapi_product", env_product)
    return True


def get_default_cbapi_product():
    return os.environ.get("CBINTERFACE_DEFAULT_CBAPI_PRODUCT", "response")


if "CBINTERFACE_DEFAULT_CBAPI_PRODUCT" not in os.environ:
    set_default_cbapi_product(CONFIG.get("default", "cbapi_product", fallback="response"))

# begin CbAPI profile/environment
def set_default_cbapi_profile(profile: str):
    os.environ["CBINTERFACE_DEFAULT_CBAPI_PROFILE"] = profile
    CONFIG.set("default", "cbapi_profile", profile)
    return True


def get_default_cbapi_profile():
    return os.environ.get("CBINTERFACE_DEFAULT_CBAPI_PROFILE", "default")


if "CBINTERFACE_DEFAULT_CBAPI_PROFILE" not in os.environ:
    set_default_cbapi_profile(CONFIG.get("default", "cbapi_profile", fallback="default"))


def get_playbook_map():
    """Load playbook config file map.

    Returns: dict of playbook name to playbook config path.
    """
    playbook_map = {}
    # package included playbooks
    playbook_paths = glob.glob(f"{HOME_PATH}/playbook_configs/*.ini")
    # configured playbooks
    if CONFIG.has_section("playbooks"):
        playbook_paths.extend(list(CONFIG["playbooks"].values()))

    for playbook_path in playbook_paths:
        playbook_name = playbook_path[playbook_path.rfind("/") + 1 : playbook_path.rfind(".")]
        playbook = ConfigParser()
        try:
            playbook.read(playbook_path)
        except Exception as e:
            LOGGER.error(f"could not load playbook: {e}")
            continue
        if playbook_name in playbook_map:
            LOGGER.error(f"playbook name collision on '{playbook_name}'. skipping this one...")
            continue
        playbook_name = playbook.get("overview", "name", fallback=playbook_name)
        playbook_description = playbook.get("overview", "description", fallback="")
        playbook_map[playbook_name] = {
            "path": playbook_path,
            "name": playbook_name,
            "description": playbook_description,
        }

    return playbook_map
