"""Configuration related items."""

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
if not CONFIG.has_section("intel_backup"):
    CONFIG.add_section("intel_backup")

if not CONFIG.has_option("default", "max_recursive_depth"):
    CONFIG.set("default", "max_recursive_depth", "50")
MAX_RECURSIVE_DEPTH = CONFIG.getint("default", "max_recursive_depth")
# TODO need to actually use max recursive depth and max segments


"""
Begin Management & Helper Functions
"""


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


def _is_valid_time_zone(zone: str):
    """True if zone is a valid time zone."""
    if zone in list(get_zonefile_instance().zones):
        return True
    return False


def set_timezone(time_zone: str):
    """Set cbinterface timezone."""
    if not _is_valid_time_zone(time_zone):
        LOGGER.error(f"Not a recongnized time zone: {time_zone}")
        return False
    os.environ["CBINTERFACE_TIMEZONE"] = time_zone
    CONFIG.set("default", "time_zone", time_zone)
    return True


def get_timezone():
    """Get cbinterface timezone."""
    return tz.gettz(os.environ.get("CBINTERFACE_TIMEZONE", "GMT"))


def set_default_cb_product(env_product: str):
    """Set Carbon Black product."""
    os.environ["CBINTERFACE_DEFAULT_CB_PRODUCT"] = env_product
    CONFIG.set("default", "cb_product", env_product)
    return True


def get_default_cb_product():
    """Get Carbon Black product."""
    return os.environ.get("CBINTERFACE_DEFAULT_CB_PRODUCT", "enterprise_edr")


def set_default_cb_profile(profile: str):
    """Set CB profile/environment."""
    os.environ["CBINTERFACE_DEFAULT_CB_PROFILE"] = profile
    CONFIG.set("default", "cb_profile", profile)
    return True


def get_default_cb_profile():
    """Get CB profile/environment."""
    return os.environ.get("CBINTERFACE_DEFAULT_CB_PROFILE", "default")


def set_and_establish_data_directory(data_dir_path: str = "."):
    """Set a default data directory.

    cbinterface will use this directory to save content, such as intel backup files.
    If not defined, the current working directory will be used.

    If the data directory does not exist, an attempt to create it will execute.
    """
    os.environ["CBINTERFACE_DATA_DIR"] = data_dir_path
    CONFIG.set("default", "data_dir", data_dir_path)
    if not os.path.exists(data_dir_path):
        from pathlib import Path

        Path(data_dir_path).mkdir(parents=True, exist_ok=True)
        if not os.path.exists(data_dir_path):
            LOGGER.warning(f"failed to create {data_dir_path}")
            return False
    return True


def get_data_directory():
    """Get the default data directory."""
    return os.environ.get("CBINTERFACE_DATA_DIR", ".")


def add_watchlist_id_to_intel_backup_list(watchlist_id: str):
    """Append this valid watchlist ID to the configured backup list.

    This list is used to track watchlists that should be backed up by routines.
    """
    watchlist_ids = CONFIG.get("intel_backup", "watchlist_id_list", fallback=[])
    if watchlist_ids:
        watchlist_ids = watchlist_ids.split(",")
    if watchlist_id not in watchlist_ids:
        watchlist_ids.append(watchlist_id)
        watchlist_ids = ",".join(watchlist_ids)
        CONFIG.set("intel_backup", "watchlist_id_list", watchlist_ids)
        save_configuration()
    return True


def remove_watchlist_id_from_intel_backup_list(watchlist_id: str):
    """Append this valid watchlist ID to the configured backup list.

    This list is used to track watchlists that should be backed up by routines.
    """
    watchlist_ids = CONFIG.get("intel_backup", "watchlist_id_list", fallback="").split(",")
    if watchlist_id in watchlist_ids:
        watchlist_ids.remove(watchlist_id)
        watchlist_ids = ",".join(watchlist_ids)
        CONFIG.set("intel_backup", "watchlist_id_list", watchlist_ids)
        save_configuration()
    return True


def get_intel_backup_watchlist_list():
    """Get the list of watchlist IDs that are tracked."""
    watchlist_ids = CONFIG.get("intel_backup", "watchlist_id_list", fallback=[])
    if watchlist_ids:
        watchlist_ids = watchlist_ids.split(",")
    return watchlist_ids


"""
Set variables.
"""
if "CBINTERFACE_TIMEZONE" not in os.environ:
    # timestamps from Cb are not timezone aware, but they are GMT.
    set_timezone(CONFIG.get("default", "time_zone", fallback="GMT"))

if "CBINTERFACE_DEFAULT_CB_PRODUCT" not in os.environ:
    set_default_cb_product(CONFIG.get("default", "cb_product", fallback="enterprise_edr"))

if "CBINTERFACE_DEFAULT_CB_PROFILE" not in os.environ:
    set_default_cb_profile(CONFIG.get("default", "cb_profile", fallback="default"))

if "CBINTERFACE_DATA_DIR" not in os.environ:
    set_and_establish_data_directory(CONFIG.get("default", "data_dir", fallback="."))
