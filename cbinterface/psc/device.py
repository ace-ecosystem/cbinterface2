"""Functions that work with Carbon Black Sensors.
"""

import datetime
import logging

from typing import Dict

from cbapi.psc import Device
from cbapi.psc.threathunter import CbThreatHunterAPI
from cbapi.psc.devices_query import DeviceSearchQuery
from cbapi.errors import ServerError, ClientError

from cbinterface.helpers import convert_csv_data_to_dictionary

from cbinterface.helpers import as_configured_timezone

LOGGER = logging.getLogger("cbinterface.psc.device")

DEVICE_STATUSES = [
    "PENDING",
    "REGISTERED",
    "UNINSTALLED",
    "DEREGISTERED",
    "ACTIVE",
    "INACTIVE",
    "ERROR",
    "ALL",
    "BYPASS_ON",
    "BYPASS",
    "QUARANTINE",
    "SENSOR_OUTOFDATE",
    "DELETED",
    "LIVE",
]


def export_devices(cb: CbThreatHunterAPI, device_status: str = "ALL"):
    """Export devices with the given status to a CSV.

    Note device fields returned are limited. Use device search for all details.
    """
    url = f"/appservices/v6/orgs/{cb.credentials.org_key}/devices/_search/download?status={device_status}"
    try:
        result = cb.get_raw_data(url)
        if not result:
            return result
        return convert_csv_data_to_dictionary(result)
    except ServerError as e:
        LOGGER.error(f"Caught ServerError: {e}")
        return False
    except ClientError as e:
        LOGGER.warning(f"got ClientError: {e}")
        return False


def device_search(
    cb: CbThreatHunterAPI,
    search_data: Dict = {},
    criteria: Dict = {},
    exclusions: Dict = {},
    query: str = None,
    time_range: Dict = {},
    rows=1000,
    start: int = 0,
    sort: Dict = [{"field": "last_contact_time", "order": "asc"}],
) -> Dict:
    """Device search"""

    url = f"/appservices/v6/orgs/{cb.credentials.org_key}/devices/_search"

    if not search_data:
        if time_range and "last_contact_time" not in criteria:
            criteria["last_contact_time"] = time_range
        search_data = {
            "criteria": criteria,
            "exclusions": exclusions,
            "query": query,
            "rows": rows,
            "start": start,
            "sort": sort,
        }

    try:
        result = cb.post_object(url, search_data)
        return result.json()
    except ServerError as e:
        LOGGER.error(f"Caught ServerError searching events: {e}")
        return False
    except ClientError as e:
        LOGGER.warning(f"got ClientError searching events: {e}")
        return False
    except ValueError:
        LOGGER.warning(f"got unexpected {result}")
        return False


def yield_devices(
    cb: CbThreatHunterAPI,
    search_data: Dict = {},
    criteria: Dict = {},
    exclusions: Dict = {},
    query: str = None,
    rows=1000,
    sort: Dict = [{"field": "last_contact_time", "order": "asc"}],
    start: int = 0,
    start_time: datetime.datetime = None,
    end_time: datetime.datetime = None,
    time_range_string: str = None,
    max_results: int = None,  # limit results returned
) -> Dict:
    """Yield Alerts resulting from alert search."""

    time_range = {}
    if time_range_string:
        time_range["range"] = f"-{time_range_string}"
    else:
        if start_time:
            time_range["start"] = start_time.isoformat()
        if end_time:
            time_range["end"] = end_time.isoformat()

    position = start
    still_querying = True
    while still_querying:
        if max_results and position + rows > max_results:
            # get however many rows that may result in max_results
            rows = max_results - position
        result = device_search(
            cb,
            search_data=search_data,
            criteria=criteria,
            exclusions=exclusions,
            query=query,
            time_range=time_range,
            rows=rows,
            sort=sort,
            start=position,
        )

        if not result:
            return result

        total_results = result["num_found"]
        results = result.get("results", [])
        LOGGER.info(f"got {len(results)+position} out of {total_results} total device results.")
        for item in results:
            yield item
            position += 1
            if max_results and position >= max_results:
                still_querying = False
                break

        if position >= total_results:
            still_querying = False
            break


def is_device_online(d: Device) -> bool:
    """Return True if the device has check in within the last 15 minutes."""
    elapsed_time = time_since_checkin(d)
    LOGGER.debug(f"elapsed time since device checked in: {elapsed_time}")
    if elapsed_time < datetime.timedelta(minutes=15):
        # guesstimation. Cb documentation is lacking.
        return True
    return False


def make_device_query(cb: CbThreatHunterAPI, device_query: str) -> DeviceSearchQuery:
    """Construct a DeviceSearchQuery object."""
    try:
        if ":" not in device_query:
            LOGGER.info("No field specification passed. Use 'FIELDS' for help.")
        devices = cb.select(Device).where(device_query)
    except ValueError as e:
        LOGGER.error(f"{e}")
        return False
    LOGGER.info(f"got {len(devices)} device results.")
    return devices


def find_device_by_hostname(cb: CbThreatHunterAPI, name: str) -> Device:
    """Find a Device by name."""
    devices = make_device_query(cb, f"name:{name}")
    if len(devices) == 1:
        return devices.first()
    elif len(devices) > 1:
        LOGGER.warning(f"{len(devices)} devices with name={name}")
        return None
    return None


def time_since_checkin(device: Device, refresh=True) -> datetime.timedelta:
    """Return the time since last device checkin."""
    from dateutil import tz
    from dateutil.parser import isoparse

    if not device.get("last_contact_time"):
        return None

    if refresh:
        device.refresh()
    now = datetime.datetime.utcnow().replace(tzinfo=tz.UTC)
    return now - isoparse(device.last_contact_time)


def device_info(device: Device, refresh=False):
    """Print device info."""
    if refresh:
        device.refresh()
    text = "\n"
    text += "-------------------------------------------------------------------------------\n"
    text += f"\tAD Group ID: {device.ad_group_id}\n"
    text += f"\tCurrent Policy Name: {device.current_sensor_policy_name}\n"
    text += f"\tDeployment Type: {device.deployment_type}\n"
    text += f"\tDevice ID: {device.id}\n"
    text += f"\tDevice Name: {device.name}\n"
    text += f"\tDevice MAC address: {device.mac_address}\n"
    text += f"\tDevice OS: {device.os}\n"
    text += f"\tDevice OS Version: {device.os_version}\n"
    text += f"\tDevice Owner ID: {device.device_owner_id}\n"
    text += f"\tDevice Owner Email: {device.email}\n"
    text += f"\tDevice Owner Name: {device.last_name}, {device.first_name}\n"
    quarantined_message = "🚫 DEVICE QUARANTINED 🚫" if device.quarantined else device.quarantined
    text += f"\tDevice Quarantined: {quarantined_message}\n"
    text += f"\tDevice Registration Time: {as_configured_timezone(device.registered_time)}\n"
    text += f"\tLast Checkin Time: {as_configured_timezone(device.get('last_contact_time'))}\n"
    elapsed_time = time_since_checkin(device, refresh=False)
    online_emotion = "appears online ✅" if elapsed_time < datetime.timedelta(minutes=15) else "likely offline 💤"
    text += "\t " + "\u21B3" + f" Elapsed Time: {elapsed_time} - {online_emotion}\n"
    text += f"\tLast Reported Event Time: {as_configured_timezone(device.last_reported_time)}\n"
    text += f"\tLast External IP: {device.last_external_ip_address}\n"
    text += f"\tLast Internal IP: {device.last_internal_ip_address}\n"
    text += f"\tLast Location: {device.last_location}\n"
    text += f"\tLast Logged In User: {device.login_user_name}\n"
    text += f"\tSensor status: {device.status}\n"
    text += f"\tSensor Version: {device.sensor_version}\n"
    text += "\n"
    return text
