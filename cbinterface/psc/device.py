"""Functions that work with Carbon Black Sensors.
"""

import datetime
import logging

from typing import Union

from cbapi.psc import Device
from cbapi.psc.threathunter import CbThreatHunterAPI
from cbapi.psc.devices_query import DeviceSearchQuery

from cbinterface.helpers import as_configured_timezone

LOGGER = logging.getLogger("cbinterface.device")


# XXX Not implemented
def is_device_online(d: Device) -> bool:
    """Return True if the device is online."""
    # TODO no more online status.. make quick last checkin time calculation
    # and tell the analyst how many mintues, hours, days, etc. it's been since the device
    # checked in
    raise NotImplementedError
    d.refresh()
    LOGGER.debug(f"device status: {d.status}")
    if s.status.lower() == "online":
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
        return devices[0]
    elif len(devices) > 1:
        LOGGER.warning(f"{len(devices)} devices with name={name}")
        return None
    return None


def time_since_checkin(device: Device, refresh=True) -> datetime.timedelta:
    """Return the time since last device checkin."""
    from dateutil import tz
    from dateutil.parser import isoparse

    if refresh:
        device.refresh()
    now = datetime.datetime.utcnow().replace(tzinfo=tz.UTC)
    return now - isoparse(device.last_contact_time)


def device_info(device: Device, refresh=False):
    """Print device info."""
    from cbinterface.helpers import utc_offset_to_potential_tz_names

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
    text += f"\tDevice Registration Time: {as_configured_timezone(device.registered_time)}\n"
    text += f"\tLast Checkin Time: {as_configured_timezone(device.last_contact_time)}\n"
    text += "\t " + "\u21B3" + f" Elapsed Time: {time_since_checkin(device, refresh=False)}\n"
    text += f"\tLast Reported Event Time: {as_configured_timezone(device.last_reported_time)}\n"
    text += f"\tLast External IP: {device.last_external_ip_address}\n"
    text += f"\tLast Internal IP: {device.last_internal_ip_address}\n"
    text += f"\tLast Location: {device.last_location}\n"
    text += f"\tLast Logged In User: {device.login_user_name}\n"
    text += f"\tSensor status: {device.status}\n"
    text += f"\tSensor Version: {device.sensor_version}\n"
    text += "\n"
    return text
