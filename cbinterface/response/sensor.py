"""Functions that work with Carbon Black Sensors.
"""

import datetime
import logging

from typing import Union

from cbapi.response import CbResponseAPI, Sensor
from cbapi.response.models import SensorQuery

from cbinterface.helpers import as_configured_timezone

LOGGER = logging.getLogger("cbinterface.response.sensor")


def is_sensor_online(s: SensorQuery) -> bool:
    """Return True if the sensor is online."""
    s.refresh()
    LOGGER.debug(f"sensor status: {s.status}")
    if s.status.lower() == "online":
        return True
    return False


def make_sensor_query(cb: CbResponseAPI, sensor_query: str) -> SensorQuery:
    """Construct a SensorQuery object."""
    try:
        if ":" not in sensor_query:
            LOGGER.warning("No field specification passed. Fields: ip, hostname, groupid")
            LOGGER.info(f"Making assumption and updating query to: 'hostname:{sensor_query}'")
            sensor_query = f"hostname:{sensor_query}"
        sensors = cb.select(Sensor).where(sensor_query)
    except ValueError as e:
        LOGGER.error(f"{e}")
        return False
    LOGGER.info(f"got {len(sensors)} sensor results.")
    return sensors


def find_sensor_by_hostname(cb: CbResponseAPI, hostname: str) -> Sensor:
    """Find a Sensor by hostname."""
    sensors = make_sensor_query(cb, f"hostname:{hostname}")
    if len(sensors) == 1:
        return sensors[0]
    elif len(sensors) > 1:
        LOGGER.warning(f"{len(sensors)} sensors with hostname={hostname}")
        return None
    return None


def sensor_info(sensor: Sensor):
    from cbinterface.helpers import utc_offset_to_potential_tz_names

    text = "\n"
    text += f"Sensor object - {sensor.webui_link}\n"
    text += "-------------------------------------------------------------------------------\n"
    text += f"\tcb_build_version_string: {sensor.build_version_string}\n"
    text += f"\tcomputer_sid: {sensor.computer_sid}\n"
    text += f"\tcomputer_dns_name: {sensor.computer_dns_name}\n"
    text += f"\tcomputer_name: {sensor.computer_name}\n"
    text += f"\tos_environment_display_string: {sensor.os_environment_display_string}\n"
    text += f"\tphysical_memory_size: {sensor.physical_memory_size}\n"
    text += f"\tsystemvolume_free_size: {sensor.systemvolume_free_size}\n"
    text += f"\tsystemvolume_total_size: {sensor.systemvolume_total_size}\n"
    text += "\n"
    text += f"\tstatus: {sensor.status}\n"
    text += f"\tis_isolating: {sensor.is_isolating}\n"
    text += f"\tsensor_id: {sensor.id}\n"
    potential_tz_names = utc_offset_to_potential_tz_names(sensor.last_checkin_time.tzinfo._offset)
    potential_regions = f"{len(potential_tz_names)} potential regions."
    if len(potential_tz_names) == 1:
        potential_regions = potential_tz_names[0]
    text += f"\tsensor_timezone: GMT{sensor.last_checkin_time.strftime('%z')} - {potential_regions}\n"
    text += f"\tlast_checkin_time: {as_configured_timezone(sensor.last_checkin_time)}\n"
    text += f"\tnext_checkin_time: {as_configured_timezone(sensor.next_checkin_time)}\n"
    text += f"\tsensor_health_message: {sensor.sensor_health_message}\n"
    text += f"\tsensor_health_status: {sensor.sensor_health_status}\n"
    text += "\tnetwork_interfaces:\n"
    for ni in sensor.network_interfaces:
        text += f"\t\t{ni}\n"
    return text
