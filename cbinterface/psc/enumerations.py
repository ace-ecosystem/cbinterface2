"""Functions for enumerations or correlations.

Example, enumerating USB activity on a sensor from a programatic
analysis of registry modifications.
"""
import os
import logging

from cbapi.psc.rest_api import CbPSCBaseAPI

from cbinterface.helpers import as_configured_timezone


LOGGER = logging.getLogger("cbinterface.psc.enumerations")


def search_for_usb_devices(cb: CbPSCBaseAPI, query):
    # XXX - This doesn't look implemented in TH?
    uri = f"/device_control/v3/orgs/{cb.credentials.org_key}/devices/_search"
    data = {"query": query}
    return cb.post_object(uri, data).json()


def logon_history(cb: CbPSCBaseAPI, hostname_or_username_query) -> None:
    """Given hostname or username, enumerate logon history.

    Note, this is an analysis of the WINDOWS behavior when a new user
    session is started. It's informative for analysts, not authoritative.
    It will NOT show processes ran under other users, as often is the case
    with enterprise admin activity.
    """
    from cbinterface.psc.query import make_process_query

    if not (
        hostname_or_username_query.startswith("device_name:")
        or hostname_or_username_query.startswith("process_username:")
    ):
        LOGGER.info(f"use 'device_name:' or 'process_username:' field to narrow enumeration search.")

    # query = f"process_name:userinit.exe parent_name:winlogon.exe {hostname_or_username_query}"
    # XXX will catch more than "log on"
    query = f"process_name:explorer.exe {hostname_or_username_query}"

    processes = make_process_query(cb, query)
    if processes and len(processes) > 0:
        timezone_string = os.environ.get("CBINTERFACE_TIMEZONE", "GMT")
        print(f"\n\t{timezone_string} Time    \t|\tUsername\t|\tHostname")
        for proc in processes:
            start_time = as_configured_timezone(proc.process_start_time, apply_time_format="%Y-%m-%d %H:%M:%S%z")
            username = proc.process_username[0]
            print("  {}\t    {}\t\t{}".format(start_time, username, proc.device_name))
        print()
    return
