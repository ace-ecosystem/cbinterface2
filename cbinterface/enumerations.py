"""Functions for enumerations or correlations.

Example, enumerating USB activity on a sensor from a programatic
analysis of registry modifications.
"""

import datetime
import logging
from dateutil import tz
from cbapi.response import CbResponseAPI, Process

LOGGER = logging.getLogger("cbinterface.query")


def logon_history(cb: CbResponseAPI, hostname_or_username_query):
    """Given hostname or username, enumerate logon history.

    Note, this is an analysis of the WINDOWS behavior when a new user
    session is started. It's informative for analysts, not authoritative.
    """
    from cbinterface.query import make_process_query

    if not (hostname_or_username_query.startswith("hostname:") or hostname_or_username_query.startswith("username:")):
        LOGGER.error(f"Must supply 'hostname:' or 'username:' field and value.")
        return False

    query = f"process_name:userinit.exe parent_name:winlogon.exe {hostname_or_username_query}"

    processes = make_process_query(cb, query)
    if processes and len(processes) > 0:
        print("\n\tEastern Time    \t|\tUsername\t|\tHostname")
        for proc in processes:
            start_time = str(proc.start)
            start_time = start_time[: start_time.rfind(".")] + " UTC"
            print("  {}\t    {}\t\t{}".format(start_time, proc.username, proc.hostname))
        print()
    return
