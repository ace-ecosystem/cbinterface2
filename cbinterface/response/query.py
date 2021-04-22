"""Functions that work with query related Carbon Black APIs.
"""

import datetime
import logging
from dateutil import tz

from typing import Union

from cbapi.response import CbResponseAPI, Process
from cbapi.response.models import ProcessQuery

LOGGER = logging.getLogger("cbinterface.response.query")


def make_process_query(
    cb: CbResponseAPI,
    query: str,
    start_time: datetime.datetime = None,
    last_time: datetime.datetime = None,
    raise_exceptions=True,
) -> ProcessQuery:
    """Query the CbResponse environment and interface results.

    Args:
        cb: A CbResponseAPI object to use
        query: The correctly formated query
        start_time: Set the minimum last update time (relative to server) for this query.
        last_time: Set the maximum last update time (relative to server) for this query.
        XXX no_warnings: Do not warn before printing large query result sets.
    Returns: cbapi.response.models.ProcessQuery or empty list.
    """

    processes = []
    LOGGER.debug(f"buiding query: {query} between '{start_time}' and '{last_time}'")
    try:
        processes = cb.select(Process).where(query).group_by("id")
        processes = processes.min_last_server_update(start_time) if start_time else processes
        processes = processes.max_last_server_update(last_time) if last_time else processes
        LOGGER.info(f"got {len(processes)} process results grouped by id.")
    except Exception as e:
        if raise_exceptions:
            raise (e)
        LOGGER.error(f"problem querying carbonblack with '{query}' : {e}")

    return processes


def print_facet_histogram(facet_dict):
    """Print facets"""
    print("\n------------------------- FACET HISTOGRAMS -------------------------")
    for field_name, facets in facet_dict.items():
        if any([key for key in ["name", "percent", "ratio", "value"] if key not in facets[0].keys()]):
            continue
        # total_results = sum([entry['value'] for entry in facets])
        # longest_process_name = len(max(process_names, key=len))
        print(f"\n\t\t\t{field_name} results: {len(facets)}")  # .format(total_results))
        print("\t\t\t--------------------------")
        for entry in facets:
            print(
                "%50s: %5s %5s%% %s"
                % (entry["name"][:45], entry["value"], entry["ratio"], "\u25A0" * (int(entry["percent"] / 2)))
            )
        print()
    return
