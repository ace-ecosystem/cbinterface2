"""Functions that work with query related Carbon Black APIs.
"""

import datetime
import logging
from dateutil import tz

from typing import Union

from cbapi.psc.threathunter import CbThreatHunterAPI, Process
from cbapi.psc.threathunter.models import AsyncProcessQuery

LOGGER = logging.getLogger("cbinterface.psc.query")


def is_valid_process_query(query: AsyncProcessQuery) -> bool:
    """Custom query validation.

    Args:
        query: Cb threathunter query
    Returns:
        True if a valid query, else False.
    """
    if not query._doc_class.validation_url:
        LOGGER.debug("Unexpectedly, class has no validation url. hmm...")
        return True

    url = query._doc_class.validation_url.format(query._cb.credentials.org_key)

    args = query._get_query_parameters()
    if args.get("query", False):
        args["q"] = args["query"]
    # v2 search sort key does not work with v1 validation
    args.pop("sort", None)
    LOGGER.debug(f"attempting to validate query with args: {args}")

    validated = query._cb.get_object(url, query_parameters=args)
    if not validated.get("valid"):
        LOGGER.error(f'Invalud query {validated["invalid_message"]}')
        return False
    return True


def make_process_query(
    cb: CbThreatHunterAPI, query: str, start_time: datetime.datetime = None, last_time: datetime.datetime = None
) -> AsyncProcessQuery:
    """Query the CbThreatHunterAPI environment and interface results.

    Args:
        cb: A CbThreatHunterAPI object to use
        query: The process query
        start_time: Set the process start time (UTC).
        last_time: Set the process last time (UTC). Only processes with a start
        time that falls before this last_time.
    Returns: AsyncProcessQuery or empty list.
    """

    LOGGER.debug(f"buiding query: {query} between '{start_time}' and '{last_time}'")
    processes = []
    try:
        processes = cb.select(Process).where(query)
        if not is_valid_process_query(processes):
            LOGGER.info(f"For help, refer to {cb.url}/#userGuideLocation=search-guide/investigate-th&fullscreen")
            return []
        if start_time or last_time:
            start_time = start_time.isoformat() if start_time else "*"
            end_time = last_time.isoformat() if last_time else "*"
            processes = processes.where(f"process_start_time:[{start_time} TO {end_time}]")
        LOGGER.info(f"got {len(processes)} process results.")
    except Exception as e:
        LOGGER.error(f"unexpected exception: {e}")

    return processes


def print_facet_histogram(processes: AsyncProcessQuery):
    """Print facets"""
    # NOTE, this is a custom implementations. TODO, look at using the built in
    # API methods: https://developer.carbonblack.com/reference/carbon-black-cloud/cb-threathunter/latest/process-search-v2/#start-a-process-facet-job
    # Also, NOTE that this table lists fields that support faceting via the built in method, children is not one of them:
    # https://developer.carbonblack.com/reference/cb-threathunter/latest/process-search-fields/
    from cbinterface.helpers import create_histogram_string, get_os_independant_filepath

    fields = [
        "parent_name",
        "process_name",
        "process_reputation",
        "process_username",
        "process_sha256",
        "device_name",
        "device_os",
    ]
    path_fields = ["parent_name", "process_name"]
    processes = list(processes)
    facet_dict = {}
    for field_name in fields:
        facet_dict[field_name] = {}
        for proc in processes:
            value = proc.get(field_name, "None")
            if isinstance(value, list):
                if len(value) > 1:
                    LOGGER.info(f"condensing {value} to {value[0]}")
                value = value[0]
            elif field_name in path_fields:
                file_path = get_os_independant_filepath(value)
                file_name = file_path.name
                value = file_name
            if value not in facet_dict[field_name]:
                facet_dict[field_name][value] = 1
            else:
                facet_dict[field_name][value] += 1

    # special case for "children"
    try:
        facet_dict["childproc_name"] = {}
        depth = 0
        for proc in processes:
            if proc.childproc_count < 1:
                continue
            children = proc.summary.children or []
            for cp in children:
                process_path = get_os_independant_filepath(cp.get("process_name"))
                process_name = process_path.name
                if process_name not in facet_dict["childproc_name"]:
                    facet_dict["childproc_name"][process_name] = 1
                else:
                    facet_dict["childproc_name"][process_name] += 1
    except Exception as e:
        LOGGER.warning(f"problem enumerating child process names: {e}")

    print("\n------------------------- FACET HISTOGRAMS -------------------------")
    for field_name, facets in facet_dict.items():
        print(f"\n\t{field_name} results: {len(facets.keys())}")
        print("\t--------------------------------")
        print(create_histogram_string(facets))
    return
