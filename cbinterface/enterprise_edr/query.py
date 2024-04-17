"""Functions that work with query related Carbon Black APIs."""

import time
import datetime
import logging

from typing import Union, Dict, List

from cbc_sdk import CBCloudAPI
from cbc_sdk.platform.processes import AsyncProcessQuery, Process
from cbc_sdk.errors import ServerError, ClientError, ObjectNotFoundError

LOGGER = logging.getLogger("cbinterface.enterprise_edr.query")

# NOTE: To receive all events, you must resubmit the search request until processed_segments is equal to total_segments.
# https://developer.carbonblack.com/reference/carbon-black-cloud/platform/latest/platform-search-api-processes/#get-events-associated-with-a-given-process-v2
MAX_EVENT_SEARCH_SEGMENT_EXTENSION = 10


def create_event_search(
    p: Union[Process, Dict],
    search_data: Dict = {},
    criteria: Dict = {},
    fields: List = ["*"],
    query: str = None,
    time_range: Dict = {},
    rows=1000,
    start: int = 0,
    sort: Dict = [{"field": "event_timestamp", "order": "asc"}],
) -> Dict:
    """Perform an event search.

    NOTE: If p is a dictionary, an instance of CBC API must be passed as "_cb".

    Without anything specified, the default is to return ALL events for the process.
    """
    # NOTE that this one is not job based search.

    cb = p.get("_cb")
    url = f"/api/investigate/v2/orgs/{cb.credentials.org_key}/events/{p.get('process_guid')}/_search"

    if not search_data:
        if not query:
            query = f"process_guid:{p.get('process_guid')}"
        search_data = {
            "criteria": criteria,
            "fields": fields,
            "query": query,
            "rows": rows,
            "start": start,
            "sort": sort,
        }
        if time_range:
            # "time_range" = { "end": "2020-01-27T18:34:04Z", "start": "2020-01-18T18:34:04Z"}
            search_data["time_range"] = time_range

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


def event_search_complete(cb: CBCloudAPI, job_id):
    """Return true when a search is complete."""
    url = f"/api/investigate/v1/orgs/{cb.credentials.org_key}/enriched_events/search_jobs/{job_id}"
    result = cb.get_object(url)
    if result["completed"] == result["contacted"]:
        return True
    return False


def get_event_search_results(cb: CBCloudAPI, job_id) -> Dict:
    """Return any results of an event search."""
    url = f"/api/investigate/v2/orgs/{cb.credentials.org_key}/enriched_events/search_jobs/{job_id}/results"
    try:
        while not event_search_complete(cb, job_id):
            time.sleep(0.1)
    except Exception as e:
        LOGGER.error(f"got exception waiting for event search to complete: {e}")
        return None
    try:
        return cb.get_object(url)
    except Exception:
        LOGGER.error("could not get results: {e}")
        return None


def yield_events(
    p: Process,
    search_data: Dict = {},
    criteria: Dict = {},
    query: str = None,
    rows=1000,
    start: int = 0,
    max_results: int = None,  # limit results returned
    start_time: datetime.datetime = None,
    end_time: datetime.datetime = None,
) -> Dict:
    """Yield Process Events resulting from Event search."""
    time_range = {}
    if start_time:
        time_range["start"] = start_time.isoformat()
    if end_time:
        time_range["end"] = end_time.isoformat()

    position = start
    still_querying = True
    search_extension_count = 0
    while still_querying:
        result = create_event_search(
            p,
            search_data=search_data,
            criteria=criteria,
            query=query,
            time_range=time_range,
            rows=rows,
            start=position,
        )
        if not result:
            return result
        LOGGER.debug(
            f"got result (minus events): {[f'{key}={result[key]}' for key in result.keys() if key !='results']}"
        )
        if max_results and position + rows > max_results:
            # get however many rows that may result in max_results
            rows = max_results - position

        total_results = result["num_available"]
        if total_results != result["num_found"]:
            LOGGER.debug("not all events are available.")
        results = result.get("results", [])

        LOGGER.debug(f"got {len(results)+position} out of {total_results} total events.")
        for item in results:
            yield item
            position += 1
            if max_results and position >= max_results:
                still_querying = False
                break
        if position >= total_results:
            if result.get("processed_segments") != result.get("total_segments"):
                # NOTE: This can happen when CBC is bogged down, however, it also may be the process hasn't terminated.
                # Usually this will complete on the first extension/second try.

                if search_extension_count >= MAX_EVENT_SEARCH_SEGMENT_EXTENSION:
                    still_querying = False
                    break
                search_extension_count += 1
                remaining = MAX_EVENT_SEARCH_SEGMENT_EXTENSION - search_extension_count
                LOGGER.info(
                    f"CBC hasn't processed all segments. There could be more events. Extending search up to {remaining} more times ... "
                )
            else:
                still_querying = False


def get_process_search_jobs(cb):
    url = f"/api/investigate/v1/orgs/{cb.credentials.org_key}/processes/search_jobs"
    return cb.get_object(url)


def get_process_search_status(cb, job_id):
    url = f"/api/investigate/v1/orgs/{cb.credentials.org_key}/processes/search_jobs/{job_id}"
    return cb.get_object(url)


def get_process_search_results(cb, job_id):
    url = f"/api/investigate/v2/orgs/{cb.credentials.org_key}/processes/search_jobs/{job_id}/results"
    return cb.get_object(url)


def cancel_process_search(cb, job_id):
    url = f"/api/investigate/v1/orgs/{cb.credentials.org_key}/processes/search_jobs/{job_id}"
    return cb.delete_object(url)


def is_valid_process_query(query: AsyncProcessQuery) -> bool:
    """Custom query validation.

    Args:
        query: CBCloudAPI query
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
        LOGGER.error(f'Invalid query {validated["invalid_message"]}')
        return False
    return True


def is_valid_process_query_string(cb: CBCloudAPI, query: str) -> bool:
    """Validates a process query string is valid for Enterprise EDR.

    Args:
        cb: CBCloudAPI connection object
        query (str): The query.

    Returns:
        True or False
    """
    args = {"query": query}
    url = f"/api/investigate/v2/orgs/{cb.credentials.org_key}/processes/search_validation"
    validated = cb.post_object(url, args).json()
    if not validated.get("valid"):
        return False
    return True


def convert_from_legacy_query(cb: CBCloudAPI, query: str) -> str:
    """Converts a legacy CB Response (EDR) query to a Enterprise EDR query.

    Args:
        cb: CBCloudAPI connection object
        query (str): The query to convert.

    Returns:
        str: The converted query.
    """
    args = {"query": query}
    try:
        resp = cb.post_object("/threathunter/feedmgr/v2/query/translate", args)
    except ClientError as e:
        LOGGER.error(f"got error attempting query conversion: {e}")
        return False
    resp = resp.json()
    return resp.get("query")


def make_process_query(
    cb: CBCloudAPI,
    query: str,
    fields: List = ["*", "process_start_time"],
    start_time: datetime.datetime = None,
    last_time: datetime.datetime = None,
    raise_exceptions=True,
    validate_query=False,
    silent=False,
) -> AsyncProcessQuery:
    """Query the CBCloudAPI environment and interface results.

    Args:
        cb: A CBCloudAPI object to use
        query: The process query
        fields: fields to be included from the query.
        start_time: Set the process start time (UTC).
        last_time: Set the process last time (UTC). Only processes with
        a start time that falls before this last_time.
        raise_exceptions: Let any exceptions raise up (library use)
        validate_query: If True, validate the query before attempting to
        use it.
        silent: if True, suppress some printing from this function.
    Returns: AsyncProcessQuery or empty list.
    """
    LOGGER.debug(f"building query: {query} between '{start_time}' and '{last_time}'")
    processes = []
    try:
        processes = cb.select(Process).where(query).set_fields(fields)
        if validate_query and not is_valid_process_query(processes):
            LOGGER.info(f"For help, refer to {cb.url}/#userGuideLocation=search-guide/investigate-th&fullscreen")
            LOGGER.info("Is this a legacy query? ... Attempting to convert to Enterprise EDR query ...")
            converted_query = convert_from_legacy_query(cb, query)
            if not converted_query:
                LOGGER.info("failed to convert to Enterprise EDR query... 🤡 your query is jacked up.")
                return []
            if is_valid_process_query_string(cb, converted_query):
                LOGGER.info(
                    "successfully converted and validated the query you supplied to a Enterprise EDR query 👍, see below."
                )
                LOGGER.info(
                    "👇👇 try again with the following query 👇👇 - also, hint, single quotes are your friend. "
                )
                LOGGER.info(f"query: '{converted_query}'")
            return []
        if start_time or last_time:
            start_time = start_time.isoformat() if start_time else "*"
            end_time = last_time.isoformat() if last_time else "*"
            processes = processes.where(f"process_start_time:[{start_time} TO {end_time}]")
        if not silent:
            LOGGER.info(f"got {len(processes)} process results.")
    except Exception as e:
        if raise_exceptions:
            raise (e)
        LOGGER.error(f"unexpected exception: {e}")

    return processes


def print_facet_histogram(processes: AsyncProcessQuery):
    """Print facets."""
    # NOTE, this is a custom implementations used before the v2
    # Will probably be deprecated in favor of v2 using API facet job
    from cbinterface.helpers import create_histogram_string, get_os_independent_filepath

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
                file_path = get_os_independent_filepath(value)
                file_name = file_path.name
                value = file_name
            facet_dict[field_name][value] = facet_dict[field_name].get(value, 0) + 1

    # special case for "children"
    try:
        facet_dict["childproc_name"] = {}
        for proc in processes:
            if proc.childproc_count < 1:
                continue
            children = proc.summary.children or []
            for cp in children:
                process_path = get_os_independent_filepath(cp.get("process_name"))
                process_name = process_path.name
                if process_name not in facet_dict["childproc_name"]:
                    facet_dict["childproc_name"][process_name] = 1
                else:
                    facet_dict["childproc_name"][process_name] += 1
    except Exception as e:
        LOGGER.warning(f"problem enumerating child process names: {e}")
        raise e

    print("\n------------------------- FACET HISTOGRAMS -------------------------")
    for field_name, facets in facet_dict.items():
        print(f"\n\t{field_name} results: {len(facets.keys())}")
        print("\t--------------------------------")
        print(create_histogram_string(facets))
    return


def print_facet_histogram_v2(
    cb: CBCloudAPI,
    query: str,
    start_time: datetime.datetime = None,
    end_time: datetime.datetime = None,
    return_string=False,
):
    """Get query facet results from the CBCloudAPI enriched events facets."""
    # NOTE: no support for childproc facets with this built-in

    from cbinterface.helpers import get_os_independent_filepath

    post_data = {}
    post_data["query"] = query
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
    post_data["terms"] = {"fields": fields}
    post_data["time_range"] = {}
    if start_time:
        post_data["time_range"]["start"] = start_time.isoformat() + "Z"
    if end_time:
        post_data["time_range"]["end"] = end_time.isoformat() + "Z"
    uri = f"/api/investigate/v2/orgs/{cb.credentials.org_key}/processes/facet_jobs"
    job_id = cb.post_object(uri, post_data).json().get("job_id", None)
    if not job_id:
        LOGGER.error("failed to get facet job.")
        return False

    uri = f"/api/investigate/v2/orgs/{cb.credentials.org_key}/processes/facet_jobs/{job_id}/results"
    time.sleep(1)
    facet_data = cb.get_object(uri)
    while facet_data["contacted"] != facet_data["completed"]:
        facet_data = cb.get_object(uri)
    txt = "\n------------------------- FACET HISTOGRAMS -------------------------\n"
    total = facet_data["num_found"]
    for facets in facet_data["terms"]:
        field_name = facets["field"]
        txt += f"\n\t{field_name} results: {len(facets['values'])}\n"
        txt += "\t--------------------------------\n"
        for entry in facets["values"]:
            entry_name = entry["name"]
            entry_length = 55 if field_name in path_fields else 20
            if field_name in path_fields:
                if len(entry_name) > 55:
                    file_path = get_os_independent_filepath(entry_name)
                    file_name = file_path.name
                    file_path = entry_name[: len(entry_name) - len(file_name)]
                    file_path = file_path[: 40 - len(file_name)]
                    entry_name = f"{file_path}...{file_name}"
            bar_value = int(((entry["total"] / total) * 100) / 2)
            txt += f"%-{entry_length}s %5s %5s%% %s\n" % (
                entry_name,
                entry["total"],
                int(entry["total"] / total * 100),
                "\u25A0" * bar_value,
            )

    txt += "\n"
    if return_string:
        return txt
    print(txt)
    return
