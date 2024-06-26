"""All things intel & alerts.

IOCs, Reports, Watchlists, Feeds, Alerts.

NOTE on Response Watchlist to Enterprise EDR Intel Migrations:

  There are three different ways that I built to migrate Response
  Watchlists to Enterprise EDR Watchlists:
   1. One-to-One
   2. Many-to-One
   3. Many-to-Two (Not connected to CLI)

 All of the above use the `yield_reports_created_from_response_watchlists` to convert
 Response Watchlists into Enterprise EDR Reports. That function converts the Response queries to
 valid Enterprise EDR queries. If a query doesn't validate/convert, a log is generated and it's
 skipped. If it does validate, a Report is generated. If the Watchlist, in Response, was really slow or
 had errors the resulting Enterprise EDR Report will be set to "ignore" automatically. Additionally, I passed
 all the available context about the Response Watchlist into the description of the resulting Reports.

 We had over 300 custom Response Watchlists, here is what I did for our use case:
  1. I seperated the watchlists with true positive detections and low FP rates
     using our ACE Alert metrics. I put the names of these Watchlists into a txt file
     and then exported them from response using the following command:
       `cat ~smcfeely/working/cbmigration/uniq.high_fidelity.watchlists.txt | cbinterface response_watchlist --watchlist-names-from-stdin -json > high_fid.response_watchlists.json`

  2. Next, I used the command below to import these Response Watchlists into a single
     Enterprise EDR Watchlist I called "ACE Higher Fidelity Response Watchlists":
       `cbinterface intel migrate ~smcfeely/working/cbmigration/high_fid.response_watchlists.json --many-to-one`

  3. After that, I exported the remaining custom Response Watchlists into another json file and called the
     `convert_response_watchlists_to_grouped_enterprise_edr_watchlists` function from a python terminal to organize
     the Response Watchlists into *two* Enterprise EDR Watchlists, one for Response Watchlists that have never
     had a hit and then the ones remaining are lower fidelity and went into a "Low Fidelity" Enterprise EDR Watchlist.

"""

import os
import json
import time
import logging

from dateutil import tz
from dateutil.parser import parse as parse_timestamp
from datetime import datetime
from typing import Dict, List, Literal

from cbc_sdk import CBCloudAPI
from cbc_sdk.platform import Alert
from cbc_sdk.errors import ServerError, ClientError, ObjectNotFoundError

LOGGER = logging.getLogger("cbinterface.enterprise_edr.intel")


## Alerts ##
def alert_search(cb: CBCloudAPI, search_data: Dict) -> Dict:
    """Perform an Alert search.

    One request and return the result.
    """
    url = f"/api/alerts/v7/orgs/{cb.credentials.org_key}/alerts/_search"
    try:
        result = cb.post_object(url, search_data)
        return result.json()

    except ServerError as e:
        LOGGER.error(f"Caught ServerError searching alerts: {e}")
        return False
    except ClientError as e:
        LOGGER.warning(f"got ClientError searching alerts: {e}")
        return False
    except ValueError:
        LOGGER.warning(f"got unexpected {result}")
        return False


def yield_alerts(
    cb: CBCloudAPI,
    query: str = None,
    time_range: Dict = None,
    criteria: Dict = None,
    exclusions: Dict = None,
    sort: List[Dict] = [{"field": "backend_update_timestamp", "order": "ASC"}],
    start: int = 1,
    rows: int = 100,
    max_results: int = 500,  # limit results returned
) -> Dict:
    """Yield Alerts resulting from alert search."""
    data = {k: v for k, v in locals().items() if v is not None and k not in ["max_results", "cb"]}
    still_querying = True
    while still_querying:
        if max_results and data["start"] + rows > max_results:
            # get however many rows that may result in max_results
            rows = max_results - data["start"]
        result = alert_search(cb, data)

        if not result:
            return result
        total_results = result["num_found"]
        results = result.get("results", [])
        LOGGER.debug(f"got {len(results)+data['start']-1} out of {total_results} total alerts.")
        for item in results:
            yield item
            data["start"] += 1
            if max_results and data["start"] >= max_results:
                still_querying = False
                break

        if data["start"] >= total_results:
            still_querying = False
            break


def get_alert(cb: CBCloudAPI, alert_id) -> Dict:
    """Get alert by ID."""
    url = f"/api/alerts/v7/orgs/{cb.credentials.org_key}/alerts/{alert_id}"
    try:
        return cb.get_object(url)
    except ServerError as e:
        LOGGER.error(f"Caught ServerError getting report {alert_id}: {e}")


def update_alert_status(
    cb: CBCloudAPI,
    alert_ids: List[str],
    status: Literal["OPEN", "IN_PROGRESS", "CLOSED"],
    determination: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "NONE"],
    closure_reason: Literal["NO_REASON", "RESOLVED", "RESOLVED_BENIGN_KNOWN_GOOD", "DUPLICATE_CLEANUP", "OTHER"],
    note: str = None,
) -> Dict:
    """Update alerts state."""
    data = {k: v for k, v in locals().items() if v is not None and k not in ["cb", "alert_ids"]}
    alert_query = cb.select(Alert).add_criteria("id", alert_ids)
    job = alert_query.update(**data)
    try:
        alert_query = cb.select(Alert).add_criteria("id", alert_ids)
        job = alert_query.update(**data)
        job.await_completion().result()
        return job.to_json()
    except ServerError as e:
        LOGGER.error(f"Caught ServerError: {e}")
        return False
    except ClientError as e:
        LOGGER.warning(f"got ClientError:: {e}")
        return False


def interactively_update_alert_state(
    cb: CBCloudAPI,
    alert_id,
    status: Literal["OPEN", "IN_PROGRESS", "CLOSED"] = None,
    determination: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "NONE"] = None,
    closure_reason: Literal["NO_REASON", "RESOLVED", "RESOLVED_BENIGN_KNOWN_GOOD", "DUPLICATE_CLEANUP", "OTHER"] = None,
    note: str = None,
) -> Dict:
    """Update alert remediation state by ID."""
    from cbinterface.helpers import input_with_timeout

    if not status:
        status = input_with_timeout("Alert status to set, OPEN, IN_PROGRESS or CLOSED? [CLOSED]: ") or "CLOSED"
        if status not in ["OPEN", "IN_PROGRESS", "CLOSED"]:
            LOGGER.error(f"status must be one of [OPEN, IN_PROGRESS, CLOSED], not {status}")
            return False
    if not determination:
        determination = input_with_timeout("Determination: ") or None
        if determination not in ["TRUE_POSITIVE", "FALSE_POSITIVE", "NONE", None]:
            LOGGER.error(f"determination must be one of [TRUE_POSITIVE, FALSE_POSITIVE, NONE], not {determination}")
            return False
    if not closure_reason:
        closure_reason = input_with_timeout("Closure reason: ") or None
        if closure_reason not in [
            "NO_REASON",
            "RESOLVED",
            "RESOLVED_BENIGN_KNOWN_GOOD",
            "DUPLICATE_CLEANUP",
            "OTHER",
            None,
        ]:
            LOGGER.error(
                f"closure reason must be one of [NO_REASON, RESOLVED, RESOLVED_BENIGN_KNOWN_GOOD, DUPLICATE_CLEANUP, OTHER], not {closure_reason}"
            )
            return False
    if not note:
        note = input_with_timeout("Note: ") or None
    return update_alert_status(cb, alert_id, status, determination, closure_reason, note)


## Reports ##
def create_report(cb: CBCloudAPI, report_data) -> Dict:
    """Create an intel Report."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports"
    try:
        result = cb.post_object(url, report_data)
    except ServerError as e:
        LOGGER.error(f"Caught ServerError creating report: {e}")
        return False
    try:
        return result.json()
    except ValueError:
        return False


def ignore_report(cb: CBCloudAPI, report_id) -> Dict:
    """Set this report to ignore status."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}/ignore"
    try:
        return cb.put_object(url, {"ignore": True})
    except ServerError as e:
        LOGGER.error(f"Caught ServerError getting report {report_id}: {e}")


def delete_report(cb: CBCloudAPI, report_id) -> Dict:
    """Set this report to ignore status."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}"
    try:
        return cb.delete_object(url)
    except ServerError as e:
        LOGGER.error(f"Caught ServerError deleting report {report_id}: {e}")


def get_report_status(cb: CBCloudAPI, report_id) -> Dict:
    """Get report to ignore status."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}/ignore"
    try:
        return cb.get_object(url)
    except ServerError as e:
        LOGGER.error(f"Caught ServerError getting report {report_id}: {e}")


def activate_report(cb: CBCloudAPI, report_id) -> Dict:
    """Set this report to active status."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}/ignore"
    try:
        return cb.delete_object(url)
    except ServerError as e:
        LOGGER.error(f"Caught ServerError getting report {report_id}: {e}")


def get_report(cb: CBCloudAPI, report_id) -> Dict:
    """Get report by report id."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}"
    try:
        report = cb.get_object(url)
        report["ignored"] = get_report_status(cb, report["id"])["ignored"]
        return report
    except ServerError as e:
        LOGGER.error(f"Caught ServerError getting report {report_id}: {e}")
    except ObjectNotFoundError:
        LOGGER.warning(f"report {report_id} does not exist")


def get_report_with_IOC_status(cb: CBCloudAPI, report_id) -> Dict:
    """Get report and include status of every report IOC."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}/iocs"
    report = get_report(cb, report_id)
    if not report:
        return None
    for ioc in report["iocs_v2"]:
        ioc["ignored"] = cb.get_object(f"{url}/{ioc['id']}/ignore")["ignored"]
    return report


def update_report(cb: CBCloudAPI, report_id, report_data) -> Dict:
    """Update an existing report."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}"

    # clean up any ignored fields or Cb will bark back
    if "ignored" in report_data:
        del report_data["ignored"]
    for ioc in report_data["iocs_v2"]:
        if "ignored" in ioc:
            del ioc["ignored"]

    # updating report time is required
    report_data["timestamp"] = time.time()

    try:
        result = cb.put_object(url, report_data)
    except ServerError as e:
        LOGGER.error(f"Caught ServerError updating report: {e}")
        return False
    except ClientError as e:
        LOGGER.warning(f"got ClientError updating report: {e}")
        return False

    return result.json()


def write_basic_report_template() -> bool:
    """Print a basic report template.

    The template can be filled out to create a new threat report.
    """
    ioc2_template = {"id": 1, "match_type": "query", "values": ["query_string_here"]}
    report_template = {
        "title": None,
        "description": None,  # required
        "severity": None,
        "link": None,
        "tags": [],
        "iocs_v2": [ioc2_template],  # required
    }
    template_name = "basic.threat_report.single_ioc_query.template.json"
    with open(template_name, "w") as fp:
        fp.write(json.dumps(report_template, indent=2))
    if os.path.exists(template_name):
        return template_name
    return False


def update_report_ioc_query(cb: CBCloudAPI, report_id, ioc_id, ioc_query_string) -> Dict:
    """Update IOC query value with ioc_query_string.

    A cbc_sdk.errors.ClientError will be raised if the query is not valid.
    """
    report_data = get_report_with_IOC_status(cb, report_id)
    for ioc in report_data["iocs_v2"]:
        if ioc["id"] == ioc_id:
            if ioc["match_type"] != "query":
                LOGGER.error(f"not a query based IOC: {ioc}")
                return False
            if ioc["ignored"]:
                LOGGER.warning("you're updating an IOC that is set to ignored.")
            if len(ioc["values"]) > 1:
                LOGGER.warning(
                    f"This query IOC has a surprising number of values that are about to be over-written: {ioc['values']}"
                )
            ioc["values"] = [ioc_query_string]
    return update_report(cb, report_id, report_data)


def interactively_update_report_ioc_query(cb: CBCloudAPI, report_id, ioc_id) -> Dict:
    """Prompt user for new query and update the report IOC query."""
    from cbinterface.helpers import input_with_timeout

    report = get_report(cb, report_id)
    if not report:
        return None

    ioc = [ioc for ioc in report["iocs_v2"] if ioc_id == ioc["id"]][0]
    if ioc["match_type"] != "query":
        LOGGER.warning(f"IOC={ioc_id} is not a query based IOC: {ioc}")

    print(f"Current IOC query: {ioc['values'][0]}")
    new_ioc_query = input_with_timeout("Enter new query: ", timeout=90)
    return update_report_ioc_query(cb, report_id, ioc_id, new_ioc_query)


def print_report(report: Dict) -> None:
    """Special print formatting."""
    print("\n------------------------- INTEL REPORT -------------------------")
    for field, value in report.items():
        if "iocs_v2" == field:
            continue
        print(f"\t{field}: {value}")
    print("\tiocs_v2: ")
    for ioc in report["iocs_v2"]:
        for field, value in ioc.items():
            if field == "values":
                continue
            print(f"\t\t{field}: {value}")
        for ioc_value in ioc["values"]:
            print(f"\t\tioc_value: {ioc_value}")
        print()
    print()


## IOCs ##
def ioc_does_exist(cb: CBCloudAPI, report_id, ioc_id):
    """Check if the given report contains the ioc_id."""
    report = get_report(cb, report_id)
    if not report:
        return None
    for ioc in report["iocs_v2"]:
        if ioc["id"] == ioc_id:
            return True
    return False


# get IOC status
def is_ioc_ignored(cb: CBCloudAPI, report_id, ioc_id, check_existence=False):
    """Return status of IOC."""
    if check_existence:
        if not ioc_does_exist(cb, report_id, ioc_id):
            LOGGER.warning("IOC does not exist.")
            return None
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}/iocs/{ioc_id}/ignore"
    return cb.get_object(url)["ignored"]


# ignore IOC
def ignore_ioc(cb: CBCloudAPI, report_id, ioc_id):
    """Ignore this IOC."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}/iocs/{ioc_id}/ignore"
    return cb.put_object(url, {"ignore": True})


# activate IOC
def activate_ioc(cb: CBCloudAPI, report_id, ioc_id):
    """Activate IOC."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}/iocs/{ioc_id}/ignore"
    resp = cb.delete_object(url)
    if resp.status_code == 204:
        return True
    return False


## Watchlists ##
def get_all_watchlists(cb: CBCloudAPI):
    """Return a list of all watchlists."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/watchlists"
    result = cb.get_object(url)
    return result.get("results", [])


def get_watchlist(cb: CBCloudAPI, watchlist_id):
    """Get a watchlist by ID."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/watchlists"
    try:
        return cb.get_object(f"{url}/{watchlist_id}")
    except ServerError as e:
        LOGGER.error(f"Caught ServerError getting watchlist {watchlist_id}: {e}")
    except ObjectNotFoundError:
        LOGGER.warning(f"No watchlist with ID {watchlist_id}")


def get_watchlists_like_name(cb: CBCloudAPI, watchlist_name):
    """Return watchlists with watchlist_name in their name."""
    return [wl for wl in get_all_watchlists(cb) if watchlist_name in wl["name"]]


def create_watchlist(cb: CBCloudAPI, watchlist_data: Dict):
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/watchlists"
    try:
        result = cb.post_object(url, watchlist_data)
    except ServerError as e:
        LOGGER.error(f"Caught ServerError creating watchlist: {e}")
        return False
    except ClientError as e:
        LOGGER.warning(f"got ClientError creating watchlist: {e}")
        return False

    return result.json()


def delete_watchlist(cb: CBCloudAPI, watchlist_id) -> Dict:
    """Set this report to ignore status."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/watchlists/{watchlist_id}"
    try:
        return cb.delete_object(url)
    except ServerError as e:
        LOGGER.error(f"Caught ServerError deleting watchlist {watchlist_id}: {e}")


def update_watchlist(cb: CBCloudAPI, watchlist_data: Dict):
    watchlist_id = watchlist_data["id"]
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/watchlists/{watchlist_id}"
    try:
        result = cb.put_object(url, watchlist_data)
    except ServerError as e:
        LOGGER.error(f"Caught ServerError creating watchlist: {e}")
        return False
    except ClientError as e:
        LOGGER.warning(f"got ClientError creating watchlist: {e}")
        return False

    return result.json()


def create_watchlist_from_report_list(
    cb: CBCloudAPI, watchlist_name: str, watchlist_description: str, reports: List[Dict]
) -> Dict:
    """Create a watchlist built on the supplied intel reports.

    Use this to create a single watchlist comprised of the intel reports.

    Args:
      cb: CBCloudAPI object
      watchlist_name: Name for the resulting watchlist
      watchlist_description: Description for the resulting watchlist
      reports: The Intel Reports.

    Returns:
      Dict representation of the new Watchlist.
    """
    assert isinstance(reports, list)
    assert isinstance(reports[0], dict)
    assert "id" in reports[0]

    report_ids = [r["id"] for r in reports]

    watchlist_data = {
        "name": watchlist_name,
        "description": watchlist_description,
        "tags_enabled": True,
        "alerts_enabled": True,
        "report_ids": report_ids,
    }
    watchlist = create_watchlist(cb, watchlist_data)
    if not isinstance(watchlist, dict):
        LOGGER.error(f"problem creating watchlist for {watchlist_data}")
        return False
    LOGGER.info(f"created watchlist: {watchlist}")

    return watchlist


def assign_reports_to_watchlist(cb: CBCloudAPI, watchlist_id: str, reports: List[Dict]) -> Dict:
    """Set a watchlist report IDs attribute to the passed reports.

    Args:
      cb: CBCloudAPI object
      watchlist_id: The Watchlist ID to update.
      reports: The Intel Reports.

    Returns:
      The Watchlist in dict form.
    """
    watchlist_data = get_watchlist(cb, watchlist_id)
    if not watchlist_data:
        return None
    watchlist_data["report_ids"] = [r["id"] for r in reports]
    watchlist_data = update_watchlist(cb, watchlist_data)
    if not watchlist_data:
        LOGGER.error("unexpected problem updating watchlist with report IDs.")
        return False

    return watchlist_data


def create_new_report_and_append_to_watchlist(cb: CBCloudAPI, watchlist_id: str, report_data: Dict) -> Dict:
    """Create a new threat report from JSON and append to watchlist."""
    watchlist_data = get_watchlist(cb, watchlist_id)
    if not watchlist_data:
        LOGGER.error(f"watchlist does not exist: {watchlist_id}")
        return False
    watchlist_threat_reports_before = len(watchlist_data["report_ids"])

    if "report" in report_data:
        report_data = report_data["report"]

    # create intel report
    report = {
        "title": report_data["title"],  # required
        "description": report_data["description"],  # required
        "timestamp": time.time(),
        "severity": report_data.get("severity", 5),
        "link": report_data.get("link", None),
        "tags": report_data.get("tags", []),
        "iocs_v2": report_data["iocs_v2"],  # required
    }
    intel_report = create_report(cb, report)
    if not isinstance(intel_report, dict):
        LOGGER.error(f"problem creating report for {report_data}")
        return False
    LOGGER.info(f"created intel report: {intel_report}")

    # append intel report to Watchlist.
    watchlist_data["report_ids"].append(intel_report["id"])
    watchlist_data = update_watchlist(cb, watchlist_data)
    if watchlist_data and len(watchlist_data["report_ids"]) == (watchlist_threat_reports_before + 1):
        LOGGER.info("successfully appended new threat report to watchlist.")
        return True
    return False


# TODO enable watchlist alerting/taging?

# TODO disable watchlist alerting/taging?


## Feeds ##
def get_all_feeds(cb: CBCloudAPI, include_public=True) -> Dict:
    """Retrieve all feeds owned by the caller.

    Provide include_public=true parameter to also include public community feeds.
    """
    url = f"/threathunter/feedmgr/v2/orgs/{cb.credentials.org_key}/feeds"
    params = {"include_public": include_public}
    result = cb.get_object(url, query_parameters=params)
    return result.get("results", [])


def get_feed(cb: CBCloudAPI, feed_id: str) -> Dict:
    """Get a specific feed by ID."""
    url = f"/threathunter/feedmgr/v2/orgs/{cb.credentials.org_key}/feeds"
    try:
        return cb.get_object(f"{url}/{feed_id}")
    except ServerError as e:
        LOGGER.error(f"Caught ServerError getting feed {feed_id}: {e}")
    except ObjectNotFoundError:
        LOGGER.warning(f"No feed by feed id {feed_id}")


def search_feed_names(cb: CBCloudAPI, name: str) -> List[Dict]:
    """Search for feeds by name."""
    return [f for f in get_all_feeds(cb) if name in f["name"]]


def get_feed_report(cb: CBCloudAPI, feed_id: str, report_id: str) -> Dict:
    """Get a specific report from a specific feed."""
    url = f"/threathunter/feedmgr/v2/orgs/{cb.credentials.org_key}/feeds/{feed_id}/reports/{report_id}"
    try:
        return cb.get_object(url)
    except ServerError as e:
        LOGGER.error(f"Caught ServerError getting feed report {feed_id}: {e}")
    except ObjectNotFoundError:
        LOGGER.warning(f"No feed {feed_id} or report {report_id} in the feed")


"""
Begin Intel backup routines.
"""


def _safe_filename(raw_string):
    import string

    raw_string = raw_string.replace(" ", "_")
    valid_chars = ["_", "-"]
    valid_chars.extend(list(string.digits))
    valid_chars.extend(list(string.ascii_lowercase))
    valid_chars.extend(list(string.ascii_uppercase))
    safe_string = ""
    for char in raw_string:
        if char in valid_chars:
            safe_string += char
    return safe_string


def backup_watchlist_threat_reports(cb: CBCloudAPI, watchlist_ids: List):
    """Backup threat reports for safe keeping.

    Write threat report json to local directory for each watchlist ID.

    Args:
      cb: CBCloudAPI object
      watchlist_ids: List of CBC watchlist IDs to backup.

    Returns:
      True on success.
    """
    from pathlib import Path
    from cbinterface.config import get_data_directory

    data_dir = get_data_directory()
    if not os.path.exists(data_dir) or data_dir == ".":
        LOGGER.warning("ENV CBINTERFACE_DATA_DIR does not exist. Using current working directory.")

    backup_dir = os.path.join(data_dir, "cbc_intel")
    Path(backup_dir).mkdir(parents=True, exist_ok=True)

    file_paths = []
    for watchlist_id in watchlist_ids:
        watchlist = get_watchlist(cb, watchlist_id)
        if not watchlist:
            continue

        wl_dir = _safe_filename(watchlist["name"])
        wl_dir += ".wl"
        wl_dir = os.path.join(backup_dir, wl_dir)
        Path(wl_dir).mkdir(parents=True, exist_ok=True)

        watchlist_path = os.path.join(wl_dir, "watchlist.json")
        with open(watchlist_path, "w") as fp:
            fp.write(json.dumps(watchlist))
            file_paths.append(watchlist_path)

        report_ids = watchlist.get("report_ids")
        if report_ids:
            for report_id in report_ids:
                report = get_report(cb, report_id)
                report_filename = _safe_filename(report["title"]) + ".json"
                report_filepath = os.path.join(wl_dir, report_filename)
                with open(report_filepath, "w") as fp:
                    fp.write(json.dumps(report))
                    file_paths.append(report_filepath)

        classifier = watchlist.get("classifier")
        if classifier and classifier.get("key") == "feed_id":
            feed_id = classifier["value"]
            feed = get_feed(cb, feed_id)
            if not feed or not feed.get("feedinfo"):
                continue
            feed_name = _safe_filename(feed["feedinfo"]["name"]) + ".feed.json"
            feed_filepath = os.path.join(wl_dir, feed_name)
            with open(feed_filepath, "w") as fp:
                fp.write(json.dumps(feed))
                file_paths.append(feed_filepath)

    for fp in file_paths:
        if os.path.exists(fp):
            LOGGER.info(f"wrote {fp}")
        else:
            LOGGER.error(f"failed to write {fp}")

    return file_paths


## Begin Response to Enterprise EDR Watchlist Migrations ##
def yield_reports_created_from_response_watchlists(cb: CBCloudAPI, response_watchlists: List[Dict]) -> List[Dict]:
    """Convert a list of response watchlists to Enterprise EDR intel reports.

    Args:
      cb: CBCloudAPI object
      response_watchlists: List of Response Watchlist in dictionary form.

    Returns:
      Yield EEDR Intel Reports for each Response Watchlist.
    """
    for wl_data in response_watchlists:
        # attempt to convert and validate query syntax for EEDR
        if "query" not in wl_data:
            LOGGER.error("how does a legacy watchlist not have a query? make sure to convert search_query to query.")
            continue
        query = wl_data["query"]
        try:
            query = cb.convert_query(query)
            LOGGER.info(f"converted query: {query}")
        except Exception as e:
            LOGGER.error(f"problem converting query for {wl_data['name']} : {e}")
            continue
        if not cb.validate_query(query):
            LOGGER.error("query did not validate")
            continue

        report_tags = ["response_migrated_watchlist"]
        report_description = f"Legacy Cb Response Watchlist Description: {wl_data.get('description')}"

        ignore_this_report = False

        # warn of disabled watchlists
        if not wl_data["enabled"]:
            LOGGER.warning(f"{wl_data['name']} is disabled... NOT creating report.")
            ignore_this_report = True
            report_description += "\nIgnored: disabled in Cb Response"
            report_tags.append("disabled_in_response")

        # warn on slow watchlists
        if wl_data["last_execution_time_ms"] is None:
            LOGGER.error(
                f"{wl_data['name']} last_execution_time time is null. This means an error occurred with it's execution. Setting report to ignore."
            )
            ignore_this_report = True
            report_description += "\nIgnored: last execution error'd in Cb Response"
            report_tags.append("execution_errors_in_response")
        elif int(wl_data["last_execution_time_ms"]) > 10000:
            seconds = int(wl_data["last_execution_time_ms"]) / 1000
            LOGGER.warning(f"{wl_data['name']} last_execution_time took {seconds} seconds")
            report_tags.append("slow_in_response")
            if seconds > 30:
                LOGGER.warning(f"{wl_data['name']} has been 💩 slow in response. Setting report to ignore...")
                ignore_this_report = True
                report_description += "\nIgnored: has been 💩 slow in Cb Response. Improve it!?"

        # inform of hit count per day
        hit_count = int(wl_data["total_hits"])
        if hit_count == 0:
            report_tags.append("no_hits_in_response")
        created_date = parse_timestamp(wl_data["date_added"]).astimezone(tz.gettz("UTC"))
        days_since_creation = (datetime.utcnow().astimezone(tz.gettz("UTC")) - created_date).days
        LOGGER.info(f"{wl_data['name']} has a hit count per day ratio of: {hit_count/days_since_creation}")
        report_description += f"\n\nCb Hit Count per day average: {hit_count/days_since_creation}"

        # create report
        ioc_data = {"id": 1, "match_type": "query", "values": [query]}
        report_description += f"\n\n===LEGACY DATA===\n{json.dumps(wl_data, indent=2)}"
        report_data = {
            "title": wl_data.get("name"),
            "description": report_description,
            "timestamp": time.time(),
            "severity": 5,
            "tags": report_tags,
            "iocs_v2": [ioc_data],
        }
        intel_report = create_report(cb, report_data)
        if not isinstance(intel_report, dict):
            LOGGER.error(f"problem creating report for {report_data}")
            continue
        LOGGER.info(f"created intel report: {intel_report}")
        if ignore_this_report:
            if ignore_report(cb, intel_report["id"]):
                LOGGER.info(f"ignored report {intel_report['id']}")

        yield intel_report


def convert_response_watchlists_to_enterprise_edr_watchlists(
    cb: CBCloudAPI, response_watchlists: List[Dict]
) -> List[Dict]:
    """Convert a list of response watchlists to Enterprise EDR watchlists.

    This is a one-for-one Watchlist migration. You probably don't want this.

    Args:
      cb: CBCloudAPI object
      response_watchlists: List of response watchlist in dictionary form.

    Returns:
      List of EEDR Watchlists.
    """
    results = []
    for intel_report in yield_reports_created_from_response_watchlists(cb, response_watchlists):
        report_id = intel_report["id"]
        # get original description
        name = intel_report.get("title")
        description = [rwl.get("description", "") for rwl in response_watchlists if rwl["name"] == name][0]

        # create watchlist
        watchlist_data = {
            "name": name,
            "description": f"Legacy Response description: {description}",
            "tags_enabled": True,
            "alerts_enabled": True,
            "report_ids": [report_id],
        }
        watchlist = create_watchlist(cb, watchlist_data)
        if not isinstance(watchlist, dict):
            LOGGER.error(f"problem creating watchlist for {watchlist_data}")
            continue
        LOGGER.info(f"created watchlist: {watchlist}")
        results.append(watchlist)

    return results


def convert_response_watchlists_to_single_enterprise_edr_watchlist(
    cb: CBCloudAPI,
    response_watchlists: List[Dict],
    watchlist_name: str = None,
    watchlist_description="Consolidated Cb Respone Watchlists. Each report in this watchlist is based on a Cb Response Watchlist",
) -> List[Dict]:
    """Convert a list of Response Watchlists to Enterprise EDR watchlists.

    This is a many-to-one Watchlist migration.

    Args:
      cb: CBCloudAPI object
      response_watchlists: List of Response Ratchlist in dictionary form.
      watchlist_name: The name to give the resulting Response consolidated Enterprise EDR Watchlist.
      watchlist_description: The description to give the resulting Watchlist.

    Returns:
      EEDR Watchlist containing all Response Watchlists as intel Reports.
    """
    from cbinterface.helpers import input_with_timeout

    if watchlist_name is None:
        watchlist_name = input_with_timeout("Enter a name for the resulting Enterprise EDR Watchlist: ", stderr=False)
        watchlist_description = (
            input_with_timeout(
                f"Enter a description for the Watchlist [default description: {watchlist_description}] : ", stderr=False
            )
            or watchlist_description
        )

    reports = list(yield_reports_created_from_response_watchlists(cb, response_watchlists))
    if not reports:
        return None

    return create_watchlist_from_report_list(cb, watchlist_name, watchlist_description, reports)


def convert_response_watchlists_to_grouped_enterprise_edr_watchlists(
    cb: CBCloudAPI,
    response_watchlists: List[Dict],
    watchlist_names_start_with: str = "ACE ",
) -> List[Dict]:
    """Convert a list of Response Watchlists to Enterprise EDR watchlists.

    This is a many-to-two Watchlist migration based on metrics provided by Response.

    Args:
      cb: CBCloudAPI object
      response_watchlists: List of Response Ratchlist in dictionary form.
      watchlist_names_start_with: A key/identifer to start the watchlist names with.

    Returns:
      List of Enterprise EDR Watchlists.
    """
    from cbinterface.helpers import input_with_timeout

    reports = list(yield_reports_created_from_response_watchlists(cb, response_watchlists))
    if not reports:
        return None

    results = []

    # no hits
    no_hit_reports = [r for r in reports if "no_hits_in_response" in r["tags"]]
    watchlist_name = f"{watchlist_names_start_with}CbResponse No Hit Watchlists"
    watchlist_description = "Migrated Cb Response Watchlists that didn't have a hit."
    results.append(create_watchlist_from_report_list(cb, watchlist_name, watchlist_description, no_hit_reports))

    # everything else is FP hits - low fidelity
    low_fid_reports = [r for r in reports if "no_hits_in_response" not in r["tags"]]
    watchlist_name = f"{watchlist_names_start_with}CbResponse Lower Fidelity Watchlists"
    watchlist_description = "Migrated Cb Response Watchlists that did have a hit but no True Positive ACE dispositions."
    results.append(create_watchlist_from_report_list(cb, watchlist_name, watchlist_description, low_fid_reports))

    return results
