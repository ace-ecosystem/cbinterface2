"""All things intel & alerts.

IOCs, Reports, Watchlists, Feeds, Alerts.

NOTE on Response Watchlist to PSC EDR Intel Migrations:

  There are three different ways that I built to migrate Response 
  Watchlists to PSC EDR Watchlists:
   1. One-to-One
   2. Many-to-One
   3. Many-to-Two (Not connected to CLI)

 All of the above use the `yield_reports_created_from_response_watchlists` to convert
 Response Watchlists into PSC EDR Reports. That function converts the Response queries to
 valid PSC EDR queries. If a query doesn't validate/convert, a log is generated and it's 
 skipped. If it does validate, a Report is generated. If the Watchlist, in Response, was really slow or
 had errors the resulting PSC EDR Report will be set to "ignore" automatically. Additionally, I passed
 all the available context about the Response Watchlist into the description of the resulting Reports.

 We had over 300 custom Response Watchlists, here is what I did for our use case:
  1. I seperated the watchlists with true positive detections and low FP rates 
     using our ACE Alert metrics. I put the names of these Watchlists into a txt file
     and then exported them from response using the following command:
       `cat ~smcfeely/working/cbmigration/uniq.high_fidelity.watchlists.txt | cbinterface response_watchlist --watchlist-names-from-stdin -json > high_fid.response_watchlists.json`

  2. Next, I used the command below to import these Response Watchlists into a single
     PSC EDR Watchlist I called "ACE Higher Fidelity Response Watchlists":
       `cbinterface intel migrate ~smcfeely/working/cbmigration/high_fid.response_watchlists.json --many-to-one`

  3. After that, I exported the remaining custom Response Watchlists into another json file and called the
     `convert_response_watchlists_to_grouped_psc_edr_watchlists` function from a python terminal to organize 
     the Response Watchlists into *two* PSC EDR Watchlists, one for Response Watchlists that have never
     had a hit and then the ones remaining are lower fidelity and went into a "Low Fidelity" PSC EDR Watchlist.
        
"""
import json
import time
import logging

from dateutil import tz
from dateutil.parser import parse as parse_timestamp
from datetime import datetime
from typing import Dict, List, Union

from cbapi.psc.threathunter import CbThreatHunterAPI
from cbapi.errors import ServerError, ClientError, ObjectNotFoundError

LOGGER = logging.getLogger("cbinterface.psc.intel")


## Alerts ##
def alert_search(
    cb: CbThreatHunterAPI,
    search_data: Dict = {},
    criteria: Dict = {},
    query: str = None,
    rows=40,
    sort: List[Dict] = [{"field": "first_event_time", "order": "DESC"}],
    start: int = 0,
    workflow_state=["OPEN", "DISMISSED"],
) -> Dict:
    """Perform an Alert search

    One request and return the result.
    """
    url = f"/appservices/v6/orgs/{cb.credentials.org_key}/alerts/watchlist/_search"
    if not search_data:
        if "workflow" not in criteria:
            criteria["workflow"] = workflow_state
        search_data = {"criteria": criteria, "query": query, "rows": rows, "start": start, "sort": sort}
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
    cb: CbThreatHunterAPI,
    search_data: Dict = {},
    criteria: Dict = {},
    query: str = None,
    rows=40,
    sort: List[Dict] = [{"field": "last_update_time", "order": "ASC"}],
    start: int = 0,
    workflow_state=["OPEN", "DISMISSED"],
    max_results: int = None,  # limit results returned
) -> Dict:
    """Yield Alerts resulting from alert search."""
    position = start
    still_querying = True
    while still_querying:
        if max_results and position + rows > max_results:
            # get however many rows that may result in max_results
            rows = max_results - position
        result = alert_search(
            cb,
            search_data=search_data,
            criteria=criteria,
            query=query,
            rows=rows,
            sort=sort,
            start=position,
            workflow_state=workflow_state,
        )

        if not result:
            return result

        total_results = result["num_found"]
        results = result.get("results", [])
        LOGGER.debug(f"got {len(results)+position} out of {total_results} total alerts.")
        for item in results:
            yield item
            position += 1
            if max_results and position >= max_results:
                still_querying = False
                break

        if position >= total_results:
            still_querying = False
            break


def get_all_alerts(
    cb: CbThreatHunterAPI,
    search_data: Dict = {},
    criteria: Dict = {},
    query: str = None,
    rows=40,
    sort: List[Dict] = [{"field": "last_update_time", "order": "ASC"}],
    start: int = 0,
    workflow_state=["OPEN", "DISMISSED"],
    max_results: int = None,  # limit results returned
) -> Dict:
    """Return list of Alerts resulting from alert search."""
    return list(
        yield_alerts(
            cb,
            search_data=search_data,
            criteria=criteria,
            query=query,
            rows=rows,
            sort=sort,
            start=start,
            workflow_state=workflow_state,
            max_results=max_results,
        )
    )


def get_alert(cb: CbThreatHunterAPI, alert_id) -> Dict:
    """Get alert by ID."""
    url = f"/appservices/v6/orgs/{cb.credentials.org_key}/alerts/{alert_id}"
    try:
        return cb.get_object(url)
    except ServerError:
        LOGGER.error(f"Caught ServerError getting report {report_id}: {e}")


def update_alert_state(
    cb: CbThreatHunterAPI,
    alert_id,
    state: Union["DISMISSED", "OPEN"],
    remediation_state: str = None,
    comment: str = None,
) -> Dict:
    """Update alert remediation state by ID."""
    url = f"/appservices/v6/orgs/{cb.credentials.org_key}/alerts/{alert_id}/workflow"
    remediation = {"state": state, "remediation_state": remediation_state, "comment": comment}
    try:
        return cb.post_object(url, remediation).json()
    except ServerError as e:
        LOGGER.error(f"Caught ServerError: {e}")
        return False
    except ClientError as e:
        LOGGER.warning(f"got ClientError:: {e}")
        return False


def interactively_update_alert_state(
    cb: CbThreatHunterAPI,
    alert_id,
    state: Union["DISMISSED", "OPEN"] = None,
    remediation_state: str = None,
    comment: str = None,
) -> Dict:
    """Update alert remediation state by ID."""
    from cbinterface.helpers import input_with_timeout

    if not state:
        state = input_with_timeout("Alert state to set, DISMISSED or OPEN? [DISMISSED]: ") or "DISMISSED"
        if state not in ["DISMISSED", "OPEN"]:
            LOGGER.error(f"state must be one of [DISMISSED, OPEN], not {state}")
            return False
    if not remediation_state:
        remediation_state = input_with_timeout("State of Remediation: ") or ""
    if not comment:
        comment = input_with_timeout("Comment: ") or ""
    return update_alert_state(cb, alert_id, state, remediation_state, comment)


## Reports ##
def create_report(cb: CbThreatHunterAPI, report_data) -> Dict:
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


def ignore_report(cb: CbThreatHunterAPI, report_id) -> Dict:
    """Set this report to ignore status"""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}/ignore"
    try:
        return cb.put_object(url, {"ignore": True})
    except ServerError:
        LOGGER.error(f"Caught ServerError getting report {report_id}: {e}")


def delete_report(cb: CbThreatHunterAPI, report_id) -> Dict:
    """Set this report to ignore status"""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}"
    try:
        return cb.delete_object(url)
    except ServerError:
        LOGGER.error(f"Caught ServerError deleting report {report_id}: {e}")


def get_report_status(cb: CbThreatHunterAPI, report_id) -> Dict:
    """Get report to ignore status"""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}/ignore"
    try:
        return cb.get_object(url)
    except ServerError:
        LOGGER.error(f"Caught ServerError getting report {report_id}: {e}")


def activate_report(cb: CbThreatHunterAPI, report_id) -> Dict:
    """Set this report to active status"""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}/ignore"
    try:
        return cb.delete_object(url)
    except ServerError:
        LOGGER.error(f"Caught ServerError getting report {report_id}: {e}")


def get_report(cb: CbThreatHunterAPI, report_id) -> Dict:
    """Get report by report id."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}"
    try:
        report = cb.get_object(url)
        report["ignored"] = get_report_status(cb, report["id"])["ignored"]
        return report
    except ServerError:
        LOGGER.error(f"Caught ServerError getting report {report_id}: {e}")
    except ObjectNotFoundError:
        LOGGER.warning(f"report {report_id} does not exist")


def get_report_with_IOC_status(cb: CbThreatHunterAPI, report_id) -> Dict:
    """Get report and include status of every report IOC."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}/iocs"
    report = get_report(cb, report_id)
    if not report:
        return None
    for ioc in report["iocs_v2"]:
        ioc["ignored"] = cb.get_object(f"{url}/{ioc['id']}/ignore")["ignored"]
    return report


def update_report(cb: CbThreatHunterAPI, report_id, report_data) -> Dict:
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


def update_report_ioc_query(cb: CbThreatHunterAPI, report_id, ioc_id, ioc_query_string) -> Dict:
    """Update IOC query value with ioc_query_string.

    A cbapi.errors.ClientError will be raised if the query is not valid.
    """
    report_data = get_report_with_IOC_status(cb, report_id)
    for ioc in report_data["iocs_v2"]:
        if ioc["id"] == ioc_id:
            if ioc["match_type"] != "query":
                LOGGER.error(f"not a query based IOC: {ioc}")
                return False
            if ioc["ignored"]:
                LOGGER.warning(f"you're updating an IOC that is set to ignored.")
            if len(ioc["values"]) > 1:
                LOGGER.warning(
                    f"This query IOC has a surprising number of values that are about to be over-written: {ioc['values']}"
                )
            ioc["values"] = [ioc_query_string]
    return update_report(cb, report_id, report_data)


def interactively_update_report_ioc_query(cb: CbThreatHunterAPI, report_id, ioc_id) -> Dict:
    """Prompt user for new query and update the report IOC query."""
    from cbinterface.helpers import input_with_timeout

    new_ioc_query = input_with_timeout("Enter new query: ", timeout=90)
    return update_report_ioc_query(cb, report_id, ioc_id, new_ioc_query)


def print_report(report: Dict) -> None:
    """Special print formatting."""
    print("\n------------------------- INTEL REPORT -------------------------")
    for field, value in report.items():
        if "iocs_v2" == field:
            continue
        print(f"\t{field}: {value}")
    print(f"\tiocs_v2: ")
    for ioc in report["iocs_v2"]:
        for field, value in ioc.items():
            if field == "values":
                continue
            print(f"\t\t{field}: {value}")
        for ioc_value in ioc["values"]:
            print(f"\t\tioc_value: {ioc_value}")
    print()


## IOCs ##
# get IOC status

# ignore IOC

# activate IOC

## Watchlists ##
def get_all_watchlists(cb: CbThreatHunterAPI):
    """Return a list of all watchlists."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/watchlists"
    result = cb.get_object(url)
    return result.get("results", [])


def get_watchlist(cb: CbThreatHunterAPI, watchlist_id):
    """Get a watchlist by ID."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/watchlists"
    try:
        return cb.get_object(f"{url}/{watchlist_id}")
    except ServerError:
        LOGGER.error(f"Caught ServerError getting watchlist {watchlist_id}: {e}")
    except ObjectNotFoundError:
        LOGGER.warning(f"No watchlist with ID {watchlist_id}")


def get_watchlists_like_name(cb: CbThreatHunterAPI, watchlist_name):
    """Return watchlists with watchlist_name in their name."""
    return [wl for wl in get_all_watchlists(cb) if watchlist_name in wl["name"]]


def create_watchlist(cb: CbThreatHunterAPI, watchlist_data: Dict):
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


def delete_watchlist(cb: CbThreatHunterAPI, watchlist_id) -> Dict:
    """Set this report to ignore status"""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/watchlists/{watchlist_id}"
    try:
        return cb.delete_object(url)
    except ServerError:
        LOGGER.error(f"Caught ServerError deleting watchlist {watchlist_id}: {e}")


def update_watchlist(cb: CbThreatHunterAPI, watchlist_data: Dict):
    watchlist_id = watchlist_data['id']
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
    cb: CbThreatHunterAPI, watchlist_name: str, watchlist_description: str, reports: List[Dict]
) -> Dict:
    """Create a watchlist built on the supplied intel reports.

    Use this to create a single watchlist comprised of the intel reports.

    Args:
      cb: Cb PSC object
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


def assign_reports_to_watchlist(cb: CbThreatHunterAPI, watchlist_id: str, reports: List[Dict]) -> Dict:
    """Set a watchlist report IDs attribute to the passed reports.

    Args:
      cb: Cb PSC object
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
        LOGGER.error(f"unexpected problem updating watchlist with report IDs.")
        return False

    return watchlist_data


# TODO enable watchlist alerting/taging?

# TODO disable watchlist alerting/taging?

## Feeds ##
def get_all_feeds(cb: CbThreatHunterAPI, include_public=True) -> Dict:
    """Retrieve all feeds owned by the caller.

    Provide include_public=true parameter to also include public community feeds.
    """
    url = f"/threathunter/feedmgr/v2/orgs/{cb.credentials.org_key}/feeds"
    params = {"include_public": include_public}
    result = cb.get_object(url, query_parameters=params)
    return result.get("results", [])


def get_feed(cb: CbThreatHunterAPI, feed_id: str) -> Dict:
    """Get a specific feed by ID."""
    url = f"/threathunter/feedmgr/v2/orgs/{cb.credentials.org_key}/feeds"
    try:
        return cb.get_object(f"{url}/{feed_id}")
    except ServerError:
        LOGGER.error(f"Caught ServerError getting feed {feed_id}: {e}")
    except ObjectNotFoundError:
        LOGGER.warning(f"No feed by feed id {feed_id}")


def search_feed_names(cb: CbThreatHunterAPI, name: str) -> List[Dict]:
    """Search for feeds by name."""
    return [f for f in get_all_feeds(cb) if name in f["name"]]


def get_feed_report(cb: CbThreatHunterAPI, feed_id: str, report_id: str) -> Dict:
    """Get a specific report from a specific feed."""
    url = f"/threathunter/feedmgr/v2/orgs/{cb.credentials.org_key}/feeds/{feed_id}/reports/{report_id}"
    try:
        return cb.get_object(url)
    except ServerError:
        LOGGER.error(f"Caught ServerError getting feed report {feed_id}: {e}")
    except ObjectNotFoundError:
        LOGGER.warning(f"No feed {feed_id} or report {report_id} in the feed")


## Begin Response to PSC EDR Watchlist Migrations ##
def yield_reports_created_from_response_watchlists(
    cb: CbThreatHunterAPI, response_watchlists: List[Dict]
) -> List[Dict]:
    """Convert a list of response watchlists to PSC EDR intel reports.

    Args:
      cb: Cb PSC object
      response_watchlists: List of Response Watchlist in dictionary form.
    Returns:
      Yield PSC Intel Reports for each Response Watchlist.
    """
    psc_watchlist_names = [wl["name"] for wl in get_all_watchlists(cb)]
    for wl_data in response_watchlists:
        # attempt to convert and validate query syntax for PSC
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
            LOGGER.error(f"query did not validate")
            continue

        report_tags = ["response_migrated_watchlist"]
        report_description = f"Legacy Cb Response Watchlist Description: {wl_data.get('description')}"

        ignore_this_report = False

        # warn of disabled watchlists
        if not wl_data["enabled"]:
            LOGGER.warning(f"{wl_data['name']} is disabled... NOT creating report.")
            ignore_this_report = True
            report_description += f"\nIgnored: disabled in Cb Response"
            report_tags.append("disabled_in_response")

        # warn on slow watchlists
        if wl_data["last_execution_time_ms"] is None:
            LOGGER.error(
                f"{wl_data['name']} last_execution_time time is null. This means an error occurred with it's execution. Setting report to ignore."
            )
            ignore_this_report = True
            report_description += f"\nIgnored: last execution error'd in Cb Response"
            report_tags.append("execution_errors_in_response")
        elif int(wl_data["last_execution_time_ms"]) > 10000:
            seconds = int(wl_data["last_execution_time_ms"]) / 1000
            LOGGER.warning(f"{wl_data['name']} last_execution_time took {seconds} seconds")
            report_tags.append("slow_in_response")
            if seconds > 30:
                LOGGER.warning(f"{wl_data['name']} has been 💩 slow in response. Setting report to ignore...")
                ignore_this_report = True
                report_description += f"\nIgnored: has been 💩 slow in Cb Response. Improve it!?"

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


def convert_response_watchlists_to_psc_edr_watchlists(
    cb: CbThreatHunterAPI, response_watchlists: List[Dict]
) -> List[Dict]:
    """Convert a list of response watchlists to PSC EDR watchlists.

    This is a one-for-one Watchlist migration. You probably don't want this.

    Args:
      cb: Cb PSC object
      response_watchlists: List of response watchlist in dictionary form.
    Returns:
      List of PSC Watchlists.
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


def convert_response_watchlists_to_single_psc_edr_watchlist(
    cb: CbThreatHunterAPI,
    response_watchlists: List[Dict],
    watchlist_name: str = None,
    watchlist_description="Consolidated Cb Respone Watchlists. Each report in this watchlist is based on a Cb Response Watchlist",
) -> List[Dict]:
    """Convert a list of Response Watchlists to PSC EDR watchlists.

    This is a many-to-one Watchlist migration.

    Args:
      cb: Cb PSC object
      response_watchlists: List of Response Ratchlist in dictionary form.
      watchlist_name: The name to give the resulting Response consolidated PSC EDR Watchlist.
      watchlist_description: The description to give the resulting Watchlist.
    Returns:
      PSC Watchlist containing all Response Watchlists as intel Reports.
    """
    from cbinterface.helpers import input_with_timeout

    if watchlist_name is None:
        watchlist_name = input_with_timeout("Enter a name for the resulting PSC EDR Watchlist: ", stderr=False)
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


def convert_response_watchlists_to_grouped_psc_edr_watchlists(
    cb: CbThreatHunterAPI,
    response_watchlists: List[Dict],
    watchlist_names_start_with: str = "ACE ",
) -> List[Dict]:
    """Convert a list of Response Watchlists to PSC EDR watchlists.

    This is a many-to-two Watchlist migration based on metrics provided by Response.

    Args:
      cb: Cb PSC object
      response_watchlists: List of Response Ratchlist in dictionary form.
      watchlist_names_start_with: A key/identifer to start the watchlist names with.
    Returns:
      List of PSC Watchlists.
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
