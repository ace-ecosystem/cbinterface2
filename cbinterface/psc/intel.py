"""All things intel.

IOCs, Reports, Watchlists and Feeds.
"""
import time
import logging

from dateutil import tz
from dateutil.parser import parse as parse_timestamp
from datetime import datetime
from typing import Dict,List

from cbapi.psc.threathunter import CbThreatHunterAPI
from cbapi.errors import ServerError, ClientError, ObjectNotFoundError

LOGGER = logging.getLogger("cbinterface.psc.intel")


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
        LOGGER.error(f"Caught ServerError getting report {report_id}: {e}")

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
        return cb.get_object(url)
    except ServerError:
        LOGGER.error(f"Caught ServerError getting report {report_id}: {e}")

def get_report_with_IOC_status(cb: CbThreatHunterAPI, report_id) -> Dict:
    """Get report and include status of every report IOC."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}/iocs"
    report = get_report(cb, report_id)
    for ioc in report['iocs_v2']:
        ioc['ignored'] = cb.get_object(f"{url}/{ioc['id']}/ignore")["ignored"]
    return report
        
def update_report(cb: CbThreatHunterAPI, report_id, report_data) -> Dict:
    """Update an existing report."""
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/reports/{report_id}"

    # clean up any ignored ioc fields or Cb will bark back
    for ioc in report_data['iocs_v2']:
        if 'ignored' in ioc:
            del ioc['ignored']

    # updating report time is required
    report_data['timestamp'] = time.time()

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
    for ioc in report_data['iocs_v2']:
        if ioc['id'] == ioc_id:
            if ioc['match_type'] != 'query':
                LOGGER.error(f"not a query based IOC: {ioc}")
                return False
            if ioc['ignored']:
                LOGGER.warning(f"you're updating an IOC that is set to ignored.")
            if len(ioc['values']) > 1:
                LOGGER.warning(f"This query IOC has a surprising number of values that are about to be over-written: {ioc['values']}")
            ioc['values'] = [ioc_query_string]
    return update_report(cb, report_id, report_data)

def interactively_update_report_ioc_query(cb: CbThreatHunterAPI, report_id, ioc_id) -> Dict:
    """Prompt user for new query and update the report IOC query.
    """
    from cbinterface.helpers import input_with_timeout

    new_ioc_query = input_with_timeout("Enter new query: ")
    return update_report_ioc_query(cb, report_id, ioc_id, new_ioc_query)

def print_report(report: Dict) -> None:
    """Special print formatting."""
    print("\n------------------------- INTEL REPORT -------------------------")
    for field,value in report.items():
        if 'iocs_v2' == field:
            continue
        print(f"\t{field}: {value}")
    print(f"\tiocs_v2: ")
    for ioc in report['iocs_v2']:
        for field,value in ioc.items():
            if field == 'values':
                continue
            print(f"\t\t{field}: {value}")
        for ioc_value in ioc['values']:
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

def update_watchlist(cb: CbThreatHunterAPI, watchlist_data: Dict):
    url = f"/threathunter/watchlistmgr/v3/orgs/{cb.credentials.org_key}/watchlists"
    try:
        result = cb.put_object(url, watchlist_data)
    except ServerError as e:
        LOGGER.error(f"Caught ServerError creating watchlist: {e}")
        return False
    except ClientError as e:
        LOGGER.warning(f"got ClientError creating watchlist: {e}")
        return False

    return result.json()

def create_watchlist_from_report_list(cb: CbThreatHunterAPI, watchlist_name: str, watchlist_description: str, reports: List[Dict]) -> Dict:
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

    watchlist_data = {"name": watchlist_name,
                        "description": watchlist_description,
                        "tags_enabled": True,
                        "alerts_enabled": True,
                        "report_ids": report_ids
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

def get_feed_report(cb: CbThreatHunterAPI, feed_id: str, report_id: str) -> Dict:
    """Get a specific report from a specific feed."""
    url = f"/threathunter/feedmgr/v2/orgs/{cb.credentials.org_key}/feeds/{feed_id}/reports/{report_id}"
    try:
        return cb.get_object(url)
    except ServerError:
        LOGGER.error(f"Caught ServerError getting feed report {feed_id}: {e}")
    except ObjectNotFoundError:
        LOGGER.warning(f"No feed {feed_id} or report {report_id} in the feed")

## Response to PSC EDR Watchlist Migrations ##
def yield_reports_created_from_response_watchlists(cb: CbThreatHunterAPI, response_watchlists: List[Dict]) -> List[Dict]:
    """Convert a list of response watchlists to PSC EDR intel reports.

    Args:
      cb: Cb PSC object
      response_watchlists: List of Response Watchlist in dictionary form.
    Returns:
      Yield PSC Intel Reports for each Response Watchlist.
    """
    psc_watchlist_names = [wl['name'] for wl in get_all_watchlists(cb)]
    for wl_data in response_watchlists:
        # attempt to convert and validate query syntax for PSC
        if 'query' not in wl_data:
            LOGGER.error("how does a legacy watchlist not have a query? make sure to convert search_query to query.")
            continue
        query = wl_data['query']
        try:
            query = cb.convert_query(query)
            LOGGER.info(f"converted query: {query}")
        except Exception as e:
            LOGGER.error(f"problem converting query for {wl_data['name']} : {e}")
            continue
        if not cb.validate_query(query):
            LOGGER.error(f"query did not validate")
            continue

        # warn if already a watchlist by the same name
        if wl_data["name"] in psc_watchlist_names:
            LOGGER.warning(f"watchlist with name={wl_data['name']} already exists.")
            continue

        ignore_this_report = False
        # the next few checks will set the flag telling us if the report should
        # be set to ignore

        # warn of disabled watchlists
        if not wl_data["enabled"]:
            LOGGER.warning(f"{wl_data['name']} is disabled... NOT creating report.")
            ignore_this_report = True

        # warn on slow watchlists
        if wl_data["last_execution_time_ms"] is None:
            LOGGER.error(f"{wl_data['name']} last_execution_time time is null. This means an error occurred with it's execution. Setting report to ignore.")
            ignore_this_report = True
        elif int(wl_data["last_execution_time_ms"]) > 10000:
            seconds = int(wl_data["last_execution_time_ms"]) / 1000
            LOGGER.warning(f"{wl_data['name']} last_execution_time took {seconds} seconds")
            if seconds > 30:
                LOGGER.warning(f"{wl_data['name']} has been 💩 slow in response. Setting report to ignore...")
                ignore_this_report = True
            
        # inform of hit count per day
        hit_count = int(wl_data["total_hits"])
        created_date = parse_timestamp(wl_data["date_added"]).astimezone(tz.gettz("UTC"))
        days_since_creation = (datetime.utcnow().astimezone(tz.gettz("UTC")) - created_date).days
        LOGGER.info(f"{wl_data['name']} has a hit count per day ratio of: {hit_count/days_since_creation}")

        # create report
        ioc_data = {"id": 1,
                    "match_type": "query",
                    "values": [query] }
        report_data = {"title": wl_data.get("name"),
                       "description": f"Intel report for legacy response watchlist. Legacy description: {wl_data.get('description')} {'(ignored)' if ignore_this_report else ''} \n===LEGACY DATA===\n{wl_data}",
                       "timestamp": time.time(),
                       "severity": 5,
                       "tags": ["response_migrated_watchlist"],
                       "iocs_v2": [ioc_data]}
        intel_report = create_report(cb, report_data)
        if not isinstance(intel_report, dict):
            LOGGER.error(f"problem creating report for {report_data}")
            continue
        LOGGER.info(f"created intel report: {intel_report}")
        if ignore_this_report:
            if ignore_report(cb, intel_report['id']):
                LOGGER.info(f"ignored report {intel_report['id']}")

        yield intel_report

def convert_response_watchlists_to_psc_edr_watchlists(cb: CbThreatHunterAPI, response_watchlists: List[Dict]) -> List[Dict]:
    """Convert a list of response watchlists to PSC EDR watchlists.

    This is a one-for-one Watchlist migration.

    Args:
      cb: Cb PSC object
      response_watchlists: List of response watchlist in dictionary form.
    Returns:
      List of PSC Watchlists.
    """
    results = []
    for intel_report in yield_reports_created_from_response_watchlists(cb, response_watchlists):
        report_id = intel_report["id"]
        
        #create watchlist
        watchlist_data = {"name": wl_data.get("name"),
                          "description": f"Legacy Response description: {wl_data.get('description')}",
                          "tags_enabled": True,
                          "alerts_enabled": True,
                          "report_ids": [report_id]
                        }
        watchlist = create_watchlist(cb, watchlist_data)
        if not isinstance(watchlist, dict):
            LOGGER.error(f"problem creating watchlist for {watchlist_data}")
            continue
        LOGGER.info(f"created watchlist: {watchlist}")
        psc_watchlist_names.append(watchlist['name'])
        results.append(watchlist)
    return results

def convert_response_watchlists_to_single_psc_edr_watchlist(cb: CbThreatHunterAPI, response_watchlists: List[Dict], watchlist_name: str=None, watchlist_description="Consolidated Cb Respone Watchlists, Watchlist. Each report in this watchlist is based on a Cb Response Watchlist") -> List[Dict]:
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
        watchlist_description = input_with_timeout(f"Enter a description for the Watchlist [default description: {watchlist_description}] : ", stderr=False) or watchlist_description

    reports = list(yield_reports_created_from_response_watchlists(cb, response_watchlists))

    return create_watchlist_from_report_list(cb, watchlist_name, watchlist_description, reports)