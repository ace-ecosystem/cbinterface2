"""Enterprise EDR CLI functions."""

import os
import sys
import argparse
import datetime
import logging
import json
import yaml

from dateutil import tz

from typing import List, Union

from cbc_sdk import __file__ as cbc_sdk_file_path
from cbc_sdk.platform.devices import Device, DeviceSearchQuery
from cbc_sdk.errors import ObjectNotFoundError, MoreThanOneResultError
from cbc_sdk.enterprise_edr import Watchlist, Feed
from cbc_sdk import CBCloudAPI
from cbc_sdk.platform import Process
from cbinterface.helpers import is_eedr_guid, clean_exit, input_with_timeout
from cbinterface.enterprise_edr.query import make_process_query, print_facet_histogram, yield_events
from cbinterface.enterprise_edr.ubs import (
    request_and_get_files,
    get_file_metadata,
    get_device_summary,
    get_signature_summary,
    get_file_path_summary,
    consolidate_metadata_and_summaries,
)
from cbinterface.enterprise_edr.intel import (
    convert_response_watchlists_to_enterprise_edr_watchlists,
    get_all_watchlists,
    get_watchlist,
    get_report,
    delete_report,
    get_report_with_IOC_status,
    print_report,
    interactively_update_report_ioc_query,
    convert_response_watchlists_to_single_enterprise_edr_watchlist,
    get_all_feeds,
    get_feed,
    get_feed_report,
    get_alert,
    yield_alerts,
    update_alert_status,
    interactively_update_alert_state,
    get_watchlists_like_name,
    search_feed_names,
    is_ioc_ignored,
    ignore_ioc,
    activate_ioc,
    create_new_report_and_append_to_watchlist,
    write_basic_report_template,
    backup_watchlist_threat_reports,
)
from cbinterface.enterprise_edr.device import (
    make_device_query,
    device_info,
    time_since_checkin,
    find_device_by_hostname,
    is_device_online,
    yield_devices,
)
from cbinterface.enterprise_edr.process import (
    print_process_info,
    print_ancestry,
    print_process_tree,
    print_modloads,
    print_filemods,
    inspect_process_tree,
    print_netconns,
    print_regmods,
    print_crossprocs,
    print_childprocs,
    print_scriptloads,
    process_to_dict,
    format_event_data,
)
from cbinterface.commands import (
    PutFile,
    ProcessListing,
    GetFile,
    ListRegKeyValues,
    RegKeyValue,
    ExecuteCommand,
    ListDirectory,
    WalkDirectory,
    LogicalDrives,
    DeleteFile,
    KillProcessByID,
    KillProcessByName,
    DeleteRegistryKeyValue,
    DeleteRegistryKey,
    SetRegKeyValue,
    CreateRegKey,
    GetSystemMemoryDump,
)
from cbinterface.enterprise_edr.sessions import (
    CustomLiveResponseSessionManager,
    get_session_by_id,
    device_live_response_sessions_by_device_id,
    all_live_response_sessions,
    get_session_commands,
    get_command_result,
    get_file_content,
    close_session_by_id,
)
from cbinterface.enterprise_edr.enumerations import logon_history
from cbinterface.config import (
    get_playbook_map,
    add_watchlist_id_to_intel_backup_list,
    remove_watchlist_id_from_intel_backup_list,
    get_intel_backup_watchlist_list,
)
from cbinterface.scripted_live_response import build_playbook_commands, build_remediation_commands

LOGGER = logging.getLogger("cbinterface.enterprise_edr.cli")


def toggle_device_quarantine(cb: CBCloudAPI, devices: Union[DeviceSearchQuery, List[Device]], quarantine: bool) -> bool:
    """Toggle device quarantine state.

    Args:
        devices: DeviceSearchQuery
        quarantine: set quarantine if True, else set quarantine to off state.
    """
    if len(devices) > 0:
        if len(devices) > 10 and quarantine:
            LOGGER.error(
                f"For now, not going to quarantine {len(devices)} devices as a safeguard "
                f"to prevent mass device impact... use the GUI if you must."
            )
            return False
        verbiage = "quarantine" if quarantine else "NOT quarantine"
        emotion = "👀" if quarantine else "👏"
        LOGGER.info(f"setting {verbiage} on {len(devices)} devices... {emotion}")

        for d in devices:
            if d.quarantined == quarantine:
                LOGGER.warning(f"device {d.id}:{d.name} is already set to {verbiage}.")
                continue
            if not is_device_online(d):
                LOGGER.info(f"device {d.id}:{d.name} hasn't checked in for: {time_since_checkin(d, refresh=False)}")
                LOGGER.warning(f"device {d.id}:{d.name} appears offline 💤")
                LOGGER.info(f"device {d.id}:{d.name} will change quarantine state when it comes online 👌")
            cb.device_quarantine([d.id], quarantine)
        return True


def add_eedr_arguments_to_parser(subparsers: argparse.ArgumentParser) -> None:
    """Given an argument parser subparser, build a EEDR specific parser."""
    # device query
    parser_sensor = subparsers.add_parser("device", aliases=["d"], help="Execute a device query.")
    parser_sensor.add_argument("device_query", help="the device query you'd like to execute. 'FIELDS' for help.")
    parser_sensor.add_argument(
        "-nw",
        "--no-warnings",
        action="store_true",
        default=False,
        help="Don't warn before printing large query results",
    )
    parser_sensor.add_argument(
        "-ad",
        "--all-details",
        action="store_true",
        default=False,
        help="Print all available process info (all fields).",
    )
    parser_sensor.add_argument(
        "-q",
        "--quarantine",
        action="store_true",
        default=False,
        help="Quarantine the devices returned by the query.",
    )
    parser_sensor.add_argument(
        "-uq",
        "--un_quarantine",
        action="store_true",
        default=False,
        help="UN-Quarantine the devices returned by the query.",
    )
    parser_sensor.add_argument(
        "--export",
        action="store_true",
        default=False,
        help="Export devices by status. WARNING: dumps json to console! Example: `cbinterface d ALL --export` would export 'ALL' devices.",
    )

    # UBS parser
    parser_ubs = subparsers.add_parser(
        "ubs", help="Interface with the Universal Binary Store (UBS) to download files and/or get information."
    )
    parser_ubs.add_argument(
        "--sha256",
        dest="sha256hashes",
        action="append",
        default=[],
        help="The SHA-256 hash of a file you're interested in. Use multiple times to build list.",
    )
    parser_ubs.add_argument(
        "--from-stdin", action="store_true", help="Read SHA-256 hashes piped from stdin to work with."
    )
    parser_ubs.add_argument(
        "-g",
        "--get-file",
        dest="ubs_get_file",
        action="store_true",
        help="Attempt to download file content for the SHA-256 hashes supplied by `--sha256`",
    )
    parser_ubs.add_argument(
        "-ds",
        "--get-device-summary",
        dest="ubs_get_device_summary",
        action="store_true",
        help="Get an overview of the devices that executed the file.",
    )
    parser_ubs.add_argument(
        "-ss",
        "--get-signature-summary",
        dest="ubs_get_signature_summary",
        action="store_true",
        help="Summary of the observed digital signature results for a given SHA-256 hashes.",
    )
    parser_ubs.add_argument(
        "-fps",
        "--get-file-path-summary",
        dest="ubs_get_file_path_summary",
        action="store_true",
        help="Summary of the observed file paths for a given SHA-256 hashes.",
    )
    parser_ubs.add_argument(
        "-i",
        "--get-metadata",
        dest="ubs_get_metadata",
        action="store_true",
        help="Get file metadata for give SHA-256 hashes.",
    )
    parser_ubs.add_argument(
        "-ci",
        "--combined-info",
        dest="ubs_combined_info",
        action="store_true",
        help="Combine metadata and summaries per SHA-256",
    )

    # intel parser
    parser_intel = subparsers.add_parser("intel", help="Intel Feeds, Watchlists, Reports, & IOCs")
    parser_intel.add_argument("--json", action="store_true", help="Return results as JSON.")
    parser_intel.add_argument(
        "--backup",
        action="store_true",
        dest="intel_backup",
        help="Download a copy of this watchlist and its threat reports.",
    )
    parser_intel.add_argument(
        "--track-watchlist-id", action="store", help="Track this watchlist via configuration for backups."
    )
    parser_intel.add_argument(
        "--untrack-watchlist-id", action="store", help="Remove this watchlist from the tracking list for backups."
    )

    intel_subparsers = parser_intel.add_subparsers(dest="intel_command")

    # intel watchlists
    parser_intel_watchlists = intel_subparsers.add_parser(
        "watchlists", help="Interface with Enterprise EDR Watchlists."
    )
    parser_intel_watchlists.add_argument("-lw", "--list-watchlists", action="store_true", help="List all watchlists.")
    parser_intel_watchlists.add_argument("-w", "--get-watchlist", action="store", help="Get watchlist by ID.")
    parser_intel_watchlists.add_argument(
        "-wn", "--watchlist-name-search", action="store", help="Search for watchlists by name."
    )
    parser_intel_watchlists.add_argument(
        "-wr", "--get-watchlist-report", action="store", help="Get a watchlist report by report ID."
    )
    parser_intel_watchlists.add_argument(
        "-dr", "--delete-watchlist-report", action="store", help="Delete watchlist report by ID."
    )
    parser_intel_watchlists.add_argument(
        "-wt",
        "--write-basic-threat-report-template",
        action="store_true",
        help="Write a basic single query IOC threat report template.",
    )
    parser_intel_watchlists.add_argument(
        "--update-ioc-query",
        action="store",
        help="Update a query IOC for the given report ID/IOC id. format: report_id/ioc_id",
    )
    parser_intel_watchlists.add_argument("--get-ioc-status", action="store", help="Get active/ignore status of an IOC.")
    parser_intel_watchlists.add_argument("--ignore-ioc", action="store", help="Ignore IOC.")
    parser_intel_watchlists.add_argument("--activate-ioc", action="store", help="Activate IOC.")

    # create new threat reports for watchlists
    parser_intel_watchlists_subparsers = parser_intel_watchlists.add_subparsers(dest="intel_watchlist_command")
    parser_intel_watchlist_creation = parser_intel_watchlists_subparsers.add_parser(
        "new", help="Create new Threat Report for a Watchlist."
    )
    parser_intel_watchlist_creation.add_argument(
        "report_path", action="store", help="Path to JSON representation of new Threat Report."
    )
    parser_intel_watchlist_creation.add_argument(
        "-w", "--watchlist-id", required=True, action="store", help="The ID of a watchlist to append to."
    )

    # intel feeds
    parser_intel_feeds = intel_subparsers.add_parser("feeds", help="Interface with Enterprise EDR Feeds.")
    parser_intel_feeds.add_argument("-lf", "--list-feeds", action="store_true", help="List all Feeds, public included.")
    parser_intel_feeds.add_argument(
        "-f",
        "--get-feed",
        action="store",
        help="Get Feed by ID. WARNING: Can return a lot of data if using the `--json` arg.",
    )
    parser_intel_feeds.add_argument(
        "-s", "--search-for-feed", action="store", help="Search the Feeds for feed names containing this value."
    )
    parser_intel_feeds.add_argument(
        "-fr",
        "--get-feed-report",
        action="store",
        help="Get specific Report from specific Feed. format: feed_id/report_id",
    )

    # alert parser plopped in here under intel
    parser_intel_alerts = intel_subparsers.add_parser("alerts", help="Interface with Alerts.")
    parser_intel_alerts.add_argument(
        "-a", "--alert-id", dest="alert_ids", default=[], action="append", help="List alert IDs to work with."
    )
    parser_intel_alerts.add_argument("-g", "--get-alert", action="store_true", help="Get Alert information.")
    parser_intel_alerts.add_argument(
        "-s",
        "--alerts-status",
        action="store",
        choices=["OPEN", "IN_PROGRESS", "CLOSED"],
        help="Set the status of Alerts.",
    )
    parser_intel_alerts.add_argument(
        "-d",
        "--determination",
        action="store",
        choices=["TRUE_POSITIVE", "FALSE_POSITIVE", "NONE"],
        help="Set the determination of Alerts. (Optional)",
    )

    parser_intel_alerts.add_argument(
        "-r",
        "--closure-reason",
        action="store",
        choices=["NO_REASON", "RESOLVED", "RESOLVED_BENIGN_KNOWN_GOOD", "DUPLICATE_CLEANUP", "OTHER"],
        help="Reason code for why the Alerts are being updated. (Optional)",
    )
    parser_intel_alerts.add_argument(
        "-n", "--note", action="store", help="Custom message to add to the note added to each modified aler. (Optional)"
    )
    parser_intel_alerts.add_argument(
        "-u", "--interactively-update-alert", action="store_true", help="Update Alerts interactively."
    )
    parser_intel_alerts.add_argument(
        "--from-stdin", action="store_true", help="Read alert IDs from stdin to work with."
    )

    intel_alerts_subparsers = parser_intel_alerts.add_subparsers(dest="intel_alerts_command")
    # alert search parser
    parser_intel_alerts_search = intel_alerts_subparsers.add_parser(
        "search", help="Search Alerts with lucene syntax queries and/or value searches."
    )
    parser_intel_alerts_search.add_argument(
        "alert_query",
        action="store",
        help="The lucene-formatted Alert search query. Example: 'watchlists_id:a1B2c3D4zxc AND workflow_status:OPEN'",
    )
    parser_intel_alerts_search.add_argument(
        "-rt",
        "--relative-time-range",
        action="store",
        help="Only return alerts created over the previous time range. Format: <integer_quantity><time_units>; time_units in [M, w, d, h, m, s]. Default=2w",
    )
    parser_intel_alerts_search.add_argument(
        "-et",
        "--explicit-time-range",
        action="store",
        help="Need to specify both start and end timestamps (ISO 8601) separated by a comma. Example: '2024-04-01T01:02:30.000Z,2024-04-03T04:05:06.000Z'",
    )
    parser_intel_alerts_search.add_argument(
        "-c",
        "--criteria",
        action="store",
        type=json.loads,
        help='Add criteria to the query. Example: \'{"device_os": ["WINDOWS"]}\'',
    )
    parser_intel_alerts_search.add_argument(
        "-ex",
        "--exclusions",
        action="store",
        type=json.loads,
        help='Add exclusions to the query. Example: \'{"device_location": ["UNKNOWN"], "device_os_version": ["Windows 11 x64"}]\'',
    )
    parser_intel_alerts_search.add_argument(
        "-so",
        "--sort",
        action="store",
        default=[{"field": "backend_update_timestamp", "order": "ASC"}],
        type=json.loads,
        help='Sort the results. Default=\'[{"field": "backend_update_timestamp", "order": "ASC"}]\'',
    )
    parser_intel_alerts_search.add_argument(
        "-st",
        "--pagination-start",
        action="store",
        default=1,
        type=int,
        help="One-based index of the first result to retrieve. Must be a whole number greater than or equal to 1. Default=1",
    )
    parser_intel_alerts_search.add_argument(
        "-r",
        "--rows",
        action="store",
        default=100,
        type=int,
        help="The number of rows to return starting from the pagination start. Increase this value in large queries to reduce waiting time. Default=100",
    )
    parser_intel_alerts_search.add_argument(
        "-m",
        "--max-alerts-result",
        action="store",
        default=500,
        type=int,
        help="Only return up to this many alerts. The maximum number of alerts is 10000. Default=500",
    )
    # cb response to enterprise edr migration parser
    parser_intel_migration = intel_subparsers.add_parser(
        "migrate", help="Utilities for migrating response watchlists to Enterprise EDR intel."
    )
    parser_intel_migration.add_argument(
        "response_watchlist_json_data_path",
        help="Path to response watchlist json file. (see cbinterface response_watchlist",
    )
    parser_intel_migration.add_argument(
        "--one-for-one",
        action="store_true",
        help="Create a Enterprise EDR Watchlist for every CbR watchlist that passes validation.",
    )
    parser_intel_migration.add_argument(
        "--many-to-one",
        action="store_true",
        help="Create a single Enterprise EDR Watchlist containing all CbR watchlist queries that pass validation.",
    )


def execute_eedr_arguments(cb: CBCloudAPI, args: argparse.Namespace) -> bool:
    """The logic to execute EEDR specific command line arguments.

    Args:
        cb: CBCloudAPI
        args: parsed argparse namespace

    Returns:
        True or None on success, False on failure.
    """
    if not isinstance(cb, CBCloudAPI):
        LOGGER.critical(f"Requires Cb Enterprise EDR based API. Got '{args.product}' API.")
        return False

    # UBS #
    if args.command == "ubs":
        if args.from_stdin:
            args.sha256hashes.extend([line.strip() for line in sys.stdin])

        if args.sha256hashes:

            set_ubs_args = [arg for arg, value in vars(args).items() if arg.startswith("ubs_") and value is True]
            if not set_ubs_args:
                LOGGER.debug("seting ubs metadata argument as default.")
                args.ubs_get_metadata = True

            if args.ubs_get_file:
                request_and_get_files(cb, sha256hashes=args.sha256hashes)
            if args.ubs_get_device_summary:
                summary = get_device_summary(cb, args.sha256hashes)
                if summary:
                    print(json.dumps(summary, indent=2))
            if args.ubs_get_signature_summary:
                summary = get_signature_summary(cb, args.sha256hashes)
                if summary:
                    print(json.dumps(summary, indent=2))
            if args.ubs_get_file_path_summary:
                summary = get_file_path_summary(cb, args.sha256hashes)
                if summary:
                    print(json.dumps(summary, indent=2))
            if args.ubs_get_metadata:
                # this is default if no arguments are specified with the sha256(s)
                file_metadata = get_file_metadata(cb, sha256hashes=args.sha256hashes)
                if file_metadata:
                    print(json.dumps(file_metadata, indent=2))
            if args.ubs_combined_info:
                results = consolidate_metadata_and_summaries(cb, args.sha256hashes)
                if results:
                    print(json.dumps(results, indent=2))
        else:
            LOGGER.error("You must specify at least one sha256 with the `--sha256` argument.")
            return False

        return True

    # Intel #
    if args.command == "intel":
        if args.intel_backup:
            watchlist_ids = get_intel_backup_watchlist_list()
            if not watchlist_ids:
                LOGGER.info("No watchlists configured for intel backup tracking.")
                return None
            return backup_watchlist_threat_reports(cb, watchlist_ids)
        if args.track_watchlist_id:
            return add_watchlist_id_to_intel_backup_list(args.track_watchlist_id)
        if args.untrack_watchlist_id:
            return remove_watchlist_id_from_intel_backup_list(args.untrack_watchlist_id)

        if args.intel_command == "alerts":

            if args.intel_alerts_command == "search":
                if args.relative_time_range and args.explicit_time_range:
                    logging.error("You can only use either explicit or relative time range. Try again.")
                    return False
                time_range = None
                if args.relative_time_range:
                    time_range = {"range": f"-{args.relative_time_range}"}
                elif args.explicit_time_range:
                    start, end = args.explicit_time_range.split(",")
                    time_range = {"start": start.strip(), "end": end.strip()}
                results = list(
                    yield_alerts(
                        cb,
                        args.alert_query,
                        time_range,
                        args.criteria,
                        args.exclusions,
                        args.sort,
                        args.pagination_start,
                        args.rows,
                        args.max_alerts_result,
                    )
                )
                if results:
                    print(json.dumps(results, indent=2))
                    print(f"\nTotal alerts {len(results)}")

                return True

            if args.from_stdin:
                args.alert_ids.extend([line.strip().strip('"') for line in sys.stdin])

            if not args.alert_ids:
                LOGGER.error("You have to supply at least one alert ID.")
                return False

            if args.get_alert:
                alerts = [get_alert(cb, alert_id) for alert_id in args.alert_ids]
                if alerts:
                    print(json.dumps(alerts, indent=2))

            if args.alerts_status:
                results = update_alert_status(
                    cb,
                    args.alert_ids,
                    status=args.alerts_status,
                    determination=args.determination,
                    closure_reason=args.closure_reason,
                    note=args.note,
                )
                if results:
                    print(json.dumps(results, indent=2))

            if args.interactively_update_alert:
                results = [interactively_update_alert_state(cb, alert_id) for alert_id in args.alert_ids]
                if results:
                    print(json.dumps(results, indent=2))

        if args.intel_command == "migrate":
            response_watchlists = None
            with open(args.response_watchlist_json_data_path, "r") as fp:
                response_watchlists = json.load(fp)

            if args.one_for_one:
                results = convert_response_watchlists_to_enterprise_edr_watchlists(cb, response_watchlists)
                LOGGER.info(
                    f"created {len(results)} Enterprise EDR watchlists from {len(response_watchlists)} Response watchlists."
                )
                print("Created watchlists:")
                for wl in results:
                    print(f" + ID={wl['id']} - Title={wl['name']}")

            if args.many_to_one:
                watchlist = convert_response_watchlists_to_single_enterprise_edr_watchlist(cb, response_watchlists)
                if not watchlist:
                    return False
                LOGGER.info(
                    f"Created \"{watchlist['name']}\" containing {len(watchlist['report_ids'])} intel reports based on {len(response_watchlists)} Response watchlists."
                )

        if args.intel_command == "watchlists":
            if args.intel_watchlist_command == "new":
                report_data = {}
                if not os.path.exists(args.report_path):
                    LOGGER.error(f"{args.report_path} does not exist.")
                    return False
                with open(args.report_path, "r") as fp:
                    report_data = json.load(fp)
                if not report_data:
                    LOGGER.error("failed to load report data")
                    return False
                watchlist_data = create_new_report_and_append_to_watchlist(cb, args.watchlist_id, report_data)
                if watchlist_data:
                    return True

            if args.write_basic_threat_report_template:
                result = write_basic_report_template()
                if result:
                    LOGGER.info(f"wrote: {result}")
                return result

            if args.list_watchlists:
                watchlists = get_all_watchlists(cb)
                if args.json:
                    print(json.dumps(watchlists, indent=2))
                else:
                    for wl in watchlists:
                        print(Watchlist(cb, initial_data=wl))
                        print()

            if args.get_watchlist:
                watchlist = get_watchlist(cb, args.get_watchlist)
                if watchlist:
                    print(json.dumps(watchlist, indent=2))

            if args.watchlist_name_search:
                watchlists = get_watchlists_like_name(cb, args.watchlist_name_search)
                if watchlists:
                    if args.json:
                        print(json.dumps(watchlists, indent=2))
                    else:
                        for wl in watchlists:
                            print(Watchlist(cb, initial_data=wl))
                            print()

            if args.get_watchlist_report:
                if args.json:
                    print(json.dumps(get_report_with_IOC_status(cb, args.get_watchlist_report), indent=2))
                else:
                    report = get_report_with_IOC_status(cb, args.get_watchlist_report)
                    if report:
                        print_report(report)  # specifically helpful with query based IOCs

            if args.delete_watchlist_report:
                result = delete_report(cb, args.delete_watchlist_report)
                if result.status_code == 204:
                    LOGGER.info("deleted watchlist report")

            if args.update_ioc_query:
                report_id, ioc_id = args.update_ioc_query.split("/", 1)
                updated_report = interactively_update_report_ioc_query(cb, report_id, ioc_id)
                if updated_report:
                    LOGGER.info(f"Query IOC ID={ioc_id} of report ID={report_id} successfully updated.")

            if args.get_ioc_status:
                report_id, ioc_id = args.get_ioc_status.split("/", 1)
                status = is_ioc_ignored(cb, report_id, ioc_id, check_existence=True)
                if status is None:
                    return False
                status = "IGNORED" if status else "ACTIVE"
                print(f"IOC ID={ioc_id} in Report ID={report_id} is {status}")

            if args.ignore_ioc:
                report_id, ioc_id = args.ignore_ioc.split("/", 1)
                status = ignore_ioc(cb, report_id, ioc_id)
                status = "IGNORED" if status else "ACTIVE"
                print(f"IOC ID={ioc_id} in Report ID={report_id} is {status}")

            if args.activate_ioc:
                report_id, ioc_id = args.activate_ioc.split("/", 1)
                status = activate_ioc(cb, report_id, ioc_id)
                status = "ACTIVE" if status else "IGNORED"
                print(f"IOC ID={ioc_id} in Report ID={report_id} is {status}")

        if args.intel_command == "feeds":
            if args.list_feeds:
                feeds = get_all_feeds(cb)
                if not feeds:
                    return None
                if args.json:
                    print(json.dumps(feeds, indent=2))
                else:
                    for f in feeds:
                        print(Feed(cb, initial_data=f))
                        print()
            if args.get_feed:
                feed = get_feed(cb, args.get_feed)
                if not feed:
                    return None
                if args.json:
                    print(json.dumps(feed, indent=2))
                else:
                    print(Feed(cb, initial_data=feed))

            if args.search_for_feed:
                feeds = search_feed_names(cb, args.search_for_feed)
                if not feeds:
                    return None
                if args.json:
                    print(json.dumps(feeds, indent=2))
                else:
                    for f in feeds:
                        print(Feed(cb, initial_data=f))
                        print()

            if args.get_feed_report:
                try:
                    feed_id, report_id = args.get_feed_report.split("/", 1)
                except ValueError:
                    feed_id, report_id = args.get_feed_report.split("-", 1)
                report = get_feed_report(cb, feed_id, report_id)
                print(json.dumps(report, indent=2))

        return True

    # Device Querying #
    if args.command and args.command.startswith("d"):
        LOGGER.info(f"searching {args.environment} environment for device query: {args.device_query}...")
        if args.device_query.upper() == "FIELDS":
            device_meta_file = os.path.join(os.path.dirname(cbc_sdk_file_path), "platform/models/device.yaml")
            model_data = {}
            with open(device_meta_file, "r") as fp:
                model_data = yaml.safe_load(fp.read())
            print("Device model fields:")
            for field_name in list(model_data["properties"].keys()):
                print(f"\t{field_name}")
            return True

        if args.quarantine and args.un_quarantine:
            LOGGER.error("quarantine AND un-quarantine? 🤨 Won't do it.")
            return False

        if args.export:
            # NOTE: TODO: update device search functionality to use the new direct api method and
            LOGGER.info(f"attempting to export devices resulting from query: {args.device_query}")

            devices = [device for device in yield_devices(cb, query=args.device_query)]
            if not devices:
                LOGGER.warning("No devices returned.")
                return devices
            print(json.dumps(devices))
            return True

        devices = make_device_query(cb, args.device_query)
        if not devices:
            return None

        # Quarantine?
        if args.quarantine:
            toggle_device_quarantine(cb, devices, True)
        elif args.un_quarantine:
            toggle_device_quarantine(cb, devices, False)

        # don't display large results by default
        print_results = True
        if not args.no_warnings and len(devices) > 10:
            prompt = "Print all results? (y/n) [y] "
            print_results = input_with_timeout(prompt, default="y")
            print_results = True if print_results.lower() == "y" else False

        if len(devices) > 0 and print_results:
            print("\n------------------------- ENTERPRISE EDR DEVICE RESULTS -------------------------")
            for device in devices:
                if args.all_details:
                    print()
                    print(device)
                # elif args.json:
                #    print(json.dumps(device._info, indent=2))
                else:
                    print(device_info(device))
            print()
        return True

    # Process Querying #
    if args.command and (args.command.startswith("q") or args.command == "pq"):
        LOGGER.info(f"searching {args.environment} environment..")

        # format datetimes as needed
        format_string = "%Y-%m-%d %H:%M:%S"
        if args.start_time and "T" in args.start_time or args.last_time and "T" in args.last_time:
            format_string = "%Y-%m-%dT%H:%M:%S"
        args.start_time = (
            datetime.datetime.strptime(args.start_time, format_string) if args.start_time else args.start_time
        )
        args.last_time = datetime.datetime.strptime(args.last_time, format_string) if args.last_time else args.last_time
        processes = make_process_query(
            cb,
            args.query,
            fields=[
                "*",
                "device_os",
                "device_external_ip",
                "device_internal_ip",
                "parent_hash",
                "parent_name",
                "process_reputation",
                "process_start_time",
                "process_cmdline",
                "parent_guid",
            ],
            start_time=args.start_time,
            last_time=args.last_time,
            raise_exceptions=True,
            validate_query=True,
        )

        if args.facets:
            LOGGER.info("getting facet data...")
            # print_facet_histogram(processes) - unvailable with CBC SDK
            # NOTE TODO - pick this v2 back up and see if it's more efficient to use
            # knowing we have to remember the childproc_name facet data we like.
            from cbinterface.enterprise_edr.query import print_facet_histogram_v2

            print_facet_histogram_v2(cb, args.query, args.start_time, args.last_time)

        # don't display large results by default
        print_results = True
        if not args.no_warnings and len(processes) > 10:
            prompt = "Print all results? (y/n) [y] "
            print_results = input_with_timeout(prompt, default="y")
            print_results = True if print_results.lower() == "y" else False

        if len(processes) > 0 and print_results:
            print("\n------------------------- QUERY RESULTS -------------------------")
            for proc in processes:
                print("  -------------------------")
                if args.all_details:
                    print(proc)
                else:
                    print_process_info(proc, raw_print=args.all_details, header=False)

        return True

    # Enumerations #
    if args.command and args.command in ["enumerate", "e"]:
        if args.logon_history:
            logon_history(cb, args.logon_history)
            return

    # Process Inspection #
    if args.command and (args.command == "proc" or args.command.startswith("i")):
        process_id = args.process_guid_options
        if not is_eedr_guid(process_id):
            # check to see if the analyst passed a local file path, which we assume is a local process json file
            # if os.path.exists(args.process_guid_options):
            # XXX NOTE: create functionality sourced from process json file?
            LOGGER.error(f"{process_id} is not in the form of a CB Cloud process guid.")
            return False

        try:
            proc = make_process_query(
                cb,
                f"process_guid:{process_id}",
                fields=[
                    "*",
                    "device_os",
                    "device_external_ip",
                    "device_internal_ip",
                    "parent_hash",
                    "parent_name",
                    "process_reputation",
                    "process_start_time",
                    "process_cmdline",
                    "process_terminated",
                ],
                raise_exceptions=True,
                validate_query=False,
                silent=True,
            ).first()
            if not proc:
                LOGGER.warning(f"Process data does not exist for GUID={process_id}")
                return False
        except Exception as e:
            LOGGER.error(f"unexpected problem finding process: {e}")
            return False

        # format datetimes as needed
        format_string = "%Y-%m-%d %H:%M:%S"
        if args.start_time and "T" in args.start_time or args.end_time and "T" in args.end_time:
            format_string = "%Y-%m-%dT%H:%M:%S"
        args.start_time = (
            datetime.datetime.strptime(args.start_time, format_string).replace(tzinfo=tz.gettz("GMT"))
            if args.start_time
            else args.start_time
        )
        args.end_time = (
            datetime.datetime.strptime(args.end_time, format_string).replace(tzinfo=tz.gettz("GMT"))
            if args.end_time
            else args.end_time
        )

        if args.event_search:
            for event in yield_events(
                proc, query=args.event_search, start_time=args.start_time, end_time=args.end_time
            ):
                if args.raw_print_events:
                    print(json.dumps(event, default=str, indent=2, sort_keys=True))
                else:
                    print(format_event_data(event))
            return True

        if args.json:
            print(
                json.dumps(
                    process_to_dict(proc, start_time=args.start_time, end_time=args.end_time, event_rows=2000),
                    default=str,
                )
            )
            return

        all_inspection_args = [iarg for iarg in vars(args).keys() if iarg.startswith("inspect_")]
        set_inspection_args = [
            iarg for iarg, value in vars(args).items() if iarg.startswith("inspect_") and value is True
        ]
        if not set_inspection_args:
            LOGGER.debug("seting all inspection arguments.")
            for iarg in all_inspection_args:
                args.__setattr__(iarg, True)

        if args.walk_and_inspect_tree:
            inspect_process_tree(
                proc,
                info=args.inspect_proc_info,
                filemods=args.inspect_filemods,
                netconns=args.inspect_netconns,
                regmods=args.inspect_regmods,
                modloads=args.inspect_modloads,
                crossprocs=args.inspect_crossprocs,
                children=args.inspect_children,
                scriptloads=args.inspect_scriptloads,
                raw_print=args.raw_print_events,
                start_time=args.start_time,
                end_time=args.end_time,
            )
            return True

        if args.inspect_process_ancestry:
            print_ancestry(proc)
            print()
        if args.inspect_process_tree:
            print_process_tree(proc, start_time=args.start_time, end_time=args.end_time)
            print()
        if args.inspect_proc_info:
            print_process_info(proc, raw_print=args.raw_print_events)
        if args.inspect_filemods:
            print_filemods(proc, raw_print=args.raw_print_events, start_time=args.start_time, end_time=args.end_time)
        if args.inspect_netconns:
            print_netconns(proc, raw_print=args.raw_print_events, start_time=args.start_time, end_time=args.end_time)
        if args.inspect_regmods:
            print_regmods(proc, raw_print=args.raw_print_events, start_time=args.start_time, end_time=args.end_time)
        if args.inspect_modloads:
            print_modloads(proc, raw_print=args.raw_print_events, start_time=args.start_time, end_time=args.end_time)
        if args.inspect_crossprocs:
            print_crossprocs(proc, raw_print=args.raw_print_events, start_time=args.start_time, end_time=args.end_time)
        if args.inspect_children:
            print_childprocs(proc, raw_print=args.raw_print_events, start_time=args.start_time, end_time=args.end_time)
        if args.inspect_scriptloads:
            print_scriptloads(proc, raw_print=args.raw_print_events, start_time=args.start_time, end_time=args.end_time)

        return True

    # Live Response Actions #
    if args.command and (args.command.lower() == "lr" or args.command.lower().startswith("live")):
        # create a LR session manager
        session_manager = CustomLiveResponseSessionManager(cb)
        # store a list of commands to execute on this device
        commands = []

        LOGGER.info("searching for device...")
        device = None
        try:  # if device.id
            device = Device(cb, args.name_or_id)
        except ObjectNotFoundError:
            device = find_device_by_hostname(cb, args.name_or_id)

        if not device:
            LOGGER.info("could not find a device.")
            return None

        if args.execute_command:
            for c in args.execute_command:
                cmd = GetFile(c.split()[-1]) if c.startswith("collect -f") else ExecuteCommand(c)
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

        # Quarantine?
        if args.quarantine:
            if toggle_device_quarantine(cb, [device], True):
                LOGGER.info(f"Device {device.id}:{device.name} is set to quarantine.")
        elif args.un_quarantine:
            if toggle_device_quarantine(cb, [device], False):
                LOGGER.info(f"Device {device.id}:{device.name} is set to NOT quarantine.")

        # Put File #
        if args.live_response_command and args.live_response_command.lower() == "put":
            cmd = PutFile(args.local_filepath, args.sensor_write_filepath)
            commands.append(cmd)
            LOGGER.info(f"recorded command: {cmd}")

        if args.create_regkey:
            cmd = CreateRegKey(args.create_regkey)
            commands.append(cmd)
            LOGGER.info(f"recorded command: {cmd}")
            if args.set_regkey_value:
                cmd = SetRegKeyValue(args.create_regkey, args.set_regkey_value)
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

        # Sensor Collection #
        if args.live_response_command and args.live_response_command.lower() == "collect":
            if args.sensor_info:
                print(sensor_info(sensor))

            if args.process_list:
                cmd = ProcessListing()
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

            if args.list_directory:
                cmd = ListDirectory(args.list_directory)
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

            if args.walk_directory:
                cmd = WalkDirectory(args.walk_directory)
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

            if args.file:
                cmd = GetFile(args.file)
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

            if args.regkeypath:
                cmd = ListRegKeyValues(args.regkeypath)
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

            if args.regkeyvalue:
                cmd = RegKeyValue(args.regkeyvalue)
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

            if args.drives:
                cmd = LogicalDrives()
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

            if args.memdump:
                cmd = GetSystemMemoryDump()
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

        # Sensor Remediation #
        if args.live_response_command and args.live_response_command == "remediate":
            if args.delete_file_path:
                cmd = DeleteFile(args.delete_file_path)
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

            if args.kill_process_name:
                cmd = KillProcessByName(args.kill_process_name)
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

            if args.delete_regkeyvalue:
                cmd = DeleteRegistryKeyValue(args.delete_regkeyvalue)
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

            if args.delete_entire_regkey:
                cmd = DeleteRegistryKey(args.delete_entire_regkey)
                commands.append(cmd)
                LOGGER.info(f"recorded command: {cmd}")

            if args.remediation_script:
                remediation_commands = build_remediation_commands(args.remediation_script)
                LOGGER.info(f"created {len(remediation_commands)} remediation commands from {args.remediation_script}")
                commands.extend(remediation_commands)

        # Playbook execution #
        if args.live_response_command and (
            args.live_response_command.startswith("play") or args.live_response_command == "pb"
        ):
            if args.playbook_configpath:
                playbook_commands = build_playbook_commands(args.playbook_configpath)
                commands.extend(playbook_commands)
                LOGGER.info(f"loaded {len(playbook_commands)} playbook commands.")
            if args.playbook_name:
                playbook_data = get_playbook_map()[args.playbook_name]
                playbook_path = playbook_data["path"]
                playbook_commands = build_playbook_commands(playbook_path)
                commands.extend(playbook_commands)
                LOGGER.info(f"loaded {len(playbook_commands)} playbook commands.")

        # Handle LR commands #
        if commands:
            timeout = 900  # default 15 minutes (same used by Cb)
            if not is_device_online(device):
                # Decision point: if the device is NOT online, give the analyst and option to wait
                LOGGER.warning(f"{device.id}:{device.name} is offline.")
                prompt = "Would you like to wait for the host to come online? (y/n) [y] "
                wait = input_with_timeout(prompt, default="y")
                wait = True if wait.lower() == "y" else False
                if not wait:
                    return None
                prompt = "How many days do you want to wait? [Default is 7 days] "
                timeout = input_with_timeout(prompt, default=7)
                if isinstance(timeout, str):
                    timeout = int(timeout)
                if timeout > 30:
                    LOGGER.warning(f"{timeout} days is a long time. Restricting to max of 30 days.")
                    timeout = 30

                # 86400 seconds in a day
                timeout = timeout * 86400

            if not session_manager.wait_for_active_session(device, timeout=timeout):
                LOGGER.error("reached timeout waiting for active session.")
                return False

            # we have an active session, issue the commands.
            for command in commands:
                session_manager.submit_command(command, device)

        if session_manager.commands:
            # Wait for issued commands to complete and process any results.
            session_manager.process_completed_commands()

    # Direct Session Interaction #
    if args.command and args.command.startswith("sess"):
        cblr = CBCloudAPI(url=cb.credentials.url,  org_key=cb.credentials.org_key)

        # if args.list_all_sessions:
        # Not implemented with Enterprise EDR
        # if args.list_sensor_sessions:
        # Not implemented with Enterprise EDR

        if args.get_session_command_list:
            print(json.dumps(get_session_commands(cblr, args.get_session_command_list), indent=2, sort_keys=True))

        if args.get_session:
            print(json.dumps(get_session_by_id(cblr, args.get_session), indent=2, sort_keys=True))

        if args.close_session:
            close_session_res = close_session_by_id(cblr, args.close_session)
            if close_session_res.status_code == 204:
                print("Session has been closed.")
            else:
                print(f"Error closing session: {close_session_res.status_code} {close_session_res.text}")

        if args.get_command_result:
            session_id, device_id, command_id = args.get_command_result.split(":", 2)
            session_id = f"{session_id}:{device_id}"
            print(json.dumps(get_command_result(cblr, session_id, command_id), indent=2, sort_keys=True))

        if args.get_file_content:
            session_id, device_id, file_id = args.get_file_content.split(":", 2)
            session_id = f"{session_id}:{device_id}"
            get_file_content(cblr, session_id, file_id)
