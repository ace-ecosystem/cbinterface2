# PYTHON_ARGCOMPLETE_OK

import os
import re

# import sys
import time
import argparse
import argcomplete
import logging
import coloredlogs
import datetime
import json
import signal
import yaml

import cbapi.auth
from cbapi.psc.threathunter import CbThreatHunterAPI
from cbapi.response import CbResponseAPI
from cbapi.errors import ConnectionError, UnauthorizedError, ServerError

from cbinterface.helpers import is_uuid, clean_exit, input_with_timeout
from cbinterface.config import (
    set_timezone,
    save_configuration,
    get_default_cbapi_product,
    get_default_cbapi_profile,
    set_default_cbapi_profile,
    set_default_cbapi_product,
)

from cbinterface.response.cli import add_response_arguments_to_parser, execute_response_arguments
from cbinterface.psc.cli import add_psc_arguments_to_parser, execute_threathunter_arguments

LOGGER = logging.getLogger("cbinterface.cli")


def main():
    """Main entry point for cbinterface."""

    # configure logging #
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - [%(levelname)s] %(message)s")
    coloredlogs.install(level="INFO", logger=logging.getLogger())

    # set clean exit signal
    signal.signal(signal.SIGINT, clean_exit)

    # load carbonblack environment profiles #

    # set custom attributes
    default_profile = cbapi.auth.default_profile
    default_profile['lr_token'] = None # needed for psc

    # locate configured environments
    supported_products = ["response", "psc"]
    environments = []
    configured_products = {}
    for product in supported_products:
        configured_products[product] = False
        for profile in cbapi.auth.FileCredentialStore(product).get_profiles():
            configured_products[product] = True
            environments.append(f"{product}:{profile}")

    # chose the default environment
    default_product_name = get_default_cbapi_product()
    default_profile_name = get_default_cbapi_profile()
    default_environments = [env for env in environments if env.startswith(default_product_name)]
    default_environment = f"{default_product_name}:{default_profile_name}"
    default_environment = (
        default_environment if default_environments and default_environment in default_environments else environments[0]
    )

    parser = argparse.ArgumentParser(description="Interface to Carbon Black for IDR teams.")
    parser.add_argument("-d", "--debug", action="store_true", help="Turn on debug logging.")
    parser.add_argument(
        "-e",
        "--environment",
        action="store",
        choices=environments,
        default=default_environment,
        help=f"specify an environment to work with. Default={default_environment}",
    )
    parser.add_argument(
        "-sde",
        "--set-default-environment",
        action="store",
        choices=environments,
        help="configure your default Cb environment",
    )
    parser.add_argument(
        "-tz",
        "--time-zone",
        action="store",
        help='specify the timezone to override defaults. ex. "US/Eastern" or "Europe/Rome"',
    )
    parser.add_argument(
        "--set-default-timezone",
        action="store",
        help='configure your default timezone. ex. "US/Eastern" or "Europe/Rome"',
    )

    subparsers = parser.add_subparsers(dest="command")

    # query parser
    parser_query = subparsers.add_parser(
        "query", aliases=["pq", "q"], help="execute a process search query. 'query -h' for more"
    )
    parser_query.add_argument("query", help="the process search query you'd like to execute")
    parser_query.add_argument(
        "-s",
        "--start-time",
        action="store",
        help="Start time of the process.  Format:'Y-m-d H:M:S' UTC",
    )
    parser_query.add_argument(
        "-e",
        "--last-time",
        action="store",
        help="Narrow to processes with start times BEFORE this end/last time. Format:'Y-m-d H:M:S' UTC",
    )
    parser_query.add_argument(
        "-nw",
        "--no-warnings",
        action="store_true",
        default=False,
        help="Don't warn before printing large query results",
    )
    parser_query.add_argument(
        "-ad",
        "--all-details",
        action="store_true",
        default=False,
        help="Print all available process info (all fields).",
    )
    parser_query.add_argument(
        "--facets", action="store_true", default=None, help="Retrieve statistical facets for this query."
    )

    # process inspection/investigation parser
    parser_inspect = subparsers.add_parser(
        "investigate", aliases=["proc", "i"], help="Investigate process events and metadata."
    )
    parser_inspect.add_argument(
        "process_guid_options", help="the process GUID/segment to inspect. Segment is optional."
    )
    parser_inspect.add_argument(
        "-i", "--proc-info", dest="inspect_proc_info", action="store_true", help="show binary and process information"
    )
    parser_inspect.add_argument(
        "-w",
        "--walk-tree",
        dest="walk_and_inspect_tree",
        action="store_true",
        help="Recursively walk, print, and inspect the process tree. Specified arguments (ex. filemods) applied at every process in tree. WARNING: can pull large datasets.",
    )
    parser_inspect.add_argument(
        "-t",
        "--process-tree",
        dest="inspect_process_tree",
        action="store_true",
        help="print the process tree with this process as the root.",
    )
    parser_inspect.add_argument(
        "-a",
        "--process-ancestry",
        dest="inspect_process_ancestry",
        action="store_true",
        help="print the the process ancestry",
    )
    parser_inspect.add_argument(
        "-c",
        "--show-children",
        dest="inspect_children",
        action="store_true",
        help="only print process children event details",
    )
    parser_inspect.add_argument(
        "-nc", "--netconns", dest="inspect_netconns", action="store_true", help="print network connections"
    )
    parser_inspect.add_argument(
        "-fm", "--filemods", dest="inspect_filemods", action="store_true", help="print file modifications"
    )
    parser_inspect.add_argument(
        "-rm", "--regmods", dest="inspect_regmods", action="store_true", help="print registry modifications"
    )
    parser_inspect.add_argument(
        "-ml", "--modloads", dest="inspect_modloads", action="store_true", help="print modloads"
    )
    parser_inspect.add_argument(
        "-sl", "--scriptloads", dest="inspect_scriptloads", action="store_true", help="print scriptloads (PSC)"
    )
    parser_inspect.add_argument(
        "-cp", "--crossprocs", dest="inspect_crossprocs", action="store_true", help="print crossprocs"
    )
    parser_inspect.add_argument(
        "-rpe",
        "--raw-print-events",
        action="store_true",
        default=False,
        help="do not format Cb events onto a single line. Print them the way Cb does by default.",
    )
    # parser_inspect.add_argument('-warn', '--give-warnings', action='store_true', default=False,
    #                         help="Warn before printing large datasets/results")
    parser_inspect.add_argument(
        "--json", action="store_true", help="Combine all results into json document and print the result."
    )
    parser_inspect.add_argument(
        "--segment-limit",
        action="store",
        type=int,
        default=None,
        help="stop processing events into json after this many process segments",
    )

    # live response parser
    parser_lr = subparsers.add_parser(
        "live-response", aliases=["lr"], help="perform live response actions on a sensor."
    )
    parser_lr.add_argument("hostname_or_sensor_id", help="the hostname or sensor_id to go live with.")
    parser_lr.add_argument(
        "-e", "--execute-command", action="store", help="Execute this command on the sensor. NOTE: waits for output."
    )
    parser_lr.add_argument("-cr", "--create-regkey", action="store", help="Create this regkey.")
    parser_lr.add_argument("-sr", "--set-regkey-value", action="append", help="Set this regkey value.")
    if configured_products["response"]:
        parser_lr.add_argument(
            "-i",
            "--sensor-isolation-toggle",
            action="store_true",
            help="Sensor hostname/ID to isolation/unisolate (on/off). (CB Response)",
        )
    if configured_products["psc"]:
        parser_lr.add_argument(
            "-q",
            "--quarantine",
            action="store_true",
            default=False,
            help="Quarantine the devices returned by the query. (PSC)",
        )
        parser_lr.add_argument(
            "-uq",
            "--un_quarantine",
            action="store_true",
            default=False,
            help="UN-Quarantine the devices returned by the query. (PSC)",
        )

    # live response subparser
    lr_subparsers = parser_lr.add_subparsers(dest="live_response_command")

    # live response put file parser
    parser_put_file = lr_subparsers.add_parser("put", help="put a file on the sensor")
    parser_put_file.add_argument("local_filepath", action="store", help="Path to the file.")
    parser_put_file.add_argument("sensor_write_filepath", action="store", help="Path to write the file on the sensor.")

    # live response collect parser
    parser_collect = lr_subparsers.add_parser("collect", help="collect artifacts from hosts")
    parser_collect.add_argument(
        "-i", "--sensor-info", dest="sensor_info", action="store_true", help="print default sensor information"
    )
    parser_collect.add_argument("-p", "--process-list", action="store_true", help="show processes running on sensor")
    parser_collect.add_argument("-f", "--file", action="store", help="collect file at this path on sensor")
    parser_collect.add_argument(
        "-lr", "--regkeypath", action="store", help="List all registry values from the specified registry key."
    )
    parser_collect.add_argument(
        "-r", "--regkeyvalue", action="store", help="Returns the associated value of the specified registry key."
    )
    parser_collect.add_argument(
        "-ld", "--list-directory", action="store", help="List the contents of a directory on the sensor."
    )
    parser_collect.add_argument(
        "-wd", "--walk-directory", action="store", help="List the contents of a directory on the sensor."
    )
    parser_collect.add_argument("--drives", action="store_true", help="Get logical drives on this sensor.")
    parser_collect.add_argument(
        "--memdump", action="store_true", help="Use Cb to dump sensor memory and collect the memdump."
    )

    # live response remediation parser
    parser_remediate = lr_subparsers.add_parser("remediate", help="remdiation (delete/kill) actions")
    parser_remediate.add_argument(
        "-f", "--delete-file-path", action="store", help="delete the file at this path on the sensor"
    )
    parser_remediate.add_argument(
        "-kpname", "--kill-process-name", action="store", help="kill all processes with this name"
    )
    parser_remediate.add_argument("-kpid", "--kill-process-id", action="store", help="kill the process with this ID")
    parser_remediate.add_argument("-drv", "--delete-regkeyvalue", action="store", help="Delete the regkey value.")
    parser_remediate.add_argument(
        "--delete-entire-regkey", action="store", help="Delete the registry key and all values. BE CAREFUL."
    )

    # session parser - XXX
    parser_session = subparsers.add_parser("session", aliases=["s"], help="get session data")
    parser_session.add_argument(
        "-lss", "--list-sensor-sessions", action="store", help="list all CbLR sessions associated to this sensor ID."
    )
    parser_session.add_argument(
        "-gsc", "--get-session-command-list", action="store", help="list commands associated to this session"
    )
    parser_session.add_argument("-a", "--list-all-sessions", action="store_true", help="list all CbLR sessions.")
    parser_session.add_argument("-g", "--get-session", action="store", help="get live response session by id.")
    parser_session.add_argument("-c", "--close-session", action="store", help="close live response session by id.")
    parser_session.add_argument(
        "-gcr", "--get-command-result", action="store", help="get any results for this command."
    )
    parser_session.add_argument(
        "-f", "--get-file-content", action="store", help="byte stream any file content to stdout. (use a pipe)"
    )

    # only add independent product args if product is a configured option
    if configured_products["response"]:
        add_response_arguments_to_parser(subparsers)
    if configured_products["psc"]:
        add_psc_arguments_to_parser(subparsers)

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    """
    XXX: Create a SINGLE background daemon service that can be launched to track and manage jobs?
    """

    if args.debug:
        logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO)
        coloredlogs.install(level="DEBUG", logger=logging.getLogger())

    if args.time_zone:
        set_timezone(args.time_zone)

    if args.set_default_timezone:
        set_timezone(args.set_default_timezone)
        save_configuration()

    if args.set_default_environment:
        product, profile = args.set_default_environment.split(":", 1)
        set_default_cbapi_product(product)
        set_default_cbapi_profile(profile)
        save_configuration()

    # XXX create custom wrapper that will catch timeout errors?
    # catch this raise cbapi/connection.py#L266
    # and log an critical error instead of barffing on the terminal.
    # ALSO catch: cbapi.errors.ServerError: Received error code 504 from API
    product, profile = args.environment.split(":", 1)
    try:
        if product == "response":
            cb = CbResponseAPI(profile=profile)
            execute_response_arguments(cb, args)

        elif product == "psc":
            cb = CbThreatHunterAPI(profile=profile)
            execute_threathunter_arguments(cb, args)
    except ConnectionError as e:
        LOGGER.critical(f"Couldn't connect to {product} {profile}: {e}")
    except UnauthorizedError as e:
        LOGGER.critical(f"{e}")
    except ServerError as e:
        LOGGER.critical(f"CB ServerError: {e}")