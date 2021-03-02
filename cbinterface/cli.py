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
from cbapi.errors import ConnectionError

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

    # enumerate some Cb env settings #
    # TODO come back and look at defining custom envtype profile element
    # and loading from os.environ as option
    default_product = get_default_cbapi_product()
    default_profile = get_default_cbapi_profile()
    supported_products = ["response", "psc"]
    environments = []
    for product in supported_products:
        for profile in cbapi.auth.FileCredentialStore(product).get_profiles():
            environments.append(f"{product}:{profile}")

    default_environments = [env for env in environments if env.startswith(default_product)]
    default_environment = f"{default_product}:{default_profile}"
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
        "-sl", "--scriptloads", dest="inspect_scriptloads", action="store_true", help="print scriptloads (psc)"
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

    # response parser TODO - append only if response config exists
    add_response_arguments_to_parser(subparsers)
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
