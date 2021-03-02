"""PSC Threathunter CLI functions."""

import os
import re
import argparse
import datetime
import logging
import json
import time
import yaml

from cbapi import __file__ as cbapi_file_path
from cbapi.errors import ObjectNotFoundError, MoreThanOneResultError
from cbapi.psc.threathunter import CbThreatHunterAPI, Process
from cbapi.psc.threathunter.query import Query

from cbinterface.helpers import is_psc_guid, clean_exit, input_with_timeout
from cbinterface.psc.query import make_process_query, print_facet_histogram
from cbinterface.psc.device import make_device_query, device_info
from cbinterface.psc.process import (
    select_process,
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
)

LOGGER = logging.getLogger("cbinterface.psc.cli")


def add_psc_arguments_to_parser(subparsers: argparse.ArgumentParser) -> None:
    """Given an argument parser subparser, build a psc specific parser."""
    # device query (psc)
    parser_sensor = subparsers.add_parser("device", aliases=["d"], help="Execute a device query (PSC).")
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


def execute_threathunter_arguments(cb: CbThreatHunterAPI, args: argparse.Namespace) -> bool:
    """The logic to execute psc ThreatHunter specific command line arguments.

    Args:
        cb: CbThreatHunterAPI
        args: parsed argparse namespace
    Returns:
        True or None on success, False on failure.
    """
    if not isinstance(cb, CbThreatHunterAPI):
        LOGGER.critical(f"Requires Cb PSC based API. Got '{product}' API.")
        return False

    # Device Quering #
    if args.command and args.command.startswith("d"):
        LOGGER.info(f"searching {args.environment} environment for device query: {args.device_query}...")
        if args.device_query.upper() == "FIELDS":
            device_meta_file = os.path.join(os.path.dirname(cbapi_file_path), "psc/defense/models/deviceInfo.yaml")
            model_data = {}
            with open(device_meta_file, "r") as fp:
                model_data = yaml.safe_load(fp.read())
            possibly_searchable_props = list(model_data["properties"].keys())
            print("Device model fields:")
            for field_name in list(model_data["properties"].keys()):
                print(f"\t{field_name}")
            return True

        devices = make_device_query(cb, args.device_query)
        if not devices:
            return None

        # don't display large results by default
        print_results = True
        if not args.no_warnings and len(devices) > 10:
            prompt = "Print all results? (y/n) [y] "
            print_results = input_with_timeout(prompt, default="y")
            print_results = True if print_results.lower() == "y" else False

        if len(devices) > 0 and print_results:
            print("\n------------------------- PSC DEVICE RESULTS -------------------------")
            for device in devices:
                if args.all_details:
                    print()
                    print(device)
                else:
                    print(device_info(device))
            print()
        return True

    # Process Quering #
    if args.command and (args.command.startswith("q") or args.command == "pq"):
        LOGGER.info(f"searching {args.environment} environment..")
        args.start_time = (
            datetime.datetime.strptime(args.start_time, "%Y-%m-%d %H:%M:%S") if args.start_time else args.start_time
        )
        args.last_time = (
            datetime.datetime.strptime(args.last_time, "%Y-%m-%d %H:%M:%S") if args.last_time else args.last_time
        )
        processes = make_process_query(cb, args.query, start_time=args.start_time, last_time=args.last_time)

        if args.facets:
            LOGGER.info("getting facet data...")
            print_facet_histogram(processes)

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

    # Process Inspection #
    if args.command and (args.command == "proc" or args.command.startswith("i")):
        process_id = args.process_guid_options
        if not is_psc_guid(process_id):
            # check to see if the analyst passed a local file path, which we assume is a local process json file
            # if os.path.exists(args.process_guid_options):
            # XXX NOTE: create functionality sourced from process json file?
            LOGGER.error(f"{process_id} is not in the form of a CbThreathunter process guid.")
            return False

        try:
            # proc = Process(cb, process_id)
            proc = select_process(cb, process_id)
            if not proc:
                LOGGER.warning(f"Process data does not exist for GUID={process_id}")
                return False
        except Exception as e:
            LOGGER.error(f"unexpected problem finding process: {e}")
            return False

        all_inspection_args = [iarg for iarg in vars(args).keys() if iarg.startswith("inspect_")]
        set_inspection_args = [
            iarg for iarg, value in vars(args).items() if iarg.startswith("inspect_") and value is True
        ]
        if not set_inspection_args:
            LOGGER.debug(f"seting all inspection arguments.")
            for iarg in all_inspection_args:
                args.__setattr__(iarg, True)

        if args.json:
            print(json.dumps(process_to_dict(proc), default=str))
            return

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
            )
            return True

        if args.inspect_process_ancestry:
            print_ancestry(proc)
            print()
        if args.inspect_process_tree:
            print_process_tree(proc)
            print()
        if args.inspect_proc_info:
            print_process_info(proc, raw_print=args.raw_print_events)
        if args.inspect_filemods:
            print_filemods(proc, raw_print=args.raw_print_events)
        if args.inspect_netconns:
            print_netconns(proc, raw_print=args.raw_print_events)
        if args.inspect_regmods:
            print_regmods(proc, raw_print=args.raw_print_events)
        if args.inspect_modloads:
            print_modloads(proc, raw_print=args.raw_print_events)
        if args.inspect_crossprocs:
            print_crossprocs(proc, raw_print=args.raw_print_events)
        if args.inspect_children:
            print_childprocs(proc, raw_print=args.raw_print_events)
        if args.inspect_scriptloads:
            print_scriptloads(proc, raw_print=args.raw_print_events)
