import os
import re
import sys
import argparse
import logging
import coloredlogs
import datetime
import json

import cbapi.auth
from cbapi.response import CbResponseAPI, Process
from cbapi.errors import ObjectNotFoundError

from cbinterface2.helpers import is_uuid
from cbinterface2.query import make_process_query, print_facet_histogram
from cbinterface2.process import get_all_events, inspect_process_tree, print_process_info, print_ancestry, print_process_tree, print_filemods, print_netconns, print_regmods, print_modloads, print_crossprocs, print_childprocs

# XXX just copy and pasted
def search_environments_for_process(profiles, proc_guid):
    """Locate CbR environment by process GUID.
    """
    #cbapi does not check for guids and doesn't error correctly
    regex = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
    if regex.match(proc_guid) == None:
        LOGGER.error("{} is not in the format of a process guid".format(proc_guid))
        return False

    #stored_exceptions = []
    for profile in profiles:
        handle_proxy(profile)
        cb = CbResponseAPI(profile=profile)
        try:
            proc = cb.select(Process, proc_guid, force_init=True)
            LOGGER.info("process found in {} environment".format(profile))
            return proc
        except Exception as e:
            #stored_exceptions.append((profile, str(e)))
            pass

    LOGGER.error("Didn't find this process guid in any environments.")
    return False

def main():
    """Main entry point for cbinterface."""

    # configure logging #
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
    coloredlogs.install(level='INFO', logger=logging.getLogger())

    # enumerate some Cb env settings #
    default_product = "response"
    # TODO come back and look at defining custom envtype profile element
    # and loading from os.environ as option
    environments = choices=cbapi.auth.FileCredentialStore(default_product).get_profiles()
    default_environment = 'default' if environments and 'default' in environments else environments[0]

    parser = argparse.ArgumentParser(description="Interface to Carbon Black for IDR teams.")
    parser.add_argument("-d", "--debug", action="store_true", help="Turn on debug logging.")
    parser.add_argument("-e", "--environment", action="store", choices=environments, default=default_environment, help="specify an environment to work with")
    parser.add_argument('-tz', '--time-zone', action='store', help='specify the timezone to override defaults. ex. "US/Eastern" or "Europe/Rome"')

    subparsers = parser.add_subparsers(dest='command')
    
    # query parser
    parser_query = subparsers.add_parser('query',
                                         help="execute a process search query. 'query -h' for more")
    parser_query.add_argument('query', help="the process search query you'd like to execute")
    parser_query.add_argument('-s', '--start-time', action='store',
                              help="Only return processes with events after given date/time stamp\
 (server’s clock). Format:'Y-m-d H:M:S' eastern time")
    parser_query.add_argument('-l', '--last-time', action='store',
                              help="Set the maximum last update time. Format:'Y-m-d H:M:S' eastern time")
    parser_query.add_argument('-nw', '--no-warnings', action='store_true', default=False,
                             help="Don't warn before printing large query results")
    parser_query.add_argument('-ad', '--all-details', action='store_true', default=False,
                             help="Print all available process info (all fields).")
    parser_query.add_argument('-rpe', '--raw-print-events', action='store_true', default=False,
                             help="do not format Cb events onto a single line. Print them the way Cb does by default.")
    parser_query.add_argument('--facets', action='store_true', default=None,
                             help="Retrieve statistical facets for this query.")

    # process inspection parser
    parser_inspect = subparsers.add_parser('inspect', help="Inspect process events and metadata.")
    parser_inspect.add_argument('guid_with_optional_segment', help="the process GUID/segment to inspect. Segment is optional.")
    parser_inspect.add_argument('-i', '--proc-info', dest='inspect_proc_info', action='store_true',
                                help="show binary and process information")
    parser_inspect.add_argument('-w', '--walk-tree', dest='walk_and_inspect_tree', action='store_true',
                             help="Recursively walk, print, and inspect the process tree. Specified arguments (ex. filemods) applied at every process in tree. WARNING: can pull large datasets.")
    parser_inspect.add_argument('-t', '--process-tree', dest='inspect_process_tree', action='store_true',
                             help="print the process tree with this process as the root.")
    parser_inspect.add_argument('-a', '--process-ancestry', dest='inspect_process_ancestry', action='store_true',
                             help="print the the process ancestry")
    parser_inspect.add_argument('-c','--show-children', dest='inspect_children', action='store_true',
                             help="only print process children event details")
    parser_inspect.add_argument('-nc', '--netconns', dest='inspect_netconns', action='store_true',
                             help="print network connections")
    parser_inspect.add_argument('-fm', '--filemods', dest='inspect_filemods', action='store_true',
                             help="print file modifications")
    parser_inspect.add_argument('-rm', '--regmods', dest='inspect_regmods', action='store_true',
                             help="print registry modifications")
    #parser_inspect.add_argument('-um', '--unsigned-modloads', action='store_true',
    #                         help="print unsigned modloads")
    parser_inspect.add_argument('-ml', '--modloads', dest='inspect_modloads', action='store_true',
                             help="print modloads")
    parser_inspect.add_argument('-cp', '--crossprocs', dest='inspect_crossprocs', action='store_true',
                             help="print crossprocs")
    parser_inspect.add_argument('-rpe', '--raw-print-events', action='store_true', default=False,
                                help="do not format Cb events onto a single line. Print them the way Cb does by default.")
    #parser_inspect.add_argument('-na', '--no-analysis', action='store_true', XXX Attempting repalcement with show-process-tree
    #                         help="Don't fetch and print process activity")
    #parser_inspect.add_argument('-warn', '--give-warnings', action='store_true', default=False,
    #                         help="Warn before printing large datasets/results")
    parser_inspect.add_argument('--json', action='store_true', help='Combine all results into json document and print the result.')
    parser_inspect.add_argument('--segment-limit', action='store', type=int, default=None,
                             help='stop processing events into json after this many process segments')

    args = parser.parse_args()

    if args.debug:
        coloredlogs.install(level='DEBUG', logger=logging.getLogger())

    cb = CbResponseAPI(profile=args.environment)

    # Process Quering #
    if args.command.lower() == 'query':
        logging.info(f"searching {args.environment} environment..")
        args.start_time = datetime.datetime.strptime(args.start_time, '%Y-%m-%d %H:%M:%S') if args.start_time else args.start_time
        args.last_time = datetime.datetime.strptime(args.last_time, '%Y-%m-%d %H:%M:%S') if args.last_time else args.last_time
        processes = make_process_query(cb, args.query, start_time=args.start_time, last_time=args.last_time)

        if args.facets:
            logging.info("getting facet data...")
            print_facet_histogram(processes.facets())

        # don't display large results by default - XXX create option to display summary/facet details of results
        print_results = True
        if not args.no_warnings and len(processes) > 10:
            print_results = input("Print all results? (y/n) [y] ") or 'y'
            print_results = True if print_results.lower() == 'y' else False

        if len(processes) > 0 and print_results:
            print("\n------------------------- QUERY RESULTS -------------------------")
            for proc in processes:
                print("\n  -------------------------")
                if args.all_details:
                    print(proc)
                else:
                    print_process_info(proc, raw_print=args.raw_print_events, header=False)
            print()

        return True

    if args.command.lower() == 'inspect':
        process_id = args.guid_with_optional_segment
        process_segment = None
        if '/' in args.guid_with_optional_segment:
            if not args.guid_with_optional_segment.count('/') == 1:
                logging.error(f"process guid/segement format error: {args.guid_with_optional_segment}")
                return False
            process_id, process_segment = args.guid_with_optional_segment.split('/')
            if not re.match('[0-9]{13}', process_segment):
                logging.error(f"{process_segment} is not in the form of a process segment.")
                return False
            process_segment = int(process_segment)
        if not is_uuid(process_id):
            logging.error(f"{process_id} is not in the form of a globally unique process id (GUID/UUID).")
            return False

        try:
            #proc = cb.select(Process, process_id, force_init=True)
            proc = Process(cb, process_id, force_init=True)
            if process_segment and process_segment not in proc.get_segments():
                logging.warning(f"segment '{process_segment}' does not exist. Setting to first segment.")
                process_segment = None
            proc.current_segment = process_segment
        except ObjectNotFoundError:
            logging.warning(f"ObjectNotFoundError - process data does not exist.")
            return False
        except Exception as e:
            logging.error(f"problem finding process: {e}")
            return False

        all_inspection_args = [iarg for iarg in vars(args).keys() if iarg.startswith('inspect_')]
        set_inspection_args = [iarg for iarg, value in vars(args).items() if iarg.startswith('inspect_') and value is True]
        if not set_inspection_args:
            logging.debug(f"seting all inspection arguments.")
            for iarg in all_inspection_args:
                args.__setattr__(iarg, True)

        if args.json:
            results = get_all_events(proc)
            print(json.dumps(results, default=str))
            return

        if args.walk_and_inspect_tree:
            inspect_process_tree(proc, info=args.inspect_proc_info, filemods=args.inspect_filemods, netconns=args.inspect_netconns, regmods=args.inspect_regmods, modloads=args.inspect_modloads, crossprocs=args.inspect_crossprocs, children=args.inspect_children, raw_print=args.raw_print_events)
            return True
        # else
        if args.inspect_process_ancestry:
            print_ancestry(proc)
        if args.inspect_process_tree:
            print_process_tree(proc)
        if args.inspect_proc_info:
            print_process_info(proc, raw_print=args.raw_print_events)
        if args.inspect_filemods:
            print_filemods(proc, current_segment_only=bool(process_segment), raw_print=args.raw_print_events)
        if args.inspect_netconns:
            print_netconns(proc, current_segment_only=bool(process_segment), raw_print=args.raw_print_events)
        if args.inspect_regmods:
            print_regmods(proc, current_segment_only=bool(process_segment), raw_print=args.raw_print_events)
        if args.inspect_modloads:
            print_modloads(proc, current_segment_only=bool(process_segment), raw_print=args.raw_print_events)
        if args.inspect_crossprocs:
            print_crossprocs(proc, current_segment_only=bool(process_segment), raw_print=args.raw_print_events)
        if args.inspect_children:
            print_childprocs(proc, current_segment_only=bool(process_segment), raw_print=args.raw_print_events)