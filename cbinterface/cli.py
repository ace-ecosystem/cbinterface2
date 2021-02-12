# PYTHON_ARGCOMPLETE_OK

import os
import re
import sys
import time
import argparse
import argcomplete
import logging
import coloredlogs
import datetime
import json
import signal

import cbapi.auth
from cbapi.response import CbResponseAPI, Process, Sensor
from cbapi.errors import ObjectNotFoundError

from cbinterface.helpers import is_uuid
from cbinterface.query import make_process_query, print_facet_histogram
from cbinterface.sensor import is_sensor_online, find_sensor_by_hostname, make_sensor_query, sensor_info
from cbinterface.process import (
    process_to_dict,
    inspect_process_tree,
    print_process_info,
    print_ancestry,
    print_process_tree,
    print_filemods,
    print_netconns,
    print_regmods,
    print_modloads,
    print_crossprocs,
    print_childprocs,
)
from cbinterface.sessions import (
    CustomLiveResponseSessionManager,
    get_session_by_id,
    sensor_live_response_sessions_by_sensor_id,
    all_live_response_sessions,
    get_session_commands,
    get_command_result,
    get_file_content,
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

from cbinterface.enumerations import logon_history

LOGGER = logging.getLogger("cbinterface.cli")


def input_with_timeout(prompt, default=None, timeout=30):
    """Wait up to timeout for user input"""

    def _log_and_exit(signum, frame):
        sys.stderr.write("\n")
        LOGGER.error("Timeout reached waiting for input.")
        sys.exit()

    signal.signal(signal.SIGALRM, _log_and_exit)
    signal.alarm(timeout)
    sys.stderr.write(prompt)
    answer = input() or default
    signal.alarm(0)
    return answer


def clean_exit(signal, frame):
    print()
    LOGGER.info(f"caught KeyboardInterrupt. exiting.")
    sys.exit(0)


def main():
    """Main entry point for cbinterface."""

    # configure logging #
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - [%(levelname)s] %(message)s")
    coloredlogs.install(level="INFO", logger=logging.getLogger())

    # set clean exit signal
    signal.signal(signal.SIGINT, clean_exit)

    # enumerate some Cb env settings #
    default_product = "response"
    # TODO come back and look at defining custom envtype profile element
    # and loading from os.environ as option
    environments = choices = cbapi.auth.FileCredentialStore(default_product).get_profiles()
    default_environment = "default" if environments and "default" in environments else environments[0]

    parser = argparse.ArgumentParser(description="Interface to Carbon Black for IDR teams.")
    parser.add_argument("-d", "--debug", action="store_true", help="Turn on debug logging.")
    parser.add_argument(
        "-e",
        "--environment",
        action="store",
        choices=environments,
        default=default_environment,
        help="specify an environment to work with",
    )
    parser.add_argument(
        "-tz",
        "--time-zone",
        action="store",
        help='specify the timezone to override defaults. ex. "US/Eastern" or "Europe/Rome"',
    )

    subparsers = parser.add_subparsers(dest="command")

    # query parser
    parser_query = subparsers.add_parser("query", help="execute a process search query. 'query -h' for more")
    parser_query.add_argument("query", help="the process search query you'd like to execute")
    parser_query.add_argument(
        "-s",
        "--start-time",
        action="store",
        help="Only return processes with events after given date/time stamp\
 (server’s clock). Format:'Y-m-d H:M:S' eastern time",
    )
    parser_query.add_argument(
        "-l", "--last-time", action="store", help="Set the maximum last update time. Format:'Y-m-d H:M:S' eastern time"
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
    # parser_query.add_argument('-rpe', '--raw-print-events', action='store_true', default=False,
    #                         help="do not format Cb events onto a single line. Print them the way Cb does by default.")
    parser_query.add_argument(
        "--facets", action="store_true", default=None, help="Retrieve statistical facets for this query."
    )

    # sensor query
    parser_sensor = subparsers.add_parser(
        "sensor-query", help="Execute a sensor query. Valid search fields: 'ip', 'hostname', and 'groupid'"
    )
    parser_sensor.add_argument("sensor_query", help="the sensor query you'd like to execute")
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

    # process inspection parser
    parser_inspect = subparsers.add_parser("inspect", aliases=["proc"], help="Inspect process events and metadata.")
    parser_inspect.add_argument(
        "guid_with_optional_segment", help="the process GUID/segment to inspect. Segment is optional."
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
    # parser_inspect.add_argument('-um', '--unsigned-modloads', action='store_true',
    #                         help="print unsigned modloads")
    parser_inspect.add_argument(
        "-ml", "--modloads", dest="inspect_modloads", action="store_true", help="print modloads"
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
    parser_lr.add_argument(
        "-i",
        "--sensor-isolation-toggle",
        action="store_true",
        help="Sensor hostname/ID to isolation/unisolate (on/off).",
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

    # session parser
    parser_session = subparsers.add_parser("session", help="get session data")
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

    # enumeration parser
    parser_enumeration = subparsers.add_parser("enumerate", help="get enumeration data")
    parser_enumeration.add_argument(
        "-lh",
        "--logon-history",
        action="store",
        help="given username or hostname, enumerate logon history (Windows OS).",
    )

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    """
    XXX: Create a SINGLE background daemon service that can be launched to track and manage jobs?
    """

    if args.debug:
        coloredlogs.install(level="DEBUG", logger=logging.getLogger())

    # XXX create custom wrapper that will catch timeout errors?
    # catch this raise cbapi/connection.py#L266
    # and log an critical error instead of barffing on the terminal.
    cb = CbResponseAPI(profile=args.environment)

    # Process Quering #
    if args.command and args.command.lower() == "query":
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
            print_facet_histogram(processes.facets())

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

    # Sensor Quering #
    if args.command and args.command.lower() == "sensor-query":
        LOGGER.info(f"searching {args.environment} environment for sensor query: {args.sensor_query}...")
        sensors = make_sensor_query(cb, args.sensor_query)
        if not sensors:
            return None

        # don't display large results by default
        print_results = True
        if not args.no_warnings and len(sensors) > 10:
            prompt = "Print all results? (y/n) [y] "
            print_results = input_with_timeout(prompt, default="y")
            print_results = True if print_results.lower() == "y" else False

        if len(sensors) > 0 and print_results:
            print("\n------------------------- SENSOR RESULTS -------------------------")
            for sensor in sensors:
                if args.all_details:
                    print()
                    print(sensor)
                else:
                    print(sensor_info(sensor))
            print()
        return True

    # Enumerations #
    if args.command and args.command == "enumerate":
        if args.logon_history:
            logon_history(cb, args.logon_history)
            return

    # Process Inspection #
    if args.command and (args.command.lower() == "inspect" or args.command.lower().startswith("proc")):
        process_id = args.guid_with_optional_segment
        process_segment = None
        if "/" in args.guid_with_optional_segment:
            if not args.guid_with_optional_segment.count("/") == 1:
                LOGGER.error(f"process guid/segement format error: {args.guid_with_optional_segment}")
                return False
            process_id, process_segment = args.guid_with_optional_segment.split("/")
            if not re.match("[0-9]{13}", process_segment):
                LOGGER.error(f"{process_segment} is not in the form of a process segment.")
                return False
            process_segment = int(process_segment)
        if not is_uuid(process_id):
            LOGGER.error(f"{process_id} is not in the form of a globally unique process id (GUID/UUID).")
            return False

        try:
            proc = Process(cb, process_id, force_init=True)
            if process_segment and process_segment not in proc.get_segments():
                LOGGER.warning(f"segment '{process_segment}' does not exist. Setting to first segment.")
                process_segment = None
            proc.current_segment = process_segment
        except ObjectNotFoundError:
            LOGGER.warning(f"ObjectNotFoundError - process data does not exist.")
            return False
        except Exception as e:
            LOGGER.error(f"problem finding process: {e}")
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
                raw_print=args.raw_print_events,
            )
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

    # Live Response Actions #
    if args.command and (args.command.lower() == "lr" or args.command.lower().startswith("live")):
        # create a LR session manager
        session_manager = CustomLiveResponseSessionManager(cb, custom_session_keepalive=True)
        # store a list of commands to execute on this sensor
        commands = []

        try:
            sensor = Sensor(cb, args.hostname_or_sensor_id, force_init=True)
        except ObjectNotFoundError:
            LOGGER.info(f"searching for sensor...")
            sensor = find_sensor_by_hostname(cb, args.hostname_or_sensor_id)

        if not sensor:
            LOGGER.info(f"could not find a sensor.")
            return None

        if args.execute_command:
            # XXX expand this for more flexibiliy by making an execute parser
            # that can accept more arugments to pass to ExecuteCommand
            cmd = ExecuteCommand(args.execute_command)
            commands.append(cmd)
            LOGGER.info(f"recorded command: {cmd}")

        if args.sensor_isolation_toggle:
            result = None
            state = "isolated" if sensor.is_isolating else "unisolated"
            desired_state = "unisolated" if sensor.is_isolating else "isolated"
            LOGGER.info(
                f"sensor {sensor.id}:{sensor.hostname} is currently {state}. Changing state to: {desired_state}"
            )
            if sensor.is_isolating:
                result = sensor.unisolate()
            else:
                result = sensor.isolate()
            if result:
                state = "isolated" if sensor.is_isolating else "unisolated"
                LOGGER.info(f"successfully {state} sensor {sensor.id}:{sensor.hostname}")
            else:
                state = "unisolate" if sensor.is_isolating else "isolate"
                LOGGER.error(f"failed to {state} sensor {sensor.id}:{sensor.hostname}")

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

        # Handle LR commands #
        if commands:
            timeout = 1200  # default 20 minutes (same used by Cb)
            if not is_sensor_online(sensor):
                # Decision point: if the sensor is NOT online, give the analyst and option to wait
                LOGGER.warning(f"{sensor.id}:{sensor.hostname} is offline.")
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

            if not session_manager.wait_for_active_session(sensor, timeout=timeout):
                LOGGER.error(f"reached timeout waiting for active session.")
                return False

            # we have an active session, issue the commands.
            for command in commands:
                session_manager.submit_command(command, sensor)

        if session_manager.commands:
            # Wait for issued commands to complete and process any results.
            session_manager.process_completed_commands()

    # Direct Session Interaction #
    if args.command and args.command.lower() == "session":
        if args.list_sensor_sessions:
            print(
                json.dumps(
                    sensor_live_response_sessions_by_sensor_id(cb, args.list_sensor_sessions), indent=2, sort_keys=True
                )
            )

        if args.get_session_command_list:
            print(json.dumps(get_session_commands(cb, args.get_session_command_list), indent=2, sort_keys=True))

        if args.list_all_sessions:
            print(json.dumps(all_live_response_sessions(cb), indent=2, sort_keys=True))

        if args.get_session:
            print(json.dumps(get_session_by_id(cb, args.get_session), indent=2, sort_keys=True))

        if args.close_session:
            session_manager = CustomLiveResponseSessionManager(cb)
            session_manager._close_session(args.close_session)
            print(json.dumps(get_session_by_id(cb, args.close_session), indent=2, sort_keys=True))

        if args.get_command_result:
            session_id, command_id = args.get_command_result.split(":", 1)
            print(json.dumps(get_command_result(cb, session_id, command_id), indent=2, sort_keys=True))

        if args.get_file_content:
            session_id, file_id = args.get_file_content.split(":", 1)
            get_file_content(cb, session_id, file_id)
