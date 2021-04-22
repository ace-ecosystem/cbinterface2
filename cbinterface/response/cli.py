import sys
import re
import argparse
import datetime
import logging
import json
import time

from cbapi.response import CbResponseAPI, Process, Sensor
from cbapi.errors import ObjectNotFoundError

from cbinterface.helpers import is_uuid, clean_exit, input_with_timeout
from cbinterface.response.query import make_process_query, print_facet_histogram
from cbinterface.response.sensor import is_sensor_online, find_sensor_by_hostname, make_sensor_query, sensor_info
from cbinterface.response.watchlists import get_all_watchlists, query_watchlists, these_watchlists_to_list_dict
from cbinterface.response.process import (
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
from cbinterface.response.sessions import (
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
from cbinterface.response.enumerations import logon_history
from cbinterface.config import get_playbook_map
from cbinterface.scripted_live_response import build_playbook_commands, build_remediation_commands

LOGGER = logging.getLogger("cbinterface.response.cli")


def add_response_arguments_to_parser(subparsers: argparse.ArgumentParser) -> None:
    """Given an argument parser subparser, build a response specific parser."""
    # sensor query parser
    parser_sensor = subparsers.add_parser(
        "sensor-query",
        aliases=["sq"],
        help="Execute a sensor query (Response). Valid search fields: 'ip', 'hostname', and 'groupid'",
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

    # response watchlist parser
    parser_watchlist = subparsers.add_parser(
        "response_watchlist", aliases=["rwl"], help="Work with response watchlists."
    )
    parser_watchlist.add_argument("-l", "--list-watchlists", action="store_true", help="Print all watchlists.")
    parser_watchlist.add_argument(
        "-q", "--query-watchlists", action="store", help="filter watchlists by watchlist query"
    )
    parser_watchlist.add_argument(
        "-json",
        "--watchlists-to-json",
        action="store_true",
        help="Convert watchlists to json and print to stdout.",
    )
    parser_watchlist.add_argument(
        "--watchlist-names-from-stdin", action="store_true", help="read a list of watchlist names from stdin to load."
    )


def execute_response_arguments(cb: CbResponseAPI, args: argparse.Namespace) -> bool:
    """The logic to execute response specific command line arguments.

    Args:
        cb: CbResponseAPI
        args: parsed argparse namespace
    Returns:
        True or None on success, False on failure.
    """

    if not isinstance(cb, CbResponseAPI):
        LOGGER.critical(f"expected CbResponseAPI but got '{type(cb)}'")
        return False

    # Sensor Quering #
    if args.command and (args.command == "sensor-query" or args.command == "sq"):
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

    # Watchlists #
    if args.command and (args.command == "response_watchlist" or args.command == "rwl"):
        watchlists = watchlist_names = []
        if args.query_watchlists:
            watchlists = query_watchlists(cb, args.query_watchlists)
        elif args.list_watchlists:
            watchlists = get_all_watchlists(cb)

        if args.watchlist_names_from_stdin:
            watchlist_names = [line.strip() for line in sys.stdin]

        if args.watchlists_to_json:
            if watchlists:
                print(json.dumps(these_watchlists_to_list_dict(cb, [wl.name for wl in watchlists])))
            if watchlist_names:
                print(json.dumps(these_watchlists_to_list_dict(cb, watchlist_names)))
            return
        elif len(watchlists) > 0:
            print("\n------------------------- WATCHLISTS -------------------------")
            for wl in watchlists:
                print(wl)

    # Process Quering #
    if args.command and (args.command.startswith("q") or args.command == "pq"):
        LOGGER.info(f"searching {args.environment} environment..")
        args.start_time = (
            datetime.datetime.strptime(args.start_time, "%Y-%m-%d %H:%M:%S") if args.start_time else args.start_time
        )
        args.last_time = (
            datetime.datetime.strptime(args.last_time, "%Y-%m-%d %H:%M:%S") if args.last_time else args.last_time
        )
        processes = make_process_query(
            cb, args.query, start_time=args.start_time, last_time=args.last_time, raise_exceptions=False
        )

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

    # Enumerations #
    if args.command and args.command == "enumerate":
        if args.logon_history:
            logon_history(cb, args.logon_history)
            return

    # Process Inspection #
    if args.command and (args.command.lower() == "inspect" or args.command.lower().startswith("proc")):
        process_id = args.process_guid_options
        process_segment = None
        if "/" in args.process_guid_options:
            if not args.process_guid_options.count("/") == 1:
                LOGGER.error(f"process guid/segement format error: {args.process_guid_options}")
                return False
            process_id, process_segment = args.process_guid_options.split("/")
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
            print(json.dumps(process_to_dict(proc, max_segments=args.segment_limit), default=str))
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
            sensor = Sensor(cb, args.name_or_id, force_init=True)
        except ObjectNotFoundError:
            LOGGER.info(f"searching for sensor...")
            sensor = find_sensor_by_hostname(cb, args.name_or_id)

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
    if args.command and args.command.startswith("sess"):
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

    return True
