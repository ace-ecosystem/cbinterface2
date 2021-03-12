"""PSC Threathunter CLI functions."""

import os
import re
import argparse
import datetime
import logging
import json
import time
import yaml

from typing import List, Union

from cbapi import __file__ as cbapi_file_path
from cbapi.errors import ObjectNotFoundError, MoreThanOneResultError, ClientError
from cbapi.psc import Device
from cbapi.psc.devices_query import DeviceSearchQuery
from cbapi.psc.threathunter import CbThreatHunterAPI, Process
from cbapi.psc.threathunter.query import Query

from cbinterface.helpers import is_psc_guid, clean_exit, input_with_timeout
from cbinterface.psc.query import make_process_query, print_facet_histogram
from cbinterface.psc.device import (
    make_device_query,
    device_info,
    time_since_checkin,
    find_device_by_hostname,
    is_device_online,
)
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
from cbinterface.psc.sessions import (
    CustomLiveResponseSessionManager,
    get_session_by_id,
    device_live_response_sessions_by_device_id,
    all_live_response_sessions,
    get_session_commands,
    get_command_result,
    get_file_content,
    close_session_by_id,
)
from cbinterface.psc.enumerations import logon_history
from cbinterface.config import get_playbook_map
from cbinterface.scripted_live_response import build_playbook_commands, build_remediation_commands

LOGGER = logging.getLogger("cbinterface.psc.cli")


def toggle_device_quarantine(
    cb: CbThreatHunterAPI, devices: Union[DeviceSearchQuery, List[Device]], quarantine: bool
) -> bool:
    """Toggle device quarantine state.

    Args:
        devices: DeviceSearchQuery
        quarantine: set quarantine if True, else set quarantine to off state.
    """
    if len(devices) > 0:
        if len(devices) > 10 and quarantine:
            LOGGER.error(
                f"For now, not going to quarnantine {len(devices)} devices as a safe gaurd "
                f"to prevent mass device impact... use the GUI if you must."
            )
            return False
        verbiage = "quarantine" if quarantine else "NOT quarantine"
        emotion = "👀" if quarantine else "👏"
        LOGGER.info(f"setting {verbiage} on {len(devices)} devices... {emotion}")

        device_ids = []
        for d in devices:
            if d.quarantined == quarantine:
                LOGGER.warning(f"device {d.id}:{d.name} is already set to {verbiage}.")
                continue
            if not is_device_online(d):
                LOGGER.info(f"device {d.id}:{d.name} hasn't checked in for: {time_since_checkin(d, refresh=False)}")
                LOGGER.warning(f"device {d.id}:{d.name} appears offline 💤")
                LOGGER.info(f"device {d.id}:{d.name} will change quarantine state when it comes online 👌")
            device_ids.append(d.id)
            cb.device_quarantine(device_ids, quarantine)
        return True


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

        if args.quarantine and args.un_quarantine:
            LOGGER.error("quarantine AND un-quarantine? 🤨 Won't do it.")
            return False

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
            # NOTE TODO - pick this v2 back up and see if it's more efficient to use
            # knowing we have to remember the childproc_name facet data we like.
            #from cbinterface.psc.query import print_facet_histogram_v2
            #print_facet_histogram_v2(cb, args.query)

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

    # Live Response Actions #
    if args.command and (args.command.lower() == "lr" or args.command.lower().startswith("live")):
        # create a LR session manager
        session_manager = CustomLiveResponseSessionManager(cb, custom_session_keepalive=True)
        # store a list of commands to execute on this device
        commands = []

        LOGGER.info(f"searching for device...")
        device = None
        try:  # if device.id
            device = Device(cb, args.name_or_id)
        except ClientError:
            device = find_device_by_hostname(cb, args.name_or_id)

        if not device:
            LOGGER.info(f"could not find a device.")
            return None

        if args.execute_command:
            # XXX expand this for more flexibiliy by making an execute parser
            # that can accept more arugments to pass to ExecuteCommand
            cmd = ExecuteCommand(args.execute_command)
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
                playbook_path = playbook_data['path']
                playbook_commands = build_playbook_commands(playbook_path)
                commands.extend(playbook_commands)
                LOGGER.info(f"loaded {len(playbook_commands)} playbook commands.")

        # Handle LR commands #
        if commands:
            timeout = 1200  # default 20 minutes (same used by Cb)
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
                LOGGER.error(f"reached timeout waiting for active session.")
                return False

            # we have an active session, issue the commands.
            for command in commands:
                session_manager.submit_command(command, device)

        if session_manager.commands:
            # Wait for issued commands to complete and process any results.
            session_manager.process_completed_commands()

    # Direct Session Interaction #
    if args.command and args.command.startswith("sess"):
        cblr = CbThreatHunterAPI(url=cb.credentials.url, token=cb.credentials.lr_token, org_key=cb.credentials.org_key)

        # if args.list_all_sessions:
        # Not implemented with PSC
        # if args.list_sensor_sessions:
        # Not implemented with PSC

        if args.get_session_command_list:
            print(json.dumps(get_session_commands(cblr, args.get_session_command_list), indent=2, sort_keys=True))

        if args.get_session:
            print(json.dumps(get_session_by_id(cblr, args.get_session), indent=2, sort_keys=True))

        if args.close_session:
            print(json.dumps(close_session_by_id(cblr, args.close_session), indent=2, sort_keys=True))

        if args.get_command_result:
            session_id, device_id, command_id = args.get_command_result.split(":", 2)
            session_id = f"{session_id}:{device_id}"
            print(json.dumps(get_command_result(cblr, session_id, command_id), indent=2, sort_keys=True))

        if args.get_file_content:
            session_id, device_id, file_id = args.get_file_content.split(":", 2)
            session_id = f"{session_id}:{device_id}"
            get_file_content(cblr, session_id, file_id)
