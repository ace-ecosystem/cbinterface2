"""Everthing ThreatHunter process related.
"""

import time
import json
import inspect
import logging

from io import StringIO
from datetime import datetime
from contextlib import redirect_stdout
from typing import Dict, List

from cbc_sdk.rest_api import CBCloudAPI
from cbc_sdk.platform import Process
from cbc_sdk.errors import ObjectNotFoundError, MoreThanOneResultError

from cbinterface.psc2.query import CustomAsyncProcessQuery
from cbinterface.helpers import as_configured_timezone, get_os_independant_filepath

LOGGER = logging.getLogger("cbinterface.psc2.process")

# TODO: keep an eye on https://developer.carbonblack.com/reference/carbon-black-cloud/platform/latest/platform-search-api-processes/#request-details-of-processes-v2

def load_process(p: Process, return_data=False) -> Process:
    """Load any process meta-data that exists or return None."""
    try:
        url = f"/api/investigate/v1/orgs/{p._cb.credentials.org_key}/processes/summary"
        summary = p._cb.get_object(url, query_parameters={"process_guid": p.process_guid})
        while summary["incomplete_results"]:
            summary = p._cb.get_object(url, query_parameters={"process_guid": p.process_guid})
        if return_data:
            return summary
        process = Process.new_object(p._cb, summary["process"])
        if is_process_loaded(process):
            return process
    except ObjectNotFoundError:
        LOGGER.debug(f"Process data does not exist for GUID={p.get('process_guid')}")
        return None

def get_process_data(p: Process) -> Dict:
    """Return dictionary of process data."""
    return load_process(p, return_data=True)

def get_process_children(p: Process) -> List[Process]:
    """Return list of children processes."""
    return [
        Process(p._cb, initial_data=child)
        for child in get_process_data(p).get('children', [])
    ]

def get_process_siblings(p: Process) -> List[Process]:
    """Return list of process siblings."""
    return [
        Process(p._cb, initial_data=sibling)
        for sibling in get_process_data(p).get('siblings', [])
    ]

def select_process(cb: CBCloudAPI, process_guid: str, fast_and_dangerous=True):
    """Select and load a Cb processes with a single API call.

    MUCH faster than using the suggested method.

    Args:
        cb: a CBCloudAPI object
        process_guid: a Cb PSC GUID in the form of a string.
        fast_and_dangeroust: use the fast api call that Cb is "deactivating"
           see here: https://developer.carbonblack.com/reference/carbon-black-cloud/cb-threathunter/latest/process-search/#process-summary
    Returns:
        A threathunter.Process or None
    """

    if fast_and_dangerous:
        process = load_process(Process(cb, process_guid, initial_data={}))
        if process:
            return process

    process = CustomAsyncProcessQuery(Process, cb).where(process_guid=process_guid)[:2]
    if process is None or len(process) == 0:
        return None
    if len(process) > 1:
        raise MoreThanOneResultError(message=f"{len(process)} results found for query process_guid={process_guid}")

    return process[0]

# XXX not used
def _summarize_process(cb: CBCloudAPI, process_guid: str):
    """Get all that summary data. Which actually isn't that helpful."""
    base_summary_url = f'/api/investigate/v2/orgs/{cb.credentials.org_key}/processes/summary_jobs'
    job = cb.post_object(base_summary_url, {"process_guid": process_guid})
    if job.status_code != 200:
        LOGGER.error(f"got unexpected result: {job.status_code} - {job.content}")
        return None
    job_id = job.json()['job_id']
    
    summary_result_url = f"{base_summary_url}/{job_id}/results"
    summary_data = cb.get_object(summary_result_url, query_parameters={"format": "tree"})
    #  Confirm the search has completed by verifying that “contacted” equals “completed”.
    while summary_data["completed"] < summary_data["contacted"]:
        time.sleep(0.1)
        summary_data = cb.get_object(summary_result_url, query_parameters={"format": "tree"})
    summary_data['summary'] = cb.get_object(summary_result_url, query_parameters={"format": "summary"})['summary']
    return summary_data    

def is_process_loaded(p: Process) -> bool:
    """Return True if the process has data."""
    if len(p._info.keys()) < 3:
        return False
    return True


def process_to_dict(p: Process) -> Dict:
    """Convert process and it's events to a dictionary."""
    process = {}
    if not is_process_loaded(p):
        p = load_process(p)
    process["info"] = p._info
    process["events"] = {}
    for event in p.events():
        if event.event_type not in process["events"]:
            process["events"][event.event_type] = []
        process["events"][event.event_type].append(event._info)

    process["process_ancestry"] = StringIO()
    with redirect_stdout(process["process_ancestry"]):
        print_ancestry(p)
    process["process_ancestry"] = process["process_ancestry"].getvalue()

    process["process_tree"] = StringIO()
    with redirect_stdout(process["process_tree"]):
        print_process_tree(p)
    process["process_tree"] = process["process_tree"].getvalue()

    return process


def print_process_info(proc: Process, return_string: bool = False, raw_print=False, header=True):
    """Analyst friendly custom process data format.

    Args:
        proc: CbTH Process (fully initialized)
        return_string: return string if True, else print it to stdout.
    Returns: string or None
    """

    if not is_process_loaded(proc):
        proc = load_process(proc)

    txt = ""
    if header:
        txt += "------ INFO ------\n"
    if raw_print:
        txt = str(proc)
    else:
        txt += f"  Process GUID: {proc.get('process_guid')}\n"
        process_name = get_os_independant_filepath(proc.get("process_name", "None")).name
        txt += f"  Process Name: {process_name}\n"
        process_pid = [str(_) for _ in proc.get("process_pid", [])]
        txt += f"  Process PID: {', '.join(process_pid)}\n"
        txt += f"  Process MD5: {proc.get('process_md5')}\n"
        txt += f"  Process SHA256: {proc.get('process_sha256')}\n"
        txt += f"  Process Path: {proc.get('process_name')}\n"
        txt += f"  Process Terminated: {proc.get('process_terminated')}\n"
        txt += f"  Start Time: {as_configured_timezone(proc.get('process_start_time', ''))}\n"
        process_command_line = (
            proc.process_cmdline[0]
            if proc.get("process_cmdline") and len(proc.process_cmdline) == 1
            else proc.get("process_cmdline")
        )
        txt += f"  Command Line: {process_command_line}\n"
        txt += f"  Process Reputation: {proc.get('process_reputation')}\n"
        txt += f"  Parent Name: {proc.get('parent_name')}\n"
        txt += f"  Parent GUID: {proc.get('parent_guid')}\n"
        parent_sha256 = next((hsh for hsh in proc.get("parent_hash", []) if len(hsh) == 64), None)
        txt += f"  Parent SHA256: {parent_sha256}\n"
        txt += f"  Username: {proc.get('process_username')}\n"
        txt += f"  Device ID: {proc.get('device_id')}\n"
        txt += f"  Device Name: {proc.get('device_name')}\n"
        txt += f"  Device OS: {proc.get('device_os')}\n"
        txt += f"  External IP: {proc.get('device_external_ip')}\n"
        txt += f"  Internal IP: {proc.get('device_internal_ip')}\n"
    if return_string:
        return txt
    txt += "\n"
    print(txt)


def print_ancestry(p: Process, max_depth=0, depth=0):
    """Print the process ancestry for this process."""

    if max_depth and depth > max_depth:
        return

    if depth == 0:
        print("\n------ Process Ancestry ------")
        print()

    if not is_process_loaded(p):
        p = load_process(p)

    start_time = as_configured_timezone(p.get("process_start_time", ""))
    command_line = (
        p.process_cmdline[0] if p.get("process_cmdline") and len(p.process_cmdline) == 1 else p.get("process_cmdline")
    )
    print(f"{'  '*(depth + 1)}{start_time}: {command_line} | {p.process_guid}")

    if p.get("parent_guid"):
        parent = select_process(p._cb, p.parent_guid)
        if parent:
            print_ancestry(parent, max_depth=max_depth, depth=depth + 1)

def print_process_tree(p: Process, max_depth=0, depth=0):
    """Print the process tree."""

    if max_depth and depth > max_depth:
        return

    if depth == 0:
        if not is_process_loaded(p):
            p = load_process(p)
        print("\n------ Process Execution Tree ------")
        print()

    command_line = (
        p.process_cmdline[0] if p.get("process_cmdline") and len(p.process_cmdline) == 1 else p.get("process_cmdline")
    )
    print(f"  {'  '*(depth+1)}{command_line}  | {p.process_guid}")

    #for child in p.children: # doesn't work with v2 api
    for child in get_process_children(p):
        print_process_tree(child, max_depth=max_depth, depth=depth + 1)

def get_events_by_type(p: Process, event_type: str):
    """Return process events by event type.

    One of filemod, netconn, regmod, modload, crossproc, childproc, scriptload,
        fileless_scriptload
    """
    # we only load the process here to check for the presence of event_types
    # only make event api calls for processes that report having those events
    if not is_process_loaded(p):
        p = load_process(p)
    # XXX bug in cbc_sdk fixed by using p._info.get instead of p.get
    event_count = p._info.get(f"{event_type}_count", None)
    if event_count is not None and event_count == 0:
        LOGGER.debug(f"processes reports not having any events of type: {event_type}")
        return []
    try:
        return p.events(event_type=event_type)
    except Exception as e:
        LOGGER.error(f"failed to get events: {e}")
        return []

def print_filemods(p: Process, raw_print=False, **kwargs):
    """Print file modifications.

    one or more of ACTION_INVALID, ACTION_FILE_CREATE, ACTION_FILE_WRITE, ACTION_FILE_DELETE, ACTION_FILE_LAST_WRITE, ACTION_FILE_MOD_OPEN,
     ACTION_FILE_RENAME, ACTION_FILE_UNDELETE, ACTION_FILE_TRUNCATE, ACTION_FILE_OPEN_READ, ACTION_FILE_OPEN_WRITE, ACTION_FILE_OPEN_DELETE,
     ACTION_FILE_OPEN_EXECUTE, ACTION_FILE_READ
    """

    print("------ FILEMODS ------")
    for fm in get_events_by_type(p, "filemod"):
        if raw_print:
            print(fm)
            continue
        # action_summary = ', '.join([action[len('ACTION_'):] for action in fm.filemod_action])
        _action_summary = [action[len("ACTION_") :] for action in fm.filemod_action]
        _edge_actions = [action for action in _action_summary if not action.startswith("FILE")]
        _fm_action_summary = [action[len("FILE_") :] for action in _action_summary if action.startswith("FILE")]
        _fm_action_summary.extend(_edge_actions)
        action_summary = ",".join(_fm_action_summary)
        fm_sha256 = f" , sha256:{fm.get('filemod_sha256')}" if fm.get("filemod_sha256") else ""
        print(f" @{as_configured_timezone(fm.event_timestamp)}: |{action_summary}| {fm.filemod_name}{fm_sha256}")
    print()


def print_netconns(p: Process, raw_print=False):
    """Print network connection events.

    action is one or more of: ACTION_CONNECTION_CREATE, ACTION_CONNECTION_CLOSE,
     ACTION_CONNECTION_ESTABLISHED, ACTION_CONNECTION_CREATE_FAILED, ACTION_CONNECTION_LISTEN
    """
    import socket, struct

    print("------ NETCONNS ------")
    for nc in get_events_by_type(p, "netconn"):
        if raw_print:
            print(nc)
            continue
        action = (
            nc.netconn_action[len("ACTION_CONNECTION_") :]
            if nc.netconn_action.startswith("ACTION_CONNECTION_")
            else nc.netconn_action
        )
        if action == "CREATE":
            # same behavior as PSC GUI
            action = "ESTABLISHED"
        action = action.capitalize()
        protocol = nc.get("netconn_protocol", "")
        if protocol.startswith("PROTO_"):
            protocol = protocol[len("PROTO_") :]
        direction = "inbound" if nc.netconn_inbound else "outbound"

        # NOTE: Cb stores ipv4 as integers and returns them as such. Their documentation is lacking but
        # research suggests they follow https://tools.ietf.org/html/rfc1700 and big-endian int can be assumed.

        local_ipv4 = nc.get("netconn_local_ipv4", "")
        if local_ipv4:
            local_ipv4 = socket.inet_ntoa(struct.pack("!i", local_ipv4))
        local_ipv6 = nc.get("netconn_local_ipv6", "")
        if local_ipv6:
            # TODO: insert a colon character between every four alphanumeric characters
            local_ipv6 = f"ipv6({local_ipv6})"
        local = f"from {local_ipv4}{local_ipv6}:{nc.netconn_local_port}"

        remote_ipv4 = nc.get("netconn_remote_ipv4", "")
        if remote_ipv4:
            remote_ipv4 = socket.inet_ntoa(struct.pack("!i", remote_ipv4))
        remote_ipv6 = nc.get("netconn_remote_ipv6", "")
        if remote_ipv6:
            # TODO: insert a colon character between every four alphanumeric characters
            remote_ipv6 = f"ipv6({remote_ipv6})"
        remote = f"to {remote_ipv4}{remote_ipv6}:{nc.netconn_remote_port}"

        domain = f"domain={nc.netconn_domain}"
        print(
            f" @{as_configured_timezone(nc.event_timestamp)}: {action} {direction} {protocol} {local} {remote} ({nc.netconn_domain})"
        )
    print()


def print_regmods(p: Process, raw_print=False):
    """Print registry modifications.

    Actions: ACTION_INVALID, ACTION_CREATE_KEY, ACTION_WRITE_VALUE, ACTION_DELETE_KEY, ACTION_DELETE_VALUE,
        ACTION_RENAME_KEY, ACTION_RESTORE_KEY, ACTION_REPLACE_KEY, ACTION_SET_SECURITY
    """
    print("------ REGMODS ------")
    for rm in get_events_by_type(p, "regmod"):
        if raw_print:
            print(rm)
            continue
        actions = []
        for a in rm.regmod_action:
            if a.startswith("ACTION_"):
                actions.append(a[len("ACTION_") :])
            else:
                actions.append(a)
        # how could the list they return ever be greater than 1 with un-corrupted data?
        action = actions[0]  # if len(actions) > 1 else actions
        if "CREATE" in action:
            action = "Created"
        elif action == "WRITE_VALUE":
            action = "Modified"
        print(f" @{as_configured_timezone(rm.event_timestamp)}: {action}: {rm.regmod_name}")
    print()


def print_scriptloads(p: Process, raw_print=False):
    """Print scriptloads and fileless scriptloads."""
    print("------ SCRIPTLOADS ------")
    for sl in get_events_by_type(p, "scriptload"):
        if raw_print:
            print(sl)
            continue

        pub_state = ",".join([state[len("FILE_SIGNATURE_") :] for state in sl.get("scriptload_publisher_state", [])])
        print(
            f" @{as_configured_timezone(sl.event_timestamp)}: {sl.scriptload_name} , sha256={sl.scriptload_sha256} - {pub_state}"
        )
    print()
    fileless_sl_events = get_events_by_type(p, "fileless_scriptload")
    if fileless_sl_events:
        print("------ FILELESS SCRIPTLOADS ------")
    for fsl in fileless_sl_events:
        if raw_print:
            print(fsl)
            continue

        print(f" @{as_configured_timezone(fsl.event_timestamp)}: {fsl.fileless_scriptload_cmdline}")
    if fileless_sl_events:
        print()

def print_modloads(p: Process, raw_print=False):
    """Print modual/library loads."""

    print("------ MODLOADS ------")
    for ml in get_events_by_type(p, "modload"):
        if raw_print:
            print(ml)
            continue
        # "for now can only be: ACTION_LOAD_MODULE"
        # action = "Loaded" if ml.modload_action == 'ACTION_LOAD_MODULE' else ml.modload_action
        ml_pub_state_summary = (
            "_".join([state[len("FILE_SIGNATURE_STATE") + 1 :] for state in ml.get("modload_publisher_state", [])])
            or ""
        )
        print(
            f" @{as_configured_timezone(ml.event_timestamp)}: {ml.modload_name} , md5:{ml.modload_md5} - {ml.get('modload_publisher')}: {ml_pub_state_summary}"
        )
    print()


def print_crossprocs(p: Process, raw_print=False):
    """Print Cross Process activity.

    Actions: ACTION_DUP_PROCESS_HANDLE, ACTION_OPEN_THREAD_HANDLE, ACTION_DUP_THREAD_HANDLE,
        ACTION_CREATE_REMOTE_THREAD, ACTION_API_CALL
    """
    print("------ CROSSPROCS ------")
    for cp in get_events_by_type(p, "crossproc"):
        if raw_print:
            print(cp)
            continue
        actions = [a[len("ACTION_") :] for a in cp.crossproc_action]
        if len(actions) == 1:
            actions = actions[0]
        else:
            actions = ",".join(actions)
        inverse_target = "from" if cp.crossproc_target is True else "to"
        direction = "<-" if cp.crossproc_target is True else "->"
        proc_guid_direction = f"{cp.process_guid} {direction} {cp.crossproc_process_guid}"
        print(
            f" @{as_configured_timezone(cp.event_timestamp)}: {actions} {inverse_target} {cp.crossproc_name} ({cp.crossproc_sha256}) | {proc_guid_direction}"
        )
    print()


def print_childprocs(p: Process, raw_print=False):
    """Print child process events."""
    print("------ CHILDPROCS ------")
    for cp in get_events_by_type(p, "childproc"):
        if raw_print:
            print(cp)
            continue
        print(f" @{as_configured_timezone(cp.event_timestamp)}: {cp.childproc_cmdline}  - {cp.childproc_process_guid}")
    print()

def print_siblings(p: Process, raw_print=False):
    """Print sibling process events."""
    print("------ SIBLING PROCESSES ------")
    for sibling in get_process_siblings(p):
        if raw_print:
            print(sibling)
            continue
        start_time = as_configured_timezone(sibling.get("process_start_time", ""))
        command_line = (
            sibling.process_cmdline[0] if sibling.get("process_cmdline") and len(sibling.process_cmdline) == 1 else sibling.get("process_cmdline")
        )
        print(f"{start_time}: {command_line} | {sibling.process_guid}")
    print()

def inspect_process_tree(
    proc: Process,
    info=False,
    filemods=False,
    netconns=False,
    regmods=False,
    modloads=False,
    crossprocs=False,
    children=False,
    scriptloads=False,
    max_depth=0,
    depth=0,
    **kwargs,
):
    """Walk down the execution chain and print inspection points."""
    if max_depth and depth > max_depth:
        return

    if depth == 0:
        print_ancestry(proc)
        print_process_tree(proc)

    process_name = get_os_independant_filepath(proc.get("process_name", "None")).name
    print(f"\n+ {process_name} - {proc.process_guid}")
    if info:
        print_process_info(proc, **kwargs)
    if filemods:
        print_filemods(proc, **kwargs)
    if netconns:
        print_netconns(proc, **kwargs)
    if regmods:
        print_regmods(proc, **kwargs)
    if modloads:
        print_modloads(proc, **kwargs)
    if crossprocs:
        print_crossprocs(proc, **kwargs)
    if children:
        print_childprocs(proc, **kwargs)
    if scriptloads:
        print_scriptloads(proc, **kwargs)

    #for child in proc.children:
    for child in get_process_children(proc):
        inspect_process_tree(
            child,
            info=info,
            filemods=filemods,
            netconns=netconns,
            regmods=regmods,
            modloads=modloads,
            crossprocs=crossprocs,
            children=children,
            scriptloads=scriptloads,
            max_depth=max_depth,
            depth=depth + 1,
            **kwargs,
        )
