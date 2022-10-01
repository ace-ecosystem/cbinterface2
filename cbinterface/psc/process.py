"""Everthing ThreatHunter process related.
"""

import datetime
import logging

from io import StringIO
from contextlib import redirect_stdout
from typing import Dict, Union, List

from cbinterface.psc.query import yield_events

from cbapi.psc.threathunter import CbThreatHunterAPI, Process, Event
from cbapi.errors import ObjectNotFoundError

from cbinterface.helpers import as_configured_timezone, get_os_independent_filepath

LOGGER = logging.getLogger("cbinterface.psc.process")

ALL_EVENT_TYPES = [
    "filemod",
    "netconn",
    "netconn_proxy" "regmod",
    "modload",
    "crossproc",
    "childproc",
    "scriptload",
    "fileless_scriptload",
]


def load_process(p: Process) -> Process:
    """Load any process meta-data that exists or return None."""
    try:
        return Process.new_object(p._cb, p.summary._info["process"])
    except RecursionError:
        LOGGER.warning(f"RecursionError occurred loading process details.. loading incomplete details.")
        url = f"/api/investigate/v1/orgs/{p._cb.credentials.org_key}/processes/summary"
        summary = p._cb.get_object(url, query_parameters={"process_guid": p.process_guid})
        return Process.new_object(p._cb, summary["process"])
    except ObjectNotFoundError:
        LOGGER.debug(f"Process data does not exist for GUID={p.get('process_guid')}")
        return None


def select_process(cb: CbThreatHunterAPI, process_guid: str):
    """Select and load a Cb processes with a single API call.

    MUCH faster than using the suggested method.

    Args:
        cb: a CbThreatHunterAPI object
        process_guid: a Cb PSC GUID in the form of a string.
    Returns:
        A threathunter.Process or None
    """
    # Create empty Process. `force_init` is not supported (underlying PSC model is unrefreshable)
    # Use the process object (see load_process) to load a new process object containing the completed process meta-data.
    return load_process(Process(cb, process_guid))


def is_process_loaded(p: Process) -> bool:
    """Return True if the process has data."""
    if len(p._info.keys()) < 3:
        return False
    return True


def process_to_dict(
    p: Process,
    max_events: int = None,
    start_time: datetime.datetime = None,
    end_time: datetime.datetime = None,
    event_rows=2000,
) -> Dict:
    """Convert process and it's events to a dictionary.

    Args:
      p: Carbon Black Cloud Process
      max_events: a limit on the amount of process events to add.
    Returns:
      Dictionary representation of the process
    """
    # TODO: add start & end args so process events during a specific
    #  time window can be pulled. This could be added for several functions on this page.
    process = {}
    if not is_process_loaded(p):
        p = load_process(p)
    process["info"] = p._info
    process["events"] = {}
    event_count = 0
    for event in yield_events(p, start_time=start_time, end_time=end_time, rows=event_rows):
        if event.get("event_type") not in process["events"]:
            process["events"][event["event_type"]] = []
        process["events"][event["event_type"]].append(event)
        event_count += 1
        if max_events is not None:
            assert isinstance(max_events, int)
            if event_count >= max_events:
                LOGGER.info(f"max event limit of {max_events} reached.")
                break

    process["process_ancestry"] = StringIO()
    with redirect_stdout(process["process_ancestry"]):
        print_ancestry(p)
    process["process_ancestry"] = process["process_ancestry"].getvalue()

    process["process_tree"] = StringIO()
    with redirect_stdout(process["process_tree"]):
        print_process_tree(p, start_time=start_time, end_time=end_time)
    process["process_tree"] = process["process_tree"].getvalue()

    return process


def print_process_info(proc: Process, yield_strings: bool = False, raw_print=False, header=True):
    """Analyst friendly custom process data format.

    Args:
        proc: CbTH Process (fully initialized)
        yield_strings: return string if True, else print it to stdout.
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
        process_name = get_os_independent_filepath(proc.get("process_name", "None")).name
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
        txt += f"  Process Username: {proc.get('process_username')}\n"
        txt += f"  Device Username: {proc.get('device_username')}\n"
        txt += f"  Device ID: {proc.get('device_id')}\n"
        txt += f"  Device Name: {proc.get('device_name')}\n"
        txt += f"  Device OS: {proc.get('device_os')}\n"
        txt += f"  External IP: {proc.get('device_external_ip')}\n"
        txt += f"  Internal IP: {proc.get('device_internal_ip')}\n"
    if yield_strings:
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


def print_process_tree(
    p: Union[Process, Dict],
    max_depth=0,
    depth=0,
    start_time: datetime.datetime = None,
    end_time: datetime.datetime = None,
):
    """Print the process tree."""

    if max_depth and depth > max_depth:
        return

    if depth == 0:
        if isinstance(p, Process) and not is_process_loaded(p):
            p = load_process(p)

        print("\n------ Process Execution Tree ------")
        print()

        command_line = (
            p.process_cmdline[0]
            if p.get("process_cmdline") and len(p.get("process_cmdline")) == 1
            else p.get("process_cmdline")
        )
        print(f"  {'  '*(depth+1)}{command_line}  | {p.get('process_guid')}")
    else:
        process_name = get_os_independent_filepath(p.get("childproc_name", "None")).name
        command_line = p.get("childproc_cmdline") if p.get("childproc_cmdline") else p.get("childproc_name")
        print(f"  {'  '*(depth+1)}{process_name}:  {command_line}  | {p.get('childproc_process_guid')}")

    try:
        for child in yield_events(p, criteria={"event_type": ["childproc"]}, start_time=start_time, end_time=end_time):
            child["_cb"] = p.get("_cb")
            child["process_guid"] = child.get("childproc_process_guid")
            print_process_tree(child, max_depth=max_depth, depth=depth + 1)
    except RecursionError:
        LOGGER.warning(f"hit RecursionError walking process tree.. stopping here")
        print(" [!] reached recursion limit walking process tree ...")
    except ObjectNotFoundError:
        LOGGER.warning(f"got 404 object not found for child process")


def get_events_by_type(
    p: Union[Process, Dict],
    event_types: List[str],
    return_dict=False,
    start_time: datetime.datetime = None,
    end_time: datetime.datetime = None,
):
    """Return process events by event type.

    One of filemod, netconn, regmod, modload, crossproc, childproc, scriptload,
        fileless_scriptload, netconn_proxy
    """

    if isinstance(p, dict):
        # processing from json file.
        # NOTE time frame is not enforced here as we assume that happend when the json was written.
        assert "events" in p
        for event_type in event_types:
            for event in p["events"].get(event_type, []):
                yield event
        return

    try:
        # NOTE: when there are thousands of events... this under-the-hood will get ALL of them before returning..
        # return p.events(event_type=event_type)
        # So using our own code to yield events:
        for event in yield_events(p, criteria={"event_type": event_types}, start_time=start_time, end_time=end_time):
            if return_dict:
                yield event
            else:
                yield Event(p._cb, initial_data=event)
    except Exception as e:
        LOGGER.error(f"failed to get events: {e}")
        return


def format_filemod(fm: Union[Event, Dict]):
    """Format filemod event into single line."""
    _action_summary = [action[len("ACTION_") :] for action in fm.get("filemod_action", [])]
    _edge_actions = [action for action in _action_summary if not action.startswith("FILE")]
    _fm_action_summary = [action[len("FILE_") :] for action in _action_summary if action.startswith("FILE")]
    _fm_action_summary.extend(_edge_actions)
    action_summary = ",".join(_fm_action_summary)
    fm_sha256 = f" , sha256:{fm.get('filemod_sha256')}" if fm.get("filemod_sha256") else ""
    return (
        f" @{as_configured_timezone(fm.get('event_timestamp'))}: |{action_summary}| {fm.get('filemod_name')}{fm_sha256}"
    )


def print_filemods(
    p: Union[Process, Dict], raw_print=False, start_time: datetime.datetime = None, end_time: datetime.datetime = None
):
    """Print file modifications.

    one or more of ACTION_INVALID, ACTION_FILE_CREATE, ACTION_FILE_WRITE, ACTION_FILE_DELETE, ACTION_FILE_LAST_WRITE, ACTION_FILE_MOD_OPEN,
     ACTION_FILE_RENAME, ACTION_FILE_UNDELETE, ACTION_FILE_TRUNCATE, ACTION_FILE_OPEN_READ, ACTION_FILE_OPEN_WRITE, ACTION_FILE_OPEN_DELETE,
     ACTION_FILE_OPEN_EXECUTE, ACTION_FILE_READ
    """
    print("------ FILEMODS ------")
    for fm in get_events_by_type(p, ["filemod"], start_time=start_time, end_time=end_time):
        if raw_print:
            print(fm)
            continue
        print(format_filemod(fm))
    print()


def format_netconn(nc: Union[Event, Dict]):
    """Format netconn or netconn_proxy event into a single line."""
    import ipaddress
    import socket, struct

    action = (
        nc.get("netconn_action", "")[len("ACTION_CONNECTION_") :]
        if nc.get("netconn_action", "").startswith("ACTION_CONNECTION_")
        else nc.get("netconn_action")
    )
    if action == "CREATE":
        # same behavior as PSC GUI
        action = "ESTABLISHED"
    action = action.capitalize()
    protocol = nc.get("netconn_protocol", "")
    if protocol.startswith("PROTO_"):
        protocol = protocol[len("PROTO_") :]
    direction = "inbound" if nc.get("netconn_inbound") else "outbound"

    # NOTE: Cb stores ipv4 as integers and returns them as such. Their documentation is lacking but
    # research suggests they follow https://tools.ietf.org/html/rfc1700 and big-endian int can be assumed.

    local_ipv4 = nc.get("netconn_local_ipv4", "")
    if local_ipv4:
        local_ipv4 = socket.inet_ntoa(struct.pack("!i", local_ipv4))
    local_ipv6 = nc.get("netconn_local_ipv6", "")
    if local_ipv6:
        local_ipv6 = ipaddress.ip_address(int(local_ipv6, 16))
    local = f"from {local_ipv4}{local_ipv6}:{nc.get('netconn_local_port')}"

    proxy_ipv4 = nc.get("netconn_proxy_ipv4", "")
    if proxy_ipv4:
        proxy_ipv4 = socket.inet_ntoa(struct.pack("!i", proxy_ipv4))
    proxy_ipv6 = nc.get("netconn_proxy_ipv6", "")
    if proxy_ipv6:
        proxy_ipv6 = ipaddress.ip_address(int(proxy_ipv6, 16))
    proxy = ""
    if proxy_ipv6 or proxy_ipv4:
        proxy = f" proxied via {proxy_ipv4}{proxy_ipv6}:{nc.get('netconn_proxy_port')}:{nc.get('netconn_remote_port')}"

    remote_ipv4 = nc.get("netconn_remote_ipv4", "")
    if remote_ipv4:
        remote_ipv4 = socket.inet_ntoa(struct.pack("!i", remote_ipv4))
    remote_ipv6 = nc.get("netconn_remote_ipv6", "")
    if remote_ipv6:
        remote_ipv6 = ipaddress.ip_address(int(remote_ipv6, 16))
    remote = ""
    if remote_ipv4 or remote_ipv6:
        remote = f"{remote_ipv4}{remote_ipv6}:{nc.get('netconn_remote_port')} "

    domain = f"domain={nc.get('netconn_domain')}" if nc.get("netconn_domain") else ""
    return f" @{as_configured_timezone(nc.get('event_timestamp'))}: {action} {direction} {protocol} {local}{proxy} to {remote}{domain}"


def print_netconns(
    p: Union[Process, Dict], raw_print=False, start_time: datetime.datetime = None, end_time: datetime.datetime = None
):
    """Print network connection events. Both netconn and netconn_proxy events.

    action is one or more of: ACTION_CONNECTION_CREATE, ACTION_CONNECTION_CLOSE,
     ACTION_CONNECTION_ESTABLISHED, ACTION_CONNECTION_CREATE_FAILED, ACTION_CONNECTION_LISTEN
    """
    print("------ NETCONNS ------")
    for nc in get_events_by_type(p, ["netconn", "netconn_proxy"], start_time=start_time, end_time=end_time):
        if raw_print:
            print(nc)
            continue
        print(format_netconn(nc))
    print()


def format_regmod(rm: Union[Event, Dict]):
    """Format regmod event into single line."""
    actions = []
    for a in rm.get("regmod_action"):
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
    return f" @{as_configured_timezone(rm.get('event_timestamp'))}: {action}: {rm.get('regmod_name')}"


def print_regmods(
    p: Union[Process, Dict], raw_print=False, start_time: datetime.datetime = None, end_time: datetime.datetime = None
):
    """Print registry modifications.

    Actions: ACTION_INVALID, ACTION_CREATE_KEY, ACTION_WRITE_VALUE, ACTION_DELETE_KEY, ACTION_DELETE_VALUE,
        ACTION_RENAME_KEY, ACTION_RESTORE_KEY, ACTION_REPLACE_KEY, ACTION_SET_SECURITY
    """
    print("------ REGMODS ------")
    for rm in get_events_by_type(p, ["regmod"], start_time=start_time, end_time=end_time):
        if raw_print:
            print(rm)
            continue
        print(format_regmod(rm))
    print()


def format_scriptload(sl: Union[Event, Dict]):
    """Format scriptload event into single line."""
    if sl.get("event_type") == "scriptload":
        pub_state = ",".join([state[len("FILE_SIGNATURE_") :] for state in sl.get("scriptload_publisher_state", [])])
        return f" @{as_configured_timezone(sl.get('event_timestamp'))}: {sl.get('scriptload_name')} , sha256={sl.get('scriptload_sha256')} - {pub_state}"

    if sl.get("event_type") == "fileless_scriptload":
        return f" @{as_configured_timezone(sl.get('event_timestamp'))}: {sl.get('fileless_scriptload_cmdline')}"


def print_scriptloads(
    p: Union[Process, Dict], raw_print=False, start_time: datetime.datetime = None, end_time: datetime.datetime = None
):
    """Print scriptloads and fileless scriptloads."""
    print("------ SCRIPTLOADS ------")
    for sl in get_events_by_type(p, ["scriptload"], start_time=start_time, end_time=end_time):
        if raw_print:
            print(sl)
            continue
        print(format_scriptload(sl))
    print()
    print("------ FILELESS SCRIPTLOADS ------")
    for sl in get_events_by_type(p, ["fileless_scriptload"], start_time=start_time, end_time=end_time):
        if raw_print:
            print(sl)
            continue
        print(format_scriptload(sl))
    print()


def format_modload(ml: Union[Event, Dict]):
    """Format modload into single line."""
    # "for now can only be: ACTION_LOAD_MODULE"
    # action = "Loaded" if ml.modload_action == 'ACTION_LOAD_MODULE' else ml.modload_action
    ml_pub_state_summary = (
        "_".join([state[len("FILE_SIGNATURE_STATE") + 1 :] for state in ml.get("modload_publisher_state", [])]) or ""
    )
    return f" @{as_configured_timezone(ml.get('event_timestamp'))}: {ml.get('modload_name')} , md5:{ml.get('modload_md5')} - {ml.get('modload_publisher')}: {ml_pub_state_summary}"


def print_modloads(
    p: Union[Process, Dict], raw_print=False, start_time: datetime.datetime = None, end_time: datetime.datetime = None
):
    """Print modual/library loads."""
    print("------ MODLOADS ------")
    for ml in get_events_by_type(p, ["modload"], start_time=start_time, end_time=end_time):
        if raw_print:
            print(ml)
            continue
        print(format_modload(ml))
    print()


def format_crossproc(cp: Union[Event, Dict]):
    """Format crossproc into single line."""
    actions = [a[len("ACTION_") :] for a in cp.get("crossproc_action", [])]
    if len(actions) == 1:
        actions = actions[0]
    else:
        actions = ",".join(actions)
    inverse_target = "from" if cp.get("crossproc_target") is True else "to"
    direction = "<-" if cp.get("crossproc_target") is True else "->"
    proc_guid_direction = f"{cp.get('process_guid')} {direction} {cp.get('crossproc_process_guid')}"
    return f" @{as_configured_timezone(cp.get('event_timestamp'))}: {actions} {inverse_target} {cp.get('crossproc_name')} ({cp.get('crossproc_sha256')}) | {proc_guid_direction}"


def print_crossprocs(
    p: Union[Process, Dict], raw_print=False, start_time: datetime.datetime = None, end_time: datetime.datetime = None
):
    """Print Cross Process activity.

    Actions: ACTION_DUP_PROCESS_HANDLE, ACTION_OPEN_THREAD_HANDLE, ACTION_DUP_THREAD_HANDLE,
        ACTION_CREATE_REMOTE_THREAD, ACTION_API_CALL
    """
    print("------ CROSSPROCS ------")
    for cp in get_events_by_type(p, ["crossproc"], start_time=start_time, end_time=end_time):
        if raw_print:
            print(cp)
            continue
        print(format_crossproc(cp))
    print()


def format_childproc(cp: Union[Event, Dict]):
    """Format childproc event into single line."""
    return f" @{as_configured_timezone(cp.get('event_timestamp'))}: {cp.get('childproc_cmdline')}  - {cp.get('childproc_process_guid')}"


def print_childprocs(
    p: Union[Process, Dict], raw_print=False, start_time: datetime.datetime = None, end_time: datetime.datetime = None
):
    """Print child process events."""
    print("------ CHILDPROCS ------")
    for cp in get_events_by_type(p, ["childproc"], start_time=start_time, end_time=end_time):
        if raw_print:
            print(cp)
            continue
        print(format_childproc(cp))
    print()


def format_event_data(event_data: Dict):
    assert "event_type" in event_data
    if "netconn" in event_data["event_type"]:
        return format_netconn(event_data)
    if event_data["event_type"] == "filemod":
        return format_filemod(event_data)
    if event_data["event_type"] == "modload":
        return format_modload(event_data)
    if "scriptload" in event_data["event_type"]:
        return format_scriptload(event_data)
    if event_data["event_type"] == "childproc":
        return format_childproc(event_data)
    if event_data["event_type"] == "crossproc":
        return format_crossproc(event_data)
    if event_data["event_type"] == "regmod":
        return format_regmod(event_data)
    LOGGER.warning(f"unknown event of type: {event_data['event_type']}")


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
    start_time: datetime.datetime = None,
    end_time: datetime.datetime = None,
    **kwargs,
):
    """Walk down the execution chain and print inspection points."""
    if max_depth and depth > max_depth:
        return

    if depth == 0:
        print_ancestry(proc)
        print_process_tree(proc, start_time=start_time, end_time=end_time)

    process_name = get_os_independent_filepath(proc.get("process_name", "None")).name
    print(f"\n+ {process_name} - {proc.process_guid}")
    if info:
        print_process_info(proc, **kwargs)
    if filemods:
        print_filemods(proc, start_time=start_time, end_time=end_time, **kwargs)
    if netconns:
        print_netconns(proc, start_time=start_time, end_time=end_time, **kwargs)
    if regmods:
        print_regmods(proc, start_time=start_time, end_time=end_time, **kwargs)
    if modloads:
        print_modloads(proc, start_time=start_time, end_time=end_time, **kwargs)
    if crossprocs:
        print_crossprocs(proc, start_time=start_time, end_time=end_time, **kwargs)
    if children:
        print_childprocs(proc, start_time=start_time, end_time=end_time, **kwargs)
    if scriptloads:
        print_scriptloads(proc, start_time=start_time, end_time=end_time, **kwargs)

    try:
        for child in proc.children:
            try:
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
                    start_time=start_time,
                    end_time=end_time,
                    **kwargs,
                )
            except RecursionError:
                LOGGER.warning(f"hit RecursionError inspecting process tree.")
                break
    except ObjectNotFoundError as e:
        LOGGER.warning(f"got object not found error for child proc: {e}")
