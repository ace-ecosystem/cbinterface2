"""Everthing response process related.
"""

import json
import inspect
import logging

from io import StringIO
from datetime import datetime
from contextlib import redirect_stdout
from typing import Generator, List, Dict

from cbapi.response import Process, models
from cbapi.errors import ObjectNotFoundError

from cbinterface.helpers import as_configured_timezone

LOGGER = logging.getLogger("cbinterface.response.process")


def process_to_dict(p: Process, max_segments=None) -> Dict:
    """Get all events for this process."""

    all_segments = p.get_segments()
    if max_segments is None:
        max_segments = len(all_segments)

    p.refresh()
    results = p.original_document
    results["captured_segments"] = {}
    results["all_segments"] = all_segments

    results["process_ancestry"] = StringIO()
    with redirect_stdout(results["process_ancestry"]):
        print_ancestry(p)
    results["process_ancestry"] = results["process_ancestry"].getvalue()

    results["process_tree"] = StringIO()
    with redirect_stdout(results["process_tree"]):
        print_process_tree(p)
    results["process_tree"] = results["process_tree"].getvalue()

    captured_segment_count = 0
    if p.current_segment:
        # if current_segment is set, something specifically targeted this segment
        # and we will ensure it gets captured here
        results["captured_segments"][p.current_segment] = segment_events_to_dict(p)
        captured_segment_count += 1

    for segment in all_segments:
        p.current_segment = segment
        if segment in results["captured_segments"]:
            continue
        if captured_segment_count >= max_segments:
            LOGGER.info(f"hit maximum segment limit exporting process to json for {p.id}")
            break
        results["captured_segments"][segment] = segment_events_to_dict(p)
        captured_segment_count += 1

    return results


def cb_event_to_dict(cbevent: models.CbEvent) -> Dict:
    """Convert a single CbEvent to dict.

    Get the default fields and enumerate some more.
    """

    def _is_jsonable(item):
        try:
            json.dumps(item)
            return True
        except (TypeError, OverflowError):
            return False

    data = {}
    data["event_type"] = cbevent.event_type
    for title in cbevent.stat_titles:
        data[title] = str(getattr(cbevent, title, ""))

    all_members = [member for member in inspect.getmembers(cbevent) if not member[0].startswith("_")]
    members = [member for member in all_members if not inspect.ismethod(member[1]) and not inspect.isclass(member[1])]
    for title, attribute in members:
        if title not in data and _is_jsonable(attribute):
            data[title] = attribute

    return data


def cb_events_to_dict(cbevents: Generator[models.CbEvent, None, None]) -> List[Dict]:
    """Convert a list of CbEvents to a list of dictionaries."""
    return [cb_event_to_dict(event) for event in cbevents]


def segment_events_to_dict(p: Process) -> Dict:
    """Convert current segment CbEvents to dict."""
    if not p.current_segment:
        return {}
    return {
        "filemods": cb_events_to_dict(p.filemods),
        "netconns": cb_events_to_dict(p.netconns),
        "regmods": cb_events_to_dict(p.regmods),
        "modloads": cb_events_to_dict(p.modloads),
        "crossprocs": cb_events_to_dict(p.crossprocs),
        "children": cb_events_to_dict(p.children),
    }


def print_process_info(proc: Process, return_string: bool = False, raw_print=False, header=True):
    """Analyst friendly custom process data format.

    Args:
        proc: CbR Process
        return_string: return string if True, else print it to stdout.
    Returns: string or None
    """

    if not proc._info and raw_print:
        LOGGER.debug(f"retrieving process info.")
        proc.refresh()

    txt = ""
    if header:
        txt += "------ INFO ------\n"
    if raw_print:
        txt = str(proc)
    else:
        status = "Terminated" if proc.terminated else "Running"
        txt += f"  Process GUID: {proc.id}\n"
        txt += f"  Process Name: {proc.process_name}\n"
        txt += f"  Process PID: {proc.process_pid}\n"
        txt += f"  Process MD5: {proc.process_md5}\n"
        txt += f"  Process Path: {proc.path}\n"
        txt += f"  Process Status: {status}\n"
        txt += f"  Command Line: {proc.cmdline}\n"
        txt += f"  Parent Name: {proc.parent_name}\n"
        txt += f"  Parent GUID: {proc.parent_id}\n"
        txt += f"  Hostname: {proc.hostname}\n"
        txt += f"  Username: {proc.username}\n"
        txt += f"  Start Time: {as_configured_timezone(proc.start)}\n"
        try:
            txt += f"  Last Update Time: {as_configured_timezone(proc.last_update)}\n"
        except TypeError:  # should be handled by cbapi
            txt += f"  Last Update Time: None\n"
        txt += f"  Sensor ID: {proc.sensor_id}\n"
        txt += f"  Comms IP: {proc.comms_ip}\n"
        txt += f"  Interface IP: {proc.interface_ip}\n"
        txt += f"  GUI Link: {proc.webui_link}\n"
    if return_string:
        return txt
    txt += "\n"
    print(txt)


def print_ancestry(p: Process):
    """Print the process ancestry for this process."""

    def _print_ancestry_details(p, depth):
        suspressed = " (suppressed) " if p.suppressed_process else " "
        print(f"{'  '*(depth + 1)}{as_configured_timezone(p.start) or '<unknown>'}:  {p.cmdline}{suspressed} | {p.id}")

    print("------ Process Ancestry ------")
    print()
    p.walk_parents(_print_ancestry_details)
    print()


def print_process_tree(p: Process):
    """Print the process tree."""

    def _print_process_tree(p, depth):
        suspressed = "(suppressed) " if p.suppressed_process else ""
        print(f"  {'  '*(depth+1)}{suspressed}{p.cmdline}  | {p.id}")  # - proc_guid={p.id})")

    print("------ Process Execution Tree ------")
    print()
    print(f"  {p.cmdline}  | {p.id}")  # - proc_guid={p.id})")
    p.walk_children(_print_process_tree)
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

    print(f"\n+ {proc.process_name} - {proc.id}")
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

    for cpevent in proc.children:
        if not cpevent.terminated:
            try:
                proc = cpevent.process
            except ObjectNotFoundError:
                continue
            else:
                inspect_process_tree(
                    proc,
                    info=info,
                    filemods=filemods,
                    netconns=netconns,
                    regmods=regmods,
                    modloads=modloads,
                    crossprocs=crossprocs,
                    children=children,
                    max_depth=max_depth,
                    depth=depth + 1,
                    **kwargs,
                )


def print_filemods(p: Process, current_segment_only: bool = False, raw_print=False, **kwargs):
    """Print file modifications."""

    def _print_filemod_events(filemods):
        for fm in filemods:
            assert isinstance(fm, models.CbFileModEvent)
            if raw_print:
                print(fm)
                continue
            detail_line = f" @{as_configured_timezone(fm.timestamp)}: {fm.type} {fm.path}"
            if fm.filetype != "Unknown":
                detail_line += f" - type:{fm.filetype}"
            if fm.md5:
                detail_line += f" - md5:{fm.md5}"
            print(detail_line)
        print()

    print("------ FILEMODS ------")
    if current_segment_only:
        _print_filemod_events(p.filemods)
        return
    _print_filemod_events(p.all_filemods())
    return


def print_netconns(p: Process, current_segment_only: bool = False, raw_print=False):
    """Print network connection events."""

    def _print_netconn_events(netconns):
        for nc in netconns:
            assert isinstance(nc, models.CbNetConnEvent)
            if raw_print:
                print(nc)
                continue
            detail_line = f" @{as_configured_timezone(nc.timestamp)}: ({nc.direction}) local_ip_port={nc.local_ip}:{nc.local_port}"
            if nc.proxy_ip != "0.0.0.0":
                detail_line += f" proxy_ip_port={nc.proxy_ip}:{nc.proxy_port}"
            detail_line += f" remote_ip_port={nc.remote_ip}:{nc.remote_port} domain={nc.domain}"
            print(detail_line)
        print()

    print("------ NETCONNS ------")
    if current_segment_only:
        _print_netconn_events(p.netconns)
        return
    _print_netconn_events(p.all_netconns())
    return


def print_regmods(p: Process, current_segment_only: bool = False, raw_print=False):
    """Print registry modifications."""

    def _print_regmod_events(regmods):
        for rm in regmods:
            assert isinstance(rm, models.CbRegModEvent)
            if raw_print:
                print(rm)
                continue
            print(f" @{as_configured_timezone(rm.timestamp)}: {rm.type} {rm.path}")
        print()

    print("------ REGMODS ------")
    if current_segment_only:
        _print_regmod_events(p.regmods)
        return
    _print_regmod_events(p.all_regmods())
    return


def print_modloads(p: Process, current_segment_only: bool = False, raw_print=False):
    """Print modual/library loads."""

    def _print_modload_events(modloads):
        for ml in modloads:
            assert isinstance(ml, models.CbModLoadEvent)
            if raw_print:
                print(ml)
                continue
            sig_status = "signed" if ml.is_signed else "unsigned"
            print(f" @{as_configured_timezone(ml.timestamp)}: ({sig_status}) {ml.path} , md5:{ml.md5}")
        print()

    print("------ MODLOADS ------")
    if current_segment_only:
        _print_modload_events(p.modloads)
        return
    _print_modload_events(p.all_modloads())
    return


def print_crossprocs(p: Process, current_segment_only: bool = False, raw_print=False):
    """Print Cross Process activity."""

    def _print_crossproc_events(crossprocs):
        for cp in crossprocs:
            assert isinstance(cp, models.CbCrossProcEvent)
            if raw_print:
                print(cp)
                continue
            print(
                f" @{as_configured_timezone(cp.timestamp)}: {cp.type} | {cp.source_path} -> {cp.target_path} | {cp.source_proc.id} -> {cp.target_proc.id}"
            )
            # print() # extra space seems to be helpful on the eye with these
        print()

    print("------ CROSSPROCS ------")
    if current_segment_only:
        _print_crossproc_events(p.crossprocs)
        return
    _print_crossproc_events(p.all_crossprocs())
    return


def print_childprocs(p: Process, current_segment_only: bool = False, raw_print=False):
    """Print child process events."""

    if p.current_segment is None:
        # avoids server error calling /api/v4/process/{guid}/{segment}/event
        p.current_segment = p.get_segments()[0]

    def _print_childproc_events(childprocs):
        if raw_print:
            for cp in childprocs:
                print(cp)
            return

        # group start/end childproc events together
        organized_childprocs = {}
        for cp in childprocs:
            guid = cp.procguid[: cp.procguid.rfind("-")]
            if guid in organized_childprocs:
                organized_childprocs[guid].append(cp)
            else:
                organized_childprocs[guid] = [cp]

        for cp_guid, cp_events in organized_childprocs.items():
            # there should only be two events, a spawn and terminate event
            # however, don't make assumptions
            spawn = cp_events[0]
            terminate_cp = None
            if len(cp_events) > 1:
                for cp in cp_events:
                    if cp.timestamp < spawn.timestamp:
                        spawn = cp
                    else:
                        terminate_cp = cp

            status = "unknown"
            try:
                if spawn.is_suppressed:
                    status = "suppressed"
                status = "terminated" if spawn.process.terminated else "running"
                if spawn.process.terminated and terminate_cp is None:
                    LOGGER.debug(f"notice: no termination event found. process must have terminated elsewhere?")
            except ObjectNotFoundError:
                LOGGER.debug(f"child process not found. ")

            print(
                f" @{as_configured_timezone(spawn.timestamp)}: ({status}) {spawn.path} md5={spawn.md5} pid={spawn.pid} - {cp_guid}"
            )
        print()

    print("------ CHILDPROCS ------")
    childprocs = []
    if current_segment_only:
        childprocs = p.childprocs
    else:
        childprocs = p.all_childprocs()

    try:
        _print_childproc_events(childprocs)
        """
        for cp in p.children:
            print(f" @{as_configured_timezone(cp.timestamp)}: {cp.path} md5={cp.md5} pid={cp.pid} - {cp.procguid}")
        print()
        """
    except Exception as e:
        LOGGER.error(f"unhandled exception when enumerating childproc events: {e}")
    return
