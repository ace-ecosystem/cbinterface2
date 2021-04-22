import pytest
import json
import os

from io import StringIO
from contextlib import redirect_stdout

from cbapi.response import CbResponseAPI, Process
from cbapi.errors import ObjectNotFoundError

from cbinterface.config import set_timezone

HOME_PATH = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(autouse=True)
def no_requests(monkeypatch):
    """Remove requests.sessions.Session.request for all tests."""
    monkeypatch.delattr("requests.sessions.Session.request")


def fake_cb_response_api(monkeypatch):
    """Fake CbResponseAPI object."""

    def fake_info(self):
        server_info = {}
        with open(f"{HOME_PATH}/test_data/cb_response_server_info.json", "r") as fp:
            server_info = json.load(fp)
        server_info["version"] = "5.0.0"
        return server_info

    monkeypatch.setattr(CbResponseAPI, "info", fake_info)
    return CbResponseAPI(url="https://fakehost", token="N/A", ssl_verify=False)


def get_process(monkeypatch):
    from cbapi.response.models import CbFileModEvent
    from cbapi.response.models import CbNetConnEvent
    from cbapi.response.models import CbRegModEvent
    from cbapi.response.models import CbModLoadEvent
    from cbapi.response.models import CbCrossProcEvent
    from cbapi.response.models import CbChildProcEvent

    def _get_segments():
        proc._segments = initial_data["captured_segments"].keys()
        return proc._segments

    def _refresh():
        return True

    def _require_events():
        proc._full_init = True
        proc._events_loaded = True
        return

    def _retrieve_cb_info():
        return cb.server_info

    def _all_filemods():
        for segment_id in proc.get_segments():
            for fm in proc._events[segment_id]["filemods"]:
                timestamp = fm["timestamp"]
                seq = fm["sequence"]
                yield CbFileModEvent(proc, timestamp, seq, fm)

    def _all_netconns():
        for segment_id in proc.get_segments():
            for nc in proc._events[segment_id]["netconns"]:
                timestamp = nc["timestamp"]
                seq = nc["sequence"]
                yield CbNetConnEvent(proc, timestamp, seq, nc)

    def _all_regmods():
        for segment_id in proc.get_segments():
            for rm in proc._events[segment_id]["regmods"]:
                timestamp = rm["timestamp"]
                seq = rm["sequence"]
                yield CbRegModEvent(proc, timestamp, seq, rm)

    def _all_modloads():
        def _is_signed(self):
            return self["is_signed"]

        modloads = []
        for segment_id in proc.get_segments():
            for ml in proc._events[segment_id]["modloads"]:
                timestamp = ml["timestamp"]
                seq = ml["sequence"]
                monkeypatch.setattr(CbModLoadEvent, "is_signed", _is_signed)
                yield CbModLoadEvent(proc, timestamp, seq, ml)

    def _all_crossprocs():
        for segment_id in proc.get_segments():
            for cp in proc._events[segment_id]["crossprocs"]:
                timestamp = cp["timestamp"]
                seq = cp["sequence"]
                yield CbCrossProcEvent(proc, timestamp, seq, cp)

    def _all_childprocs():
        for segment_id in proc.get_segments():
            for cp in proc._events[segment_id]["children"]:
                timestamp = cp["timestamp"]
                seq = cp["sequence"]
                is_suppressed = cp["is_suppressed"]
                proc_data = cp["proc_data"]
                yield CbChildProcEvent(proc, timestamp, seq, cp, is_suppressed=is_suppressed, proc_data=proc_data)

    def _walk_children(callback, max_depth=1, depth=0):
        if max_depth and depth > max_depth:
            return
        if not proc.terminated:
            try:
                callback(proc, depth=depth)
            except ObjectNotFoundError:
                pass
            else:
                proc.walk_children(callback, max_depth=max_depth, depth=depth + 1)

    def _walk_parents(callback, max_depth=1, depth=0):
        if max_depth and depth > max_depth:
            return
        try:
            parent_proc = proc
            if parent_proc and parent_proc.get("process_pid", -1) != -1:
                callback(parent_proc, depth=depth)
            else:
                return
        except ObjectNotFoundError:
            return
        else:
            parent_proc.walk_parents(callback, max_depth=max_depth, depth=depth + 1)

    # set default timezone to GMT
    set_timezone("GMT")

    initial_data = {}
    cb = fake_cb_response_api(monkeypatch)

    with open(f"{HOME_PATH}/test_data/00007c6f-0000-0a28-01d6-ffde20451832.json", "r") as fp:
        initial_data = json.load(fp)
    proc = Process(cb, "00007c6f-0000-0a28-01d6-ffde20451832", initial_data=initial_data)

    # load events
    for segment_id in initial_data["captured_segments"].keys():
        if segment_id not in proc._events:
            proc._events[segment_id] = {}
        for event_type in ["filemods", "netconns", "regmods", "modloads", "crossprocs", "children"]:
            proc._events[segment_id][event_type] = initial_data["captured_segments"][segment_id][event_type]

    monkeypatch.setattr(proc, "get_segments", _get_segments)
    monkeypatch.setattr(proc, "refresh", _refresh)
    monkeypatch.setattr(proc, "require_events", _require_events)
    monkeypatch.setattr(proc, "_retrieve_cb_info", _retrieve_cb_info)
    monkeypatch.setattr(proc, "all_filemods", _all_filemods)
    monkeypatch.setattr(proc, "all_netconns", _all_netconns)
    monkeypatch.setattr(proc, "all_regmods", _all_regmods)
    monkeypatch.setattr(proc, "all_modloads", _all_modloads)
    monkeypatch.setattr(proc, "all_crossprocs", _all_crossprocs)
    monkeypatch.setattr(proc, "all_childprocs", _all_childprocs)
    monkeypatch.setattr(proc, "walk_children", _walk_children)
    monkeypatch.setattr(proc, "walk_parents", _walk_parents)
    return proc


def test_fake_cb(monkeypatch):
    assert isinstance(fake_cb_response_api(monkeypatch), CbResponseAPI)


def test_make_cb_response_query(monkeypatch):
    from datetime import datetime
    from cbapi.response.models import ProcessQuery
    from cbinterface.response.query import make_process_query

    def _get_query_results(url, query_parameters=None, default=None):
        assert url == "/api/v1/process"
        assert query_parameters == [("cb.urlver", 1), ("q", "hostname:hippo"), ("start", 0), ("rows", 0)]
        return {}

    cb = fake_cb_response_api(monkeypatch)
    result = make_process_query(cb, "hostname:hippo", raise_exceptions=False)
    assert isinstance(result, ProcessQuery)
    result = make_process_query(cb, "hostname:hippo", datetime.now(), raise_exceptions=False)
    assert isinstance(result, ProcessQuery)
    result = make_process_query(cb, "hostname:hippo", datetime.now(), datetime.now(), raise_exceptions=False)
    assert isinstance(result, ProcessQuery)
    monkeypatch.setattr(cb, "get_object", _get_query_results)
    assert len(result) == 0


def test_print_facet_histogram():
    from io import StringIO
    from contextlib import redirect_stdout
    from cbinterface.response.query import print_facet_histogram

    facet_data = {}
    with open(f"{HOME_PATH}/test_data/facet_data.json", "r") as fp:
        facet_data = json.load(fp)
    output_string = ""
    with open(f"{HOME_PATH}/test_data/facet_data_output.txt", "r") as fp:
        output_string = fp.read()
    results = StringIO()
    with redirect_stdout(results):
        print_facet_histogram(facet_data)
    assert results.getvalue() == output_string


def test_make_sensor_query(monkeypatch):
    from cbapi.response import Sensor
    from cbapi.response.models import SensorQuery
    from cbinterface.response.sensor import make_sensor_query

    def _get_sensor_results(url, query_parameters=None, default=None):
        assert url == "/api/v1/sensor"
        assert query_parameters == [("hostname", "hippo")]
        return []

    cb = fake_cb_response_api(monkeypatch)
    monkeypatch.setattr(cb, "get_object", _get_sensor_results)
    result = make_sensor_query(cb, "hostname:hippo")
    assert isinstance(result, SensorQuery)


def test_print_process_info(monkeypatch):
    from cbinterface.response.process import print_process_info

    proc = get_process(monkeypatch)

    result = print_process_info(proc, return_string=True)
    assert isinstance(result, str)
    stored_result = ""
    with open(f"{HOME_PATH}/test_data/printed_process_info.txt", "r") as fp:
        stored_result = fp.read()
    assert result == stored_result
    result = print_process_info(proc, return_string=True, header=False)
    assert "------ INFO ------" not in result


def test_print_process_ancestry(monkeypatch):
    from cbinterface.response.process import print_ancestry

    proc = get_process(monkeypatch)

    expected_output = ""
    with open(f"{HOME_PATH}/test_data/ancestry_str.txt", "r") as fp:
        expected_output = fp.read()
    results = StringIO()
    with redirect_stdout(results):
        print_ancestry(proc)
    assert results.getvalue() == expected_output


def test_print_process_tree(monkeypatch):
    from cbinterface.response.process import print_process_tree

    proc = get_process(monkeypatch)

    expected_output = ""
    with open(f"{HOME_PATH}/test_data/process_tree_str.txt", "r") as fp:
        expected_output = fp.read()
    results = StringIO()
    with redirect_stdout(results):
        print_process_tree(proc)
    assert results.getvalue() == expected_output


def test_print_filemods(monkeypatch):
    from cbinterface.response.process import print_filemods

    proc = get_process(monkeypatch)

    expected_output = ""
    with open(f"{HOME_PATH}/test_data/filemods.txt", "r") as fp:
        expected_output = fp.read()
    results = StringIO()
    with redirect_stdout(results):
        print_filemods(proc)
    assert results.getvalue() == expected_output


def test_print_netconns(monkeypatch):
    from cbinterface.response.process import print_netconns

    proc = get_process(monkeypatch)

    expected_output = ""
    with open(f"{HOME_PATH}/test_data/netconns.txt", "r") as fp:
        expected_output = fp.read()
    results = StringIO()
    with redirect_stdout(results):
        print_netconns(proc)
    assert results.getvalue() == expected_output


def test_print_regmods(monkeypatch):
    from cbinterface.response.process import print_regmods

    proc = get_process(monkeypatch)

    expected_output = ""
    with open(f"{HOME_PATH}/test_data/regmods.txt", "r") as fp:
        expected_output = fp.read()
    results = StringIO()
    with redirect_stdout(results):
        print_regmods(proc)
    assert results.getvalue() == expected_output


def test_print_modloads(monkeypatch):
    from cbinterface.response.process import print_modloads

    proc = get_process(monkeypatch)

    expected_output = ""
    with open(f"{HOME_PATH}/test_data/modloads.txt", "r") as fp:
        expected_output = fp.read()
    results = StringIO()
    with redirect_stdout(results):
        print_modloads(proc)
    assert results.getvalue() == expected_output


def test_print_crossprocs(monkeypatch):
    from cbinterface.response.process import print_crossprocs

    proc = get_process(monkeypatch)

    expected_output = ""
    with open(f"{HOME_PATH}/test_data/crossprocs.txt", "r") as fp:
        expected_output = fp.read()
    results = StringIO()
    with redirect_stdout(results):
        print_crossprocs(proc)
    assert results.getvalue() == expected_output


def test_print_children(monkeypatch):
    from cbinterface.response.process import print_childprocs

    proc = get_process(monkeypatch)

    expected_output = ""
    with open(f"{HOME_PATH}/test_data/children.txt", "r") as fp:
        expected_output = fp.read()
    results = StringIO()
    with redirect_stdout(results):
        print_childprocs(proc)
    assert results.getvalue() == expected_output


def test_process_to_dict(monkeypatch):
    from cbinterface.response.process import process_to_dict

    proc = get_process(monkeypatch)
    cb = proc._cb

    results = process_to_dict(proc, max_segments=2)
    assert isinstance(results, dict)


def test_configured_timezone(monkeypatch):
    from cbinterface.helpers import as_configured_timezone

    proc = get_process(monkeypatch)
    set_timezone("GMT")
    assert "2021-02-10 18:54:14.323000+0000" == as_configured_timezone(proc.start)
    set_timezone("US/Eastern")
    assert "2021-02-10 13:54:14.323000-0500" == as_configured_timezone(proc.start)

"""time zones change time zones
def test_utc_offset_to_potential_tz_names():
    from datetime import timedelta
    from cbinterface.helpers import utc_offset_to_potential_tz_names

    zones = utc_offset_to_potential_tz_names(timedelta(hours=5, minutes=30))
    assert len(zones) == 3
    zones = utc_offset_to_potential_tz_names(timedelta(hours=-5))
    # daylight saving time
    assert len(zones) == 47 or len(zones) == 35
"""
