import pytest
import json
import os

from io import StringIO
from contextlib import redirect_stdout

from cbapi.psc.threathunter import CbThreatHunterAPI, Process
from cbapi.errors import ObjectNotFoundError

from cbinterface.config import set_timezone

HOME_PATH = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(autouse=True)
def no_requests(monkeypatch):
    """Remove requests.sessions.Session.request for all tests."""
    monkeypatch.delattr("requests.sessions.Session.request")


# helper
def fake_cb_api(monkeypatch):
    """Fake CbThreatHunterAPI object."""
    return CbThreatHunterAPI(url="https://mcfeely.net", token="N/A", org_key="ork_gey", ssl_verify=False)


def test_fake_cb(monkeypatch):
    assert isinstance(fake_cb_api(monkeypatch), CbThreatHunterAPI)


# helper
def get_dummy_process_data():
    process_guid = "H8NDJUE1-02361dc7-000009d4-00000000-1d70b8a6f55bfa7"
    initial_data = {}
    with open(f"{HOME_PATH}/test_data/{process_guid}.json", "r") as fp:
        initial_data = json.load(fp)
    return initial_data


# helper
def load_dummy_process(monkeypatch):
    initial_data = get_dummy_process_data()
    cb = fake_cb_api(monkeypatch)
    process_info = initial_data["info"]
    process_info["_events"] = initial_data["events"]
    return Process(cb, initial_data["info"]["process_guid"], initial_data=process_info)


def test_dummy_process(monkeypatch):
    assert isinstance(load_dummy_process(monkeypatch), Process)


def test_make_device_query(monkeypatch):
    from cbapi.psc.devices_query import DeviceSearchQuery
    from cbinterface.psc.device import make_device_query

    def _count(self):
        return 0

    cb = fake_cb_api(monkeypatch)
    monkeypatch.setattr(DeviceSearchQuery, "_count", _count)
    assert isinstance(make_device_query(cb, "name:test"), DeviceSearchQuery)


def test_make_process_query(monkeypatch):
    from cbapi.psc.threathunter.models import AsyncProcessQuery
    from cbinterface.psc.query import make_process_query

    cb = fake_cb_api(monkeypatch)
    assert isinstance(make_process_query(cb, "process_name:loop.exe", raise_exceptions=False), AsyncProcessQuery)


def test_is_valid_process_query(monkeypatch):
    from cbapi.psc.threathunter.models import AsyncProcessQuery
    from cbinterface.psc.query import make_process_query
    from cbinterface.psc.query import is_valid_process_query

    def _get_object(url, query_parameters):
        assert url == "/api/investigate/v1/orgs/ork_gey/processes/search_validation"
        assert query_parameters["q"] == "process_name:loop.exe"
        return {"valid": True}

    cb = fake_cb_api(monkeypatch)
    monkeypatch.setattr(cb, "get_object", _get_object)
    query = make_process_query(cb, "process_name:loop.exe", raise_exceptions=False)
    assert is_valid_process_query(query) is True


def test_is_process_loaded(monkeypatch):
    from cbinterface.psc.process import is_process_loaded

    p = load_dummy_process(monkeypatch)
    assert is_process_loaded(p) is True


def test_process_to_dict(monkeypatch, mocker):
    from cbapi.psc.threathunter.models import Event
    from cbinterface.psc.process import process_to_dict

    data = get_dummy_process_data()
    p = load_dummy_process(monkeypatch)

    def _events(self):
        all_events = []
        # NOTE, could use this same events HACK to allow users to parse events from json as-if from the Cb PSC.
        for etype in p._events.keys():
            all_events.extend(data["events"][etype])
        return [Event(p._cb, initial_data=e) for e in all_events]

    monkeypatch.setattr(Process, "events", _events)
    mocker.patch("cbinterface.psc.process.print_ancestry", return_value=data["process_ancestry"])
    mocker.patch("cbinterface.psc.process.print_process_tree", return_value=data["process_tree"])
    process_dict = process_to_dict(p)
    assert isinstance(process_dict, dict)
    assert process_dict.keys() == data.keys()
    assert process_dict["events"] == data["events"]
