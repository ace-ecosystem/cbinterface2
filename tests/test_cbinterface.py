import pytest
import json
import os

HOME_PATH = os.path.dirname(os.path.abspath(__file__))


def test_version():
    from cbinterface import __version__
    assert __version__ == "2.3.13"

def test_timezone_settings():
    from dateutil import tz
    from cbinterface.config import set_timezone, get_timezone

    set_timezone("GMT")
    assert "GMT" == os.environ["CBINTERFACE_TIMEZONE"]
    assert get_timezone() == tz.gettz("GMT")


def test_cbapi_environment_settings():
    from cbinterface.config import (
        set_default_cbapi_product,
        set_default_cbapi_profile,
        get_default_cbapi_product,
        get_default_cbapi_profile,
    )

    set_default_cbapi_product("buckets")
    assert get_default_cbapi_product() == "buckets"
    set_default_cbapi_product("more_buckets")
    set_default_cbapi_profile("stacks")
    assert f"{get_default_cbapi_product()}:{get_default_cbapi_profile()}" == "more_buckets:stacks"

def test_playbook_map():
    from cbinterface.config import get_playbook_map
    playbook_map = get_playbook_map()
    assert isinstance(playbook_map, dict)
    playbook = list(playbook_map.values())[0]
    assert list(playbook.keys()) == ['path', 'name', 'description']

def test_playbook_build():
    from cbinterface.scripted_live_response import build_playbook_commands
    from cbinterface.commands import GetFile, PutFile, ExecuteCommand

    commands = build_playbook_commands(f"{HOME_PATH}/test_data/playbooking.around.ini")
    # order matters
    assert len(commands) == 3
    assert isinstance(commands[0], PutFile)
    assert isinstance(commands[1], ExecuteCommand)
    assert isinstance(commands[2], GetFile)

def test_remediation_script():
    from cbinterface.scripted_live_response import build_remediation_commands
    from cbinterface.commands import ( GetFile, PutFile, ExecuteCommand, DeleteFile,
                                       KillProcessByID, KillProcessByName,
                                       DeleteRegistryKeyValue, DeleteRegistryKey)

    cmds = build_remediation_commands(f"{HOME_PATH}/test_data/remediating.around.ini")
    assert isinstance(cmds, list)
    #for cmd in cmds:
    #    print(type(cmd))
    assert len(cmds) == 16
    assert isinstance(cmds[0], KillProcessByID)
    assert isinstance(cmds[1], KillProcessByName)
    assert isinstance(cmds[2], ExecuteCommand)
    assert isinstance(cmds[3], GetFile)
    assert isinstance(cmds[4], ExecuteCommand)
    assert isinstance(cmds[5], ExecuteCommand)
    assert isinstance(cmds[6], GetFile)
    assert isinstance(cmds[7], ExecuteCommand)
    assert isinstance(cmds[8], DeleteRegistryKeyValue)
    assert isinstance(cmds[9], DeleteFile)
    assert isinstance(cmds[10], ExecuteCommand)
    assert isinstance(cmds[11], GetFile)
    assert isinstance(cmds[12], ExecuteCommand)
    assert isinstance(cmds[13], ExecuteCommand)
    assert isinstance(cmds[14], GetFile)
    assert isinstance(cmds[15], ExecuteCommand)
