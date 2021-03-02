import pytest
import json
import os

HOME_PATH = os.path.dirname(os.path.abspath(__file__))


def test_version():
    from cbinterface import __version__

    assert __version__ == "2.1.0"


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
