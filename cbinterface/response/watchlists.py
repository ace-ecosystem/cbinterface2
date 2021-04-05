"""Everything Watchlist management.

I wrote everything here to help migrate watchlists to to PSC EDR.
"""

import datetime
import logging
from dateutil import tz

from typing import Union, List, Dict

from cbapi.query import SimpleQuery
from cbapi.response import CbResponseAPI, Watchlist

LOGGER = logging.getLogger("cbinterface.response.watchlists")


def get_all_watchlists(cb: CbResponseAPI) -> SimpleQuery:
    """Return a list of all watchlists."""
    return cb.select(Watchlist)


def query_watchlists(cb: CbResponseAPI, query: str) -> SimpleQuery:
    """perform watchlist query"""
    try:
        return cb.select(Watchlist).where(query)
    except Exception as e:
        LOGGER.error(f"problem querying watchlists: {e}")
        return []


def watchlist_to_dict(watchlist: Watchlist) -> Dict:
    """Return watchlist dictionary."""
    wl = watchlist._info
    wl["query"] = watchlist.query
    return wl


def these_watchlists_to_list_dict(cb: CbResponseAPI, watchlist_names=[], watchlist_ids=[]) -> List[Dict]:
    """Convert the listed watchlists to a list of their dictionary representations."""
    wl_data = []
    for wl_name in watchlist_names:
        wl = cb.select(Watchlist).where(f"name:{wl_name}")
        if wl:
            if len(wl) > 1:
                LOGGER.warning(f"got {len(wl)} watchlists with name matching {wl_name}. Using first result")
            wl = wl[0]
            wl_data.append(watchlist_to_dict(wl))

    return wl_data
