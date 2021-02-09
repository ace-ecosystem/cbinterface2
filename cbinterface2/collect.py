"""Everything related to sensor collection."""

import json

from cbapi.response.cblr import LiveResponseSession
from cbinterface2.sessions import BaseSessionCommand

def process_listing(session: LiveResponseSession):
    return session.list_processes()

class ProcessListing(BaseSessionCommand):
    """Get process listing via Live Response."""
    def __init__(self):
        super().__init__(description="process listing")

    def run(self, session: LiveResponseSession):
        return session.list_processes()

    def process_result(self):
        # just print the results as json
        print(json.dumps(self.result, indent=2, sort_keys=True))