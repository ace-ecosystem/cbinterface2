"""Helper functions for common actions.
"""

import re

UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)

def is_uuid(uuid):
    """Returns True if the given string matches the UUID pattern."""
    return UUID_REGEX.match(uuid)