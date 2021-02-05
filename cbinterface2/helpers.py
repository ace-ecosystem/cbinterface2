"""Helper functions for common actions.
"""

import re

from cbapi.response import Process

UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)

def is_uuid(uuid):
    """Returns True if the given string matches the UUID pattern."""
    return UUID_REGEX.match(uuid)


# XXX just copy and pasted
def handle_proxy(profile):
    """Toggle proxy environment settings per profile.
    XXX I'm sure there is a better way to do this by passing proxy info to cbapi.
    """
    creds = auth.FileCredentialStore("response").get_credentials(profile=profile)

    if 'ignore_system_proxy' in creds and 'https_proxy' in os.environ:
        if creds['ignore_system_proxy']:
            del os.environ['https_proxy']
        else:
            os.environ['https_proxy'] = HTTPS_PROXY
    return