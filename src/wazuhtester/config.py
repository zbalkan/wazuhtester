"""Socket path and protocol constants for the Wazuh logtest daemon."""
from __future__ import annotations

import os
from typing import Final

#: Where Wazuh puts the logtest socket on a default install. Kept as a
#: module-level constant for backward compatibility with the original
#: `internal.logtest.LOGTEST_SOCKET`; it does NOT honour the environment
#: override below because it is evaluated once at import time. Prefer
#: `get_socket_path()` in new code.
DEFAULT_LOGTEST_SOCKET: Final[str] = "/var/ossec/queue/sockets/logtest"
LOGTEST_SOCKET: Final[str] = DEFAULT_LOGTEST_SOCKET

_ENV_VAR: Final[str] = "WAZUH_LOGTEST_SOCKET"

#: Maximum size for a single event, mirroring Wazuh's OS_MAXSTR
#: (OS_SIZE_65536) definition for the buffers used to receive log data.
WAZUH_MAX_EVENT_SIZE: Final[int] = 65536


def get_socket_path() -> str:
    """Return the Wazuh logtest socket path to use.

    Honours the `WAZUH_LOGTEST_SOCKET` environment variable so the client
    can be pointed at a non-default install (a container, a test fixture,
    a machine where Wazuh isn't installed at its usual location). Falls
    back to the default Wazuh install location.
    """
    return os.environ.get(_ENV_VAR, DEFAULT_LOGTEST_SOCKET)
