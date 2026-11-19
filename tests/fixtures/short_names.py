"""Windows 8.3 short names, for tests of paths that use them."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def short_name(path: Path) -> str:
    """The 8.3 name of the last part of ``path``, or ``""`` if the volume keeps none."""
    if sys.platform != "win32":
        return ""
    import ctypes

    buffer = ctypes.create_unicode_buffer(1024)
    if not ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, len(buffer)):
        return ""
    name = os.path.basename(buffer.value)
    return "" if name.casefold() == path.name.casefold() else name
