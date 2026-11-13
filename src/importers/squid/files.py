"""
Safe file access for the Squid converter.

A Squid configuration is untrusted input: it names files (`include` files and
quoted ACL value files) by paths written for the Squid server, for example
`/etc/squid/allowed_domains.txt`. The converter must never read an arbitrary
file named by such a path (a hostile config could otherwise read, say, a
credentials file in the user's home folder into the report).

Rules (one allowed root, the folder that holds the selected squid.conf):

* A relative path is looked up under the config's folder.
* An absolute path (POSIX `/etc/...`, Windows `C:\\...`, UNC `\\\\host\\...`)
  is tried as its trailing sub-paths under the config's folder, longest first,
  ending with the file name: `/etc/squid/conf.d/x.conf` tries
  `etc/squid/conf.d/x.conf`, `squid/conf.d/x.conf`, `conf.d/x.conf`, `x.conf`.
* Every candidate is resolved with `os.path.realpath` and accepted only when it
  lies inside the config's folder, which also defeats `..` and symlinks that
  point outside it.
* Globs (`include conf.d/*.conf`) follow the same rules.

A path with no accepted candidate is not read. The caller reports it with the
message from `FileResolver.explain()`, which names the file so the user knows
what to copy into the folder.

`read_config()` reads the selected squid.conf itself (UTF-8 with or without a
byte-order mark, CRLF or LF, binary input rejected).
"""

import glob
import os
import re
from typing import List, Optional, Tuple

# Leading Windows drive ("C:") on a path written in the config.
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def read_config(path: str) -> str:
    """Read a squid.conf as text.

    Handles a UTF-8 byte-order mark (configs edited on Windows) and
    normalises CRLF and CR line endings to LF. Raises ValueError for a file
    that is not text (contains NUL bytes), and OSError when the file cannot
    be opened.
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    if b"\x00" in raw:
        raise ValueError(
            "%s is not a text file (contains NUL bytes); expected a squid.conf"
            % path)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def is_rooted(path: str) -> bool:
    """True for a path that is absolute on the Squid host or on Windows:
    `/x`, `\\x`, `\\\\host\\x` or `C:...`."""
    return path.startswith(("/", "\\")) or bool(_DRIVE_RE.match(path))


def path_parts(path: str) -> List[str]:
    """Split a config path into components on `/` and `\\`, ignoring a
    leading drive letter. The same on every operating system, so a Windows
    path in a config is handled on macOS too."""
    rest = _DRIVE_RE.sub("", path, count=1)
    return [p for p in re.split(r"[\\/]+", rest) if p]


class FileResolver:
    """Resolves paths written in a Squid config to files inside one folder.

    `config_dir` is the folder of the selected squid.conf (its subfolders are
    allowed too). With `config_dir=None` nothing can be read.
    """

    def __init__(self, config_dir: Optional[str]):
        self.config_dir = config_dir
        self._root = (os.path.normcase(os.path.realpath(config_dir))
                      if config_dir else None)

    # -- containment ---------------------------------------------------------
    def inside(self, path: str) -> bool:
        """True when `path` (after resolving symlinks and `..`) is inside
        the config's folder."""
        if self._root is None:
            return False
        real = os.path.normcase(os.path.realpath(path))
        try:
            return os.path.commonpath([self._root, real]) == self._root
        except ValueError:            # different drives on Windows
            return False

    # -- candidates ----------------------------------------------------------
    def candidates(self, path: str) -> List[str]:
        """Paths under the config's folder to try for `path`, in order."""
        if not self.config_dir:
            return []
        parts = path_parts(path)
        if not parts:
            return []
        if not is_rooted(path):
            return [os.path.join(self.config_dir, *parts)]
        return [os.path.join(self.config_dir, *parts[i:])
                for i in range(len(parts))]

    def resolve_file(self, path: str) -> Tuple[Optional[str], str]:
        """(file to read, '') or (None, reason) for a path in the config."""
        outside = False
        for cand in self.candidates(path):
            if os.path.isfile(cand):
                if self.inside(cand):
                    return cand, ""
                outside = True
        return None, self.explain(path, outside)

    def resolve_glob(self, pattern: str) -> Tuple[List[str], str]:
        """(files, '') or ([], reason) for an `include` path or glob."""
        if not glob.has_magic(pattern):
            found, reason = self.resolve_file(pattern)
            return ([found], "") if found else ([], reason)
        outside = False
        for cand in self.candidates(pattern):
            hits = sorted(h for h in glob.glob(cand) if os.path.isfile(h))
            ok = [h for h in hits if self.inside(h)]
            if ok:
                return ok, ""
            if hits:
                outside = True
        return [], self.explain(pattern, outside)

    def explain(self, path: str, outside: bool = False) -> str:
        """Why `path` was not read, naming the file."""
        if outside:
            return ("file '%s' was not read: it is outside the config's "
                    "folder" % path)
        return ("file '%s' was not found in the config's folder: copy it "
                "there" % path)
