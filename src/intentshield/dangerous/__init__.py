"""Deterministic rules for dangerous built-in tool calls (shell, write, edit, read) of ``--builtin-tools``.

What the rest of the hook decides from session state (a tool output that tried to instruct the agent, an address the
user never named) says nothing about a single call that destroys a disk, force-pushes over shared history or sends
``~/.ssh`` to a stranger. These rules read the call alone and decide on its text:

* deny: clear destruction (recursive delete of root, home or system directories, writes to a block device, mkfs,
  fork bombs, force-push or deletion of a shared branch) and clear theft (private keys, cloud credential files and
  keychains read, a sensitive file sent to a network destination, a reverse shell, a backdoor in authorized_keys);
* ask: the softer cases (hook bypass, a force-push elsewhere, ``curl | sh``, a ``.env`` read, a file upload, a
  write to a shell startup file, cron, launchd, systemd, a git hook or a CI workflow, chmod 777).

Safe parsing: commands are split with ``shlex`` into stages, never executed or expanded, and wrappers (sudo, env,
``bash -c``, ``eval``, ``$(...)``) are read through to a depth of three. Every regex here is a bounded character
class or literal with no nested quantifier, so a hostile command costs linear time; commands over ``_MAX`` characters
are cut, and what a limit cuts off is asked about, never allowed. The rules are written from a list of categories, not
from any test set. They are text rules: a command built at run time from pieces (``$(printf ...)``, variables set elsewhere)
is not seen, and that is a limit, not a feature.

The package: ``core`` (limits, ``Hit``), ``parsing`` (command text into stages), ``runners`` (wrappers such as sudo, flock, ssh),
``paths`` (path and credential-store rules), ``rules`` (git, rm, find, disks, modes, network), ``variables`` (variables, braces,
``cd``), ``selfguard`` (the guard's own files), ``powershell`` (cmdlets read as POSIX commands) and ``analysis`` (a whole command,
``assess_shell`` and ``assess_file``). The public names are imported here; the private ones stay reachable as ``dangerous._name``.
"""
from __future__ import annotations

# The names of the private rules stay reachable as ``dangerous._name`` (the tests read the limits and the tables there).
from . import analysis, core, parsing, paths, powershell, rules, runners, selfguard, variables  # noqa: E402
from .analysis import assess_file as assess_file
from .analysis import assess_shell as assess_shell
from .core import ASK as ASK
from .core import DENY as DENY
from .core import Hit as Hit
from .paths import persistence_path as persistence_path
from .rules import path_risk as path_risk
from .rules import shlex_args as shlex_args
from .selfguard import guard_surface as guard_surface

for _module in (core, parsing, runners, paths, rules, variables, selfguard, powershell, analysis):
    for _name, _value in vars(_module).items():
        if _name.startswith("_") and not _name.startswith("__"):
            globals().setdefault(_name, _value)
