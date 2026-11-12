"""The limits, the verdict a rule gives (``Hit``) and the parsed stage of a command that the other modules share."""
from __future__ import annotations

import re
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import PurePosixPath

_MAX = 50_000        # characters of one command or file read here
_MAX_STAGES = 400    # simple commands examined
_MAX_TOKENS = 20_000  # words examined
_MAX_DEPTH = 3      # nested bash -c / eval / $(...)
_MAX_WORDS = 400    # words of one command after its brace lists are expanded
_MAX_SUBSTITUTIONS = 200   # command substitutions read in one command (more is asked about)
_TOO_DEEP = "nested more than three levels deep (bash -c, eval, $(...)), too deep to read in full."

_PATH_CAP = 1000      # characters of one path read by the file rules, after repeated slashes are collapsed
_PATH_CAP_WHY = f"a path longer than {_PATH_CAP} characters, too long to check"

DENY, ASK = "deny", "ask"

# The working directory of the call being read, for the rules that need to open a file a relative path names (set by
# ``assess_shell`` and ``assess_file``; empty means the process's own).
_WORKDIR: ContextVar[str] = ContextVar("intentshield_workdir", default="")

# Home directories the event names beyond the running user's own (see ``paths._homes``), set the same way.
_EVENT_HOMES: ContextVar[tuple[str, ...]] = ContextVar("intentshield_event_homes", default=())


def _is_opt(arg: str, *names: str) -> bool:
    """True when ``arg`` spells one of the long options ``names`` whole or cut short, as getopt_long and git's option parser
    accept it (``--recursive``, ``--rec``, ``--rec=x``): ``--`` and at least one more character. A cut that two options share is
    an error in the real program, so reading it as the option only makes the guard ask about a command that would not run."""
    if len(arg) < 3 or not arg.startswith("--"):
        return False
    head = arg.partition("=")[0]
    return any(name.startswith(head) for name in names)


def _canon(arg: str, names: tuple[str, ...]) -> str:
    """``arg`` as the full spelling of the long option of ``names`` it abbreviates (the value after ``=`` kept), else as it is."""
    if len(arg) >= 3 and arg.startswith("--"):
        head, eq, value = arg.partition("=")
        if head not in names:
            for name in names:
                if name.startswith(head):
                    return name + eq + value
    return arg


_LONG_WORD = re.compile(r"\S{121,}")


@dataclass
class Hit:
    decision: str
    reason: str
    trigger: str = ""   # the path or text a user may have asked for, to soften a deny to an ask
    escalate: bool = False  # an ask that is a deny where the text is written to a file that runs later, unseen

    def __post_init__(self) -> None:
        if len(self.reason) > 400:  # a reason that quotes a padded path stays readable
            self.reason = _LONG_WORD.sub(lambda m: m[0][:60] + "..." + m[0][-30:], self.reason)


@dataclass
class _Stage:
    argv: list[str]
    redirects: list[tuple[str, str]] = field(default_factory=list)
    piped: bool = False      # its stdin is the previous stage's output
    pipeline: int = 0
    sudo: bool = False
    assigns: list[str] = field(default_factory=list)
    xargs: bool = False      # the program is run by xargs: its last arguments come from its stdin


def _bin(word: str) -> str:
    name = PurePosixPath(word).name.lower()
    return re.sub(r"^(python|perl|ruby|php)[\d.]+$", r"\1", name)
