"""The addresses a command reaches and the data it sends: curl, wget, httpie, git and the like."""
from __future__ import annotations

import re

from intentshield.mcp_inspect import _parse, distinctive_values

from .expand import _option_letters

# The user part of a URL (http://[::1]@host/): curl connects to the host after the @, whatever comes before it.
# Bounded, so a long dotted run without a scheme is not scanned once per position.
_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,30}://)[^/?#\s@]{0,256}@")


def network_values(text: str) -> set[str]:
    values = distinctive_values(text)
    if "://" in text and "@" in text and _USERINFO.search(text):
        values |= distinctive_values(_USERINFO.sub(r"\1", text))
    return {v for v in values if _parse(v)[0] in ("url", "host", "email")}


def _dynamic(text: str, loopvars: frozenset[str] | set[str]) -> bool:
    """Text built at run time from a command's output or a variable the command does not set itself (a loop
    variable is not data; ``$TOKEN`` may be)."""
    return ("`" in text or "$(" in text or bool(re.search(r"\$(?![\w{])", text))  # $(..) cut at its bracket
            or any(name not in loopvars for name in re.findall(r"\$\{?(\w+)", text)))


def _curl_sends(args: list[str]) -> bool:
    for i, arg in enumerate(args):
        following = args[i + 1] if i + 1 < len(args) else ""
        if arg.startswith(("--data", "--form", "--upload-file", "--json", "--post", "--url-query", "--variable",
                           "--expand-")):  # --variable x@file, --url-query x@file: a file's text goes in the request
            return True
        if arg in ("-X", "--request") and following.upper() in ("POST", "PUT", "PATCH"):
            return True
        if re.fullmatch(r"-(?:X|-request=)(?:POST|PUT|PATCH)", arg, re.I):
            return True
        # headers and cookies read from a file go with the request
        if arg.startswith("@") or re.match(r"--(?:header|cookie)=@", arg):
            return True
        if arg in ("-H", "--header") and following.startswith("@"):
            return True
        if arg in ("-b", "--cookie") and following and "=" not in following:
            return True
        # -d, -F, -T alone, glued to their value (-d@file) or in a cluster (-sSd, -sSd@f); likewise -X, -H, -b
        if re.match(r"-[\w#:]", arg):
            letter, value = _curl_valued(arg, following)
            if letter and letter in "dFT" or letter == "X" and value.upper() in ("POST", "PUT", "PATCH") \
                    or letter == "H" and value.startswith("@") or letter == "b" and value and "=" not in value:
                return True
    return False


# curl's short options that take a value; in a cluster the first of them takes the rest of the word as its value
_CURL_VALUED = frozenset("AbcCdDeEFHKmoPQrTtuUwxXyYz")


def _curl_valued(arg: str, following: str) -> tuple[str, str]:
    """The first short option of the cluster ``arg`` that takes a value, and that value ("" and "" if none)."""
    for i, letter in enumerate(arg[1:], 1):
        if letter in _CURL_VALUED:
            return letter, arg[i + 1:] or following
    return "", ""


def _wget_sends(args: list[str]) -> bool:
    return any(arg.startswith(("--post-", "--body-", "--method=P", "--method=p", "--load-cookies")) or arg == "--method"
               for arg in args)


# curl options that write a file or read options from one; a short cluster ending in o, O, c, D or K does too.
_CURL_WRITES = ("--output", "--remote-name", "--cookie-jar", "--dump-header", "--trace", "--libcurl", "--config",
                "--etag-save", "--hsts", "--alt-svc", "--stderr", "--create-dirs")
# wget saves a file unless told to print the page: only these options are known not to write one.
_WGET_PRINTS = frozenset({"-q", "--quiet", "-O-", "-qO-", "-nv", "--no-verbose", "-S", "--server-response",
                          "--spider"})


def _downloads(name: str, args: list[str]) -> bool:
    """A plain download: a GET or HEAD whose page goes to stdout, carrying no data and writing no file. It
    changes nothing here, so it counts as read-only; the guard still checks where it goes."""
    if any("$" in a or "`" in a for a in args):  # an address built at run time may carry data
        return False
    if name == "curl":
        for i, arg in enumerate(args):
            following = args[i + 1] if i + 1 < len(args) else ""
            if arg in ("-X", "--request") and following.upper() not in ("GET", "HEAD"):
                return False
            if re.fullmatch(r"-(?:X|-request=)(?!GET$|HEAD$).+", arg, re.I):
                return False
            if arg in ("-D", "--dump-header") and following == "-":
                continue
            if arg.startswith(_CURL_WRITES) or re.fullmatch(r"-[a-zA-Z]*[oOcDK]", arg) or re.match(r"-[oOcDK].", arg):
                return False
        return not _curl_sends(args)
    if name == "wget":
        options = [a for a in args if a.startswith("-") or a == "-"]
        printed = any(a in ("-O-", "-qO-", "--spider", "--output-document=-") for a in args) or any(
            a in ("-O", "-qO", "--output-document") and args[i + 1:i + 2] == ["-"] for i, a in enumerate(args))
        allowed = _WGET_PRINTS | {"-O", "-qO", "--output-document", "--output-document=-", "-"}
        return printed and all(a in allowed for a in options) and not _wget_sends(args)
    return False


def _httpie_sends(args: list[str]) -> bool:
    return any(arg.upper() in ("POST", "PUT", "PATCH") or (not arg.startswith("-") and "://" not in arg and
               bool(re.match(r"[\w.-]+(?::=|=|@)", arg))) for arg in args)


def _git_sub(args: list[str]) -> tuple[str, list[str], list[str]]:
    """The git subcommand, its arguments, and the configuration given before it (``-c name=value``, or
    ``env:name=VARIABLE`` for ``--config-env``), which can name a program to run; git's other global options
    (``-C dir``, ``--git-dir=x``) are skipped."""
    i, configs = 0, []
    while i < len(args) and args[i].startswith("-"):
        arg = args[i]
        if arg == "-c" or arg == "--config-env":
            configs.append(("env:" if arg != "-c" else "") + (args[i + 1] if i + 1 < len(args) else ""))
            i += 2
        elif arg.startswith("-c"):
            configs.append(arg[2:])
            i += 1
        elif arg.startswith("--config-env="):
            configs.append("env:" + arg.partition("=")[2])
            i += 1
        elif arg.startswith("--exec-path"):
            configs.append("")
            i += 1
        else:
            i += 2 if arg in ("-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix") else 1
    return (args[i] if i < len(args) else ""), args[i + 1:], configs


# global options that point git at another repository, whose configuration (core.fsmonitor, a pager, a hook)
# names programs that even git status runs
_GIT_ELSEWHERE = ("-C", "--git-dir", "--work-tree")
# long options that are a prefix of an unsafe one without being it (git diff --text is not --textconv)
_OTHER_OPTIONS = frozenset({"--text"})


def _has_option(args: list[str], long: tuple[str, ...], short: str) -> bool:
    """One of these options is among ``args`` (long ones also by any prefix, as ``sort --ou`` is ``--output``;
    short ones also in a cluster)."""
    for arg in args:
        if arg == "--":
            break
        if arg.startswith("--"):
            option = arg.partition("=")[0]
            if option in long or len(option) >= 3 and option not in _OTHER_OPTIONS \
                    and any(name.startswith(option) for name in long):
                return True
        elif short and arg.startswith("-") and len(arg) > 1:
            if any(letter in short for letter in _option_letters(arg)):
                return True
    return False


def _positionals(args: list[str], valued: str = "") -> list[str]:
    """Arguments that are neither options nor the values of the ``valued`` short options."""
    found, skip = [], False
    for arg in args:
        if skip:
            skip = False
        elif arg.startswith("-") and len(arg) > 1:
            skip = arg in tuple("-" + c for c in valued)
        else:
            found.append(arg)
    return found
