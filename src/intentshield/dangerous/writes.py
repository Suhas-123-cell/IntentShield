"""Which paths a command writes: the one place that says what each program does to the files it is given.

A rule that treats a write differently from a read (a system file, a key, a startup file, the guard's own files) asks
``written_paths`` and gets the paths the command writes, whichever way the program is told to write them: a redirect, ``tee``,
``dd of=``, the destination of ``cp`` and its kin (also ``-t DIR``), an in-place edit (``sed -i``, ``sed -ni``, ``perl -pi``,
``ruby -i.bak``, ``awk -i inplace``), an editor given a file, ``tar -C DIR``, ``unzip -d DIR``, and the root of a ``find`` that
runs a command or deletes. Option clusters are read as a parser reads them, not matched against a list of spellings."""
from __future__ import annotations

import re

from .core import _bin, _canon

_Option = tuple[str, str | None]


def _options(args: list[str], value: str = "", attached: str = "", longs: dict[str, bool] | None = None
             ) -> tuple[list[_Option], list[str]]:
    """``args`` split into options and operands the way getopt reads them. ``value``: short options that take a value (the rest
    of the cluster, or else the next word). ``attached``: short options whose value is the rest of the cluster (``-i.bak``) and
    which take no other. ``longs``: long options by name, each True when it takes a value (``--name=v`` or ``--name v``); a long
    option may be cut short. A cluster is read letter by letter: ``-pi``, ``-0777pi`` and ``-lpi.bak`` are their letters."""
    longs = longs or {}
    opts: list[_Option] = []
    operands: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            operands.extend(args[i:])
            break
        if arg.startswith("--") and len(arg) > 2:
            name, eq, val = _canon(arg, tuple(longs)).partition("=")
            if longs.get(name) and not eq and i < len(args):
                val, i = args[i], i + 1
            opts.append((name, val if eq or longs.get(name) else None))
        elif arg.startswith("-") and len(arg) > 1:
            body = arg[1:]
            for k, c in enumerate(body):
                rest = body[k + 1:]
                if c in value:
                    if rest:
                        opts.append(("-" + c, rest))
                    elif i < len(args):
                        opts.append(("-" + c, args[i]))
                        i += 1
                    else:
                        opts.append(("-" + c, None))
                    break
                if c in attached:
                    opts.append(("-" + c, rest))
                    break
                opts.append(("-" + c, None))
        else:
            operands.append(arg)
    return opts, operands


def _has(opts: list[_Option], *names: str) -> bool:
    return any(o in names for o, _ in opts)


def _last(opts: list[_Option], *names: str) -> str | None:
    found = [v for o, v in opts if o in names and v is not None]
    return found[-1] if found else None


def _join(directory: str, member: str) -> str:
    return directory.rstrip("/") + "/" + member.lstrip("/") if directory != "/" else "/" + member.lstrip("/")


_DISK_COPIERS = frozenset({"dd", "dcfldd", "dc3dd"})
_AWKS = frozenset({"awk", "gawk", "mawk", "nawk"})

# --- in-place edits -------------------------------------------------------------------------------------------------------

_SED_LONGS = {"--in-place": False, "--expression": True, "--file": True, "--line-length": True, "--quiet": False,
              "--silent": False, "--regexp-extended": False, "--separate": False, "--null-data": False, "--debug": False,
              "--posix": False, "--sandbox": False, "--unbuffered": False, "--binary": False, "--follow-symlinks": False,
              "--help": False, "--version": False}


def _sed_files(args: list[str]) -> list[str]:
    """The files ``sed -i`` (any cluster holding ``i``: ``-ni``, ``-i.bak``, ``-Ei``, ``--in-place=.bak``) edits."""
    opts, operands = _options(args, value="efl", attached="i", longs=_SED_LONGS)
    if not _has(opts, "-i", "--in-place"):
        return []
    files = [a for a in operands if a]   # BSD sed takes its suffix as the next word, which may be empty
    return files if _has(opts, "-e", "-f", "--expression", "--file") else files[1:]


def _script_runner_files(args: list[str], value: str, attached: str) -> list[str]:
    """The files ``perl`` or ``ruby`` edits in place with ``-i[ext]`` anywhere in a cluster (``-pi``, ``-ni``, ``-lpi``,
    ``-0777pi``, ``-pi.bak``, ``-i.bak``): the operands, less the script file when the code is not given with ``-e``."""
    opts, operands = _options(args, value=value, attached=attached)
    if not _has(opts, "-i"):
        return []
    return operands if _has(opts, "-e", "-E") else operands[1:]


_AWK_LONGS = {"--file": True, "--field-separator": True, "--assign": True, "--source": True, "--exec": True,
              "--include": True, "--load": True}
_INPLACE_LIB = re.compile(r"(?:.*/)?inplace(?:\.awk|\.so)?")
_AWK_ASSIGN = re.compile(r"[A-Za-z_]\w*=")


def _awk_files(args: list[str]) -> list[str]:
    """The files ``gawk -i inplace`` (also ``-iinplace``, ``--include=inplace``, ``-l inplace``) edits."""
    opts, operands = _options(args, value="fFveEil", attached="dDoLp", longs=_AWK_LONGS)
    libs = [v for o, v in opts if o in ("-i", "-l", "--include", "--load") and v]
    if not any(_INPLACE_LIB.fullmatch(v) for v in libs):
        return []
    files = [a for a in operands if not _AWK_ASSIGN.match(a)]
    return files if _has(opts, "-f", "--file", "-e", "--source", "-E", "--exec") else files[1:]


# --- editors --------------------------------------------------------------------------------------------------------------

_VIM_LIKE = frozenset({"vim", "vi", "nvim", "rvim", "gvim", "mvim", "vimdiff", "nvi", "ex", "vimx"})
_NANO_LIKE = frozenset({"nano", "rnano", "pico"})
_OTHER_EDITORS = frozenset({"micro", "joe", "kak", "hx", "ne", "red", "mcedit", "ed"})
_EDITORS = _VIM_LIKE | _NANO_LIKE | _OTHER_EDITORS | {"emacs", "emacsclient"}
_NANO_LONGS = {"--rcfile": True, "--operatingdir": True, "--speller": True, "--syntax": True, "--tabsize": True,
               "--quotestr": True, "--fill": True, "--wordchars": True, "--backupdir": True, "--guidestripe": True}
_EMACS_VALUED = frozenset({"-f", "--funcall", "-funcall", "-l", "--load", "-load", "-L", "--directory", "-directory", "-eval",
                           "--eval", "-i", "--insert", "-insert", "-u", "--user", "-user", "-T", "--title", "-title",
                           "--script", "-script", "-D", "-g", "--geometry", "-geometry", "-fn", "--font", "-font", "-bg", "-fg"})


def _editor_files(name: str, args: list[str]) -> list[str]:
    """The files an editor is given: it may write each of them, with or without batch flags (``vim -es``, ``ed -s``)."""
    if name in ("emacs", "emacsclient"):
        out, i = [], 0
        while i < len(args):
            a = args[i]
            i += 1
            if a in _EMACS_VALUED:
                i += 1
            elif not a.startswith(("-", "+")) and a:
                out.append(a)
        return out
    if name in _VIM_LIKE:
        _, operands = _options(args, value="cSuUit", longs={"--cmd": True, "--servername": True, "--startuptime": True})
    elif name in _NANO_LIKE:
        _, operands = _options(args, value="rTYsoXQ", longs=_NANO_LONGS)
    elif name == "ed":
        _, operands = _options(args, value="p", longs={"--prompt": True})
    else:
        _, operands = _options(args)
    return [a for a in operands if a and a != "-" and not a.startswith("+")]


# --- copies and links -----------------------------------------------------------------------------------------------------

_COPY_DEFAULT = {"--target-directory": True, "--suffix": True}
_COPY_OPTIONS: dict[str, tuple[str, dict[str, bool]]] = {
    "cp": ("St", _COPY_DEFAULT), "mv": ("St", _COPY_DEFAULT), "ln": ("St", _COPY_DEFAULT),
    "install": ("mogSt", {**_COPY_DEFAULT, "--mode": True, "--owner": True, "--group": True, "--strip-program": True}),
    "ditto": ("", {}),
    "scp": ("iFoJcDlPSX", {}),
    "rsync": ("efTBM@", {"--rsh": True, "--rsync-path": True, "--exclude": True, "--include": True, "--filter": True,
                         "--port": True, "--bwlimit": True, "--timeout": True, "--exclude-from": True, "--include-from": True,
                         "--files-from": True, "--backup-dir": True, "--suffix": True, "--temp-dir": True,
                         "--partial-dir": True, "--log-file": True, "--chmod": True, "--chown": True, "--max-size": True,
                         "--min-size": True, "--compare-dest": True, "--copy-dest": True, "--link-dest": True,
                         "--password-file": True, "--out-format": True, "--info": True, "--debug": True,
                         "--skip-compress": True, "--compress-level": True, "--block-size": True, "--address": True,
                         "--sockopts": True, "--protocol": True, "--iconv": True, "--max-delete": True,
                         "--modify-window": True, "--usermap": True, "--groupmap": True, "--remote-option": True}),
}
_COPIERS = frozenset(_COPY_OPTIONS)
_REMOTE = re.compile(r"^(?:[\w.+-]{1,64}@)?[\w.-]{1,255}:(?!//)|^[a-z]{2,10}://")


def _in_directory(directory: str, sources: list[str]) -> list[str]:
    """The files ``cp`` makes in ``directory`` from ``sources``: each one's name."""
    names = (s.rstrip("/").rpartition("/")[2] for s in sources)
    return [_join(directory, n) for n in names if n]


def _copy_destination(name: str, args: list[str]) -> list[str]:
    """Where ``cp``, ``mv``, ``ln``, ``install``, ``ditto``, ``rsync`` and ``scp`` put what they copy: the last operand, or the
    directory of ``-t DIR`` / ``--target-directory=DIR`` (with the name of each source in it, since that is the file written).
    A destination on another host is not a path on this machine."""
    short, longs = _COPY_OPTIONS[name]
    opts, operands = _options(args, value=short, longs=longs)
    if name == "install" and _has(opts, "-d", "--directory"):
        return operands   # install -d makes each of its operands a directory
    directory = _last(opts, "-t", "--target-directory")
    if directory is not None:
        return [directory, *_in_directory(directory, operands)]
    if len(operands) < 2:
        return []
    dest = operands[-1]
    if name in ("scp", "rsync") and _REMOTE.match(dest):
        return []
    out = [dest]
    if dest.endswith("/"):   # a directory: the file written is in it
        out += _in_directory(dest, operands[:-1])
    return out


# --- archives -------------------------------------------------------------------------------------------------------------

_TAR_LONGS = {"--file": True, "--directory": True, "--files-from": True, "--exclude-from": True, "--use-compress-program": True,
              "--transform": True, "--xform": True, "--to-command": True, "--index-file": True, "--listed-incremental": True,
              "--label": True, "--newer": True, "--newer-mtime": True, "--blocking-factor": True, "--strip-components": True,
              "--exclude": True, "--owner": True, "--group": True, "--mode": True, "--format": True,
              "--checkpoint-action": True, "--remote-shell": True, "--rmt-command": True, "--add-file": True,
              "--extract": False, "--get": False, "--create": False, "--append": False, "--update": False,
              "--concatenate": False, "--to-stdout": False}


def _tar_writes(args: list[str]) -> list[str]:
    """What ``tar`` writes: the files it extracts (into ``-C DIR`` / ``--directory=DIR``, named by the members it is told to
    extract) and the archive it makes or adds to."""
    if args and not args[0].startswith("-"):
        args = ["-" + args[0], *args[1:]]   # the old spelling: tar xf a.tar
    opts, operands = _options(args, value="fCTXIKLNgVbHF", longs=_TAR_LONGS)
    archive = _last(opts, "-f", "--file")
    if _has(opts, "-x", "--extract", "--get"):
        if _has(opts, "-O", "--to-stdout"):
            return []
        directory = _last(opts, "-C", "--directory")
        if directory is None:
            return [m for m in operands if m and not m.startswith("/")]
        return [directory, *(_join(directory, m) for m in operands if m and not m.startswith("/"))]
    if _has(opts, "-c", "-r", "-u", "-A", "--create", "--append", "--update", "--concatenate") and archive not in (None, "-"):
        return [archive] if archive else []
    return []


def _unzip_writes(args: list[str]) -> list[str]:
    """What ``unzip`` extracts: into ``-d DIR``, the members it is told to extract (up to ``-x``, which lists those it leaves)."""
    opts: list[_Option] = []
    operands: list[str] = []
    i = 0
    excluding = False
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--":
            operands.extend(w for w in args[i:] if not excluding)
            break
        if a.startswith("-") and len(a) > 1:
            excluding = False
            body = a[1:]
            for k, c in enumerate(body):
                rest = body[k + 1:]
                if c in "dP":
                    opts.append(("-" + c, rest or (args[i] if i < len(args) else None)))
                    i += 0 if rest else 1
                    break
                if c == "x":
                    excluding = True
                    break
                opts.append(("-" + c, None))
        elif not excluding:
            operands.append(a)
    if any(o in ("-l", "-t", "-v", "-Z", "-p", "-c", "-z") for o, _ in opts):
        return []   # a listing, a test or output to the terminal
    directory = _last(opts, "-d")
    members = operands[1:]
    if directory is None:
        return [m for m in members if not m.startswith("/")]
    return [directory, *(_join(directory, m) for m in members if not m.startswith("/"))]


# --- find -----------------------------------------------------------------------------------------------------------------

_FIND_RUNS = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_FIND_FILE_OUTPUT = frozenset({"-fprint", "-fprint0", "-fprintf", "-fls"})
# Programs a find may run that only read the files they are given, or change a mode or an owner (not what is in the file).
_FIND_QUIET = frozenset({"cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "wc", "ls", "stat", "file", "du",
                         "md5sum", "sha1sum", "sha256sum", "sha512sum", "shasum", "md5", "diff", "cmp", "test", "[", "echo",
                         "printf", "basename", "dirname", "readlink", "realpath", "strings", "od", "xxd", "hexdump", "nl",
                         "sort", "uniq", "cut", "tr", "true", "false", "chmod", "chown", "chgrp", "bat", "batcat", "tac"})


def _placeholder(words: list[str], marks: tuple[str, ...]) -> list[str]:
    """``words`` with the places where find or fd put a file name filled with one harmless relative name."""
    return [re.sub(r"\{(?:/|//|\.|/\.)?\}", "found", w) if any(m in w for m in marks) else w for w in words]


def _run_by_find(argv: list[str]) -> list[list[str]]:
    """The commands ``find`` runs for each file (``-exec``, ``-execdir``, ``-ok``, ``-okdir``; up to ``;`` or ``{} +``)."""
    out: list[list[str]] = []
    i = 1
    while i < len(argv):
        if argv[i] not in _FIND_RUNS:
            i += 1
            continue
        j = i + 1
        while j < len(argv) and argv[j] != ";" and not (argv[j] == "+" and argv[j - 1].endswith("{}")):
            j += 1
        out.append(_placeholder(argv[i + 1:j], ("{}",)))
        i = j + 1
    return out


def _find_roots(args: list[str]) -> list[str]:
    roots: list[str] = []
    i = 0
    while i < len(args) and args[i].startswith("-") and (args[i] in ("-H", "-L", "-P") or args[i].startswith("-O")
                                                         or args[i] == "-D"):
        i += 2 if args[i] == "-D" else 1
    while i < len(args) and not args[i].startswith("-") and args[i] not in ("(", ")", "!", ","):
        roots.append(args[i])
        i += 1
    return roots


_PARSED = frozenset({"sed", "perl", "ruby", "tar", "unzip", "tee", "find"}) | _AWKS | _EDITORS | _COPIERS | _DISK_COPIERS


def _find_writes(argv: list[str]) -> list[str]:
    """What a ``find`` may write: its root when it deletes or runs a command that may change the files (a root that is a key, an
    access file or a startup file is one the command is aimed at), the paths that command names, and the files ``-fprint`` and
    ``-fls`` make."""
    args = argv[1:]
    out: list[str] = []
    for k, a in enumerate(args[:-1]):
        if a in _FIND_FILE_OUTPUT:
            out.append(args[k + 1])
    runs = _run_by_find(argv)
    loud = [words for words in runs if words and _bin(words[0]) not in _FIND_QUIET]
    if "-delete" in args or loud or any(not words for words in runs):
        out += _find_roots(args)
    for words in loud:   # a program with no rule of its own for its arguments: every file it names may be written
        if _bin(words[0]) not in _PARSED:
            out += [w for w in words[1:] if w and not w.startswith("-") and "found" != w]
    return out


# --- the one question -----------------------------------------------------------------------------------------------------

_IN_PLACE_RUNNERS = {"perl": ("eE", "iIMmxCFdDV"), "ruby": ("eIrCE", "iFKxW")}


def written_paths(name: str, argv: list[str], redirects: list[tuple[str, str]] | None = None) -> list[str]:
    """The paths the command ``argv`` (program ``name``) writes, as written: the targets of its output redirects, and what the
    program does to its arguments (see the module's text). A path it only reads is not here."""
    args = argv[1:]
    out = [t for op, t in redirects or [] if op.startswith(">") and t not in ("/dev/null", "/dev/stderr", "/dev/stdout")]
    if name == "tee":
        out += _options(args)[1]
    elif name in _DISK_COPIERS:
        out += [a[3:] for a in args if a.startswith("of=")]
    elif name in _COPIERS:
        out += _copy_destination(name, args)
    elif name == "sed":
        out += _sed_files(args)
    elif name in _IN_PLACE_RUNNERS:
        out += _script_runner_files(args, *_IN_PLACE_RUNNERS[name])
    elif name in _AWKS:
        out += _awk_files(args)
    elif name in _EDITORS:
        out += _editor_files(name, args)
    elif name == "tar":
        out += _tar_writes(args)
    elif name == "unzip":
        out += _unzip_writes(args)
    elif name == "find":
        out += _find_writes(argv)
    return out
