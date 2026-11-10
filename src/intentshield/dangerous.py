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
are cut. The rules are written from a list of categories, not from any test set. They are text rules: a command built
at run time from pieces (``$(printf ...)``, variables set elsewhere) is not seen, and that is a limit, not a feature.
"""
# ruff: noqa: E501
from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from . import shell

_MAX = 50_000        # characters of one command or file read here
_MAX_STAGES = 400    # simple commands examined
_MAX_DEPTH = 3      # nested bash -c / eval / $(...)

DENY, ASK = "deny", "ask"


@dataclass
class Hit:
    decision: str
    reason: str
    trigger: str = ""   # the path or text a user may have asked for, to soften a deny to an ask


@dataclass
class _Stage:
    argv: list[str]
    redirects: list[tuple[str, str]] = field(default_factory=list)
    piped: bool = False      # its stdin is the previous stage's output
    pipeline: int = 0
    sudo: bool = False
    assigns: list[str] = field(default_factory=list)


# --- parsing ---------------------------------------------------------------------------------------------------

_PUNCT = frozenset("|&;()<>")
_SPLIT_OPS = re.compile(r"<\(|>\(|&&|\|\||\|&|;;|<<<|<<|>>|>&|&>>|&>|<&|<>|>\||[<>|&;()]")
_HEREDOC = re.compile(r"<<-?[ \t]*['\"]?([A-Za-z_][\w-]{0,40})['\"]?")
_SHELL_WORD = re.compile(r"\b(?:ba|z|da|k)?sh\b")
_SUBST = re.compile(r"\$\(([^()]{0,2000})\)|`([^`]{0,2000})`")
_ASSIGN = re.compile(r"^[A-Za-z_]\w{0,60}=")
_FD = re.compile(r"^\d{1,2}$")
_OPS = frozenset({"|", "&&", "||", ";", "&", "|&", ";;", "(", ")", "<(", ">("})
_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>", "<", "<<<", ">&", "<&", "<>"})
_WRAPPERS = frozenset({"nohup", "time", "command", "exec", "nice", "ionice", "setsid", "stdbuf", "caffeinate", "builtin",
                       "timeout", "chronic", "unbuffer", "xargs", "watch", "doas", "env", "sudo"})
_SUDO_VALUED = frozenset({"-u", "-g", "-h", "-p", "-C", "-r", "-t", "-D", "-U", "-T", "--user", "--group", "--host"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "csh", "tcsh"})
_INTERPRETERS = frozenset({"python", "python3", "python2", "perl", "ruby", "node", "php", "deno", "bun", "lua", "pwsh"})
_FETCHERS = frozenset({"curl", "wget", "fetch", "aria2c", "lwp-download", "http", "https", "xh"})


def _bin(word: str) -> str:
    name = PurePosixPath(word).name.lower()
    return re.sub(r"^(python|perl|ruby|php)[\d.]+$", r"\1", name)


def _strip_heredocs(text: str) -> str:
    """Drops here-document bodies (text for a file or a program's stdin) unless the line starts a shell."""
    out, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        m = _HEREDOC.search(line)
        if m and "<<<" not in line[m.start():m.start() + 3]:
            end = i
            while end < len(lines) and lines[end].strip() != m[1]:
                end += 1
            if _SHELL_WORD.search(line):
                out.extend(lines[i:end])
            i = end + 1
    return "\n".join(out)


def _stages(text: str) -> list[_Stage] | None:
    """The simple commands of ``text``, or None when it cannot be tokenized (unbalanced quotes)."""
    text = _strip_heredocs(text[:_MAX]).replace("\r", " ").replace("\n", " ; ")
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        raw = list(lexer)
    except ValueError:  # unbalanced quotes: read it again without them, so a stray quote does not hide a command
        lexer = shlex.shlex(text.replace("'", " ").replace('"', " "), posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        try:
            raw = list(lexer)
        except ValueError:
            return None
    pieces: list[str] = []
    for token in raw[:20_000]:
        if len(token) > 1 and set(token) <= _PUNCT:
            pieces.extend(_SPLIT_OPS.findall(token))
        else:
            pieces.append(token)
    stages: list[_Stage] = []
    argv: list[str] = []
    redirects: list[tuple[str, str]] = []
    piped, pipeline, comment, i = False, 0, False, 0

    def flush() -> None:
        nonlocal argv, redirects, piped
        if argv or redirects:
            stages.append(_Stage(argv, redirects, piped, pipeline))
        argv, redirects, piped = [], [], False

    while i < len(pieces) and len(stages) < _MAX_STAGES:
        token = pieces[i]
        i += 1
        if token in _OPS:
            flush()
            if token in ("|", "|&"):
                piped = True
            elif token != "(" and token != ")":
                pipeline += 1
            comment = False
            continue
        if comment:
            continue
        if token.startswith("#") and not argv:
            comment = True
            continue
        if token in _REDIRECTS:
            target = pieces[i] if i < len(pieces) else ""
            if target not in _OPS and target not in _REDIRECTS:
                i += 1
                redirects.append((token, target))
            if argv and _FD.match(argv[-1]) and token.startswith(("<", ">")):
                argv.pop()
            continue
        argv.append(token)
    flush()
    # a stage "piped" only when a pipe, not another operator, came right before it
    return stages


def _unwrap(stage: _Stage) -> tuple[_Stage, list[str]]:
    """Strips assignments, sudo, env, nohup, time... from the front. Returns the bare stage and notes (the text a
    ``-c`` or ``eval`` runs is returned in ``inner``)."""
    argv = list(stage.argv)
    sudo, assigns = stage.sudo, list(stage.assigns)
    inner: list[str] = []
    for _ in range(8):
        while argv and _ASSIGN.match(argv[0]):
            assigns.append(argv.pop(0))
        if not argv:
            break
        name = _bin(argv[0])
        if name not in _WRAPPERS:
            break
        argv.pop(0)
        sudo = sudo or name in ("sudo", "doas")
        while argv and argv[0].startswith("-") and argv[0] != "--":
            flag = argv.pop(0)
            if name in ("sudo", "doas") and flag in _SUDO_VALUED and argv:
                argv.pop(0)
            elif name in ("env",) and flag in ("-u", "-C", "-S") and argv:
                argv.pop(0)
            elif name in ("nice", "ionice") and flag in ("-n", "-c") and argv:
                argv.pop(0)
        if argv and argv[0] == "--":
            argv.pop(0)
        if name == "timeout" and argv:
            argv.pop(0)
        if name == "nice" and argv and argv[0].lstrip("+-").isdigit():
            argv.pop(0)
    return _Stage(argv, stage.redirects, stage.piped, stage.pipeline, sudo, assigns), inner


# --- paths -----------------------------------------------------------------------------------------------------

_HOME = re.compile(r"^(?:\$\{?(?:HOME|USERPROFILE)\}?|~[\w.-]{0,32}|/Users/[^/]+|/home/[^/]+|/root|/var/root)(?=/|$)")
_GLOB_TAIL = re.compile(r"/(?:\.?\*{1,2}|\.\[!\.\]\*|\.\[\^\.\]\*|\.\?\*)$")
_SYSTEM_ROOTS = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var", "/boot", "/System", "/Library", "/opt", "/private",
                 "/dev", "/sys", "/proc", "/Applications", "/srv", "/mnt", "/Volumes", "/Users", "/home", "/root", "/snap")
_PROTECTED = frozenset({"/", "~", *_SYSTEM_ROOTS, "/usr/bin", "/usr/lib", "/usr/local", "/usr/local/bin", "/usr/sbin",
                        "/usr/share", "/var/lib", "/var/log", "/var/root", "/System/Library", "/Library/Frameworks",
                        "/private/etc", "/private/var", "/etc/ssh", "/lib/modules"})
_HOME_DIRS = frozenset({"Documents", "Desktop", "Downloads", "Pictures", "Music", "Movies", "Library", "Developer", ".ssh",
                        ".aws", ".gnupg", ".config", ".kube", ".local"})


_HOME_HEAD = re.compile(r"^(?:~[\w.-]{0,32}|\$\{?(?:HOME|USERPROFILE)\}?)(?=/|$)")


def _norm(path: str) -> str:
    """A path with the home directory as ``~``, ``..`` resolved and a trailing glob removed: ``/Users/x/../x/*`` is ``~``."""
    p = path.strip().strip("\"'")
    if not p:
        return ""
    head = _HOME_HEAD.match(p)
    if head:
        stack: list[str] = []
        for seg in p[head.end():].split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if not stack:
                    return "/Users"  # above the home directory
                stack.pop()
            else:
                stack.append(seg)
        p = "/".join(["~", *stack])
    else:
        p = posixpath.normpath("/" + p.lstrip("/")) if p.startswith("/") else posixpath.normpath(p)
        m = _HOME.match(p)
        if m:
            p = "~" + p[m.end():]
    for _ in range(3):
        stripped = _GLOB_TAIL.sub("", p)
        if stripped == p:
            break
        p = stripped or "/"
    return p or "/"


def _protected(path: str) -> bool:
    p = _norm(path)
    if p in _PROTECTED:
        return True
    if p.startswith("~/") and p[2:] in _HOME_DIRS:
        return True
    return False


def _system(path: str) -> bool:
    p = _norm(path)
    return any(p == r or p.startswith(r + "/") for r in _SYSTEM_ROOTS if r not in ("/Users", "/home", "/root", "/mnt", "/Volumes", "/srv"))


_DEVICE = re.compile(r"^/dev/(?:r?disk\d|sd[a-z]|hd[a-z]|nvme\d|mmcblk\d|vd[a-z]|xvd[a-z]|md\d|dm-\d|loop\d|mapper/|sr\d|"
                     r"disk/|zd\d|mtd|ram\d)")
_SAFE_DEVICE = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty", "/dev/zero", "/dev/random",
                          "/dev/urandom"})


def _device(path: str) -> bool:
    return bool(_DEVICE.match(path)) and path not in _SAFE_DEVICE


def _is_empty_var_target(arg: str) -> bool:
    """``$DIR``, ``$DIR/``, ``${DIR}/*``: whatever the variable holds, the target is that, and an empty one is root."""
    m = re.fullmatch(r"\"?\$\{?[A-Za-z_]\w{0,40}\}?\"?(?:/\*?)?", arg)
    return bool(m) and not re.match(r"\"?\$\{?(?:HOME|USERPROFILE)\b", arg)


# --- credential stores -----------------------------------------------------------------------------------------

_KEY_NAME = re.compile(r"^(?:id_(?:rsa|dsa|ecdsa|ed25519|ecdsa_sk|ed25519_sk)|identity|[\w.-]{1,40}_(?:rsa|dsa|ecdsa|ed25519))$")
_ENV_FILE = re.compile(r"^(?:\.env(?:\.[\w-]{1,30})?|[\w-]{1,30}\.env)$")
_ENV_SAMPLE = re.compile(r"\.(?:example|sample|template|dist|defaults|schema|tpl|md)$")
_CLOUD_FILES = re.compile(r"(?:^|/)(?:\.aws/(?:credentials|sso/cache|cli/cache)|\.vault-token|\.config/gcloud/"
                          r"(?:credentials\.db|access_tokens\.db|application_default_credentials\.json|legacy_credentials)|"
                          r"\.gnupg/(?:private-keys-v1\.d|secring\.gpg|trustdb\.gpg)|library/keychains|\.local/share/keyrings)")
_SOFT_FILES = re.compile(r"(?:^|/)(?:\.kube/config|\.docker/config\.json|\.npmrc|\.pypirc|\.azure/(?:accesstokens|msal)|"
                         r"\.config/gcloud|\.config/gh/hosts\.yml|\.config/hub|\.terraform\.d/credentials|\.heroku/|"
                         r"\.config/doctl|\.config/op/|\.pgpass|\.my\.cnf|\.s3cfg|\.boto|\.gnupg|\.password-store/|\.cargo/credentials|"
                         r"\.config/rclone/rclone\.conf|\.oci/config|\.git-credentials)")
_ETC_SECRET = re.compile(r"^/(?:private/)?etc/(?:shadow|gshadow|master\.passwd|sudoers(?:\.d/[\w.-]+)?|ssh/ssh_host_[\w_]+_key)$")
_PROC_SECRET = re.compile(r"^/proc/(?:self|\d{1,8})/(?:environ|mem|maps)$")
_BROWSER = re.compile(r"(?:chrome|chromium|firefox|mozilla|brave|safari|microsoft edge|vivaldi)")
_BROWSER_FILE = re.compile(r"(?:^|/)(?:login data|cookies|cookies\.sqlite|logins\.json|key[34]\.db|web data)$")
_KEYISH = re.compile(r"\.(?:pem|p12|pfx|ppk|key|keystore|jks|asc)$")
_APP_SECRET = re.compile(r"(?:^|/)(?:credentials\.json|client_secrets?[\w-]{0,20}\.json|service[-_]?account[\w-]{0,30}\.json|"
                         r"secrets\.(?:ya?ml|json|toml)|terraform\.tfstate|[\w-]{1,30}\.tfvars)$")


def _cred_level(path: str) -> tuple[str, str] | None:
    """(decision, what) when ``path`` names a credential store."""
    if not path or len(path) > 1000:
        return None
    n = _norm(path).lower() if path.startswith(("~", "$", "/")) else posixpath.normpath(path.strip()).lower()
    raw = path.strip().lower()
    base = n.rpartition("/")[2]
    if _ETC_SECRET.match(n) or _PROC_SECRET.match(n):
        return DENY, "a system secret file"
    if base.endswith(".pub"):
        return None
    if _CLOUD_FILES.search(n):
        return DENY, "a cloud credential store or keychain"
    if "/.ssh/" in "/" + n + "/" or n.endswith("/.ssh") or n == ".ssh" or n.startswith(".ssh/"):
        if base in ("known_hosts", "config", "authorized_keys", "known_hosts.old") or n.endswith(".ssh/*"):
            return (DENY, "the SSH directory") if n.endswith(".ssh/*") or raw.endswith(".ssh/*") else None
        return DENY, "an SSH private key" if base != ".ssh" else "the SSH directory"
    if _KEY_NAME.match(base):
        return DENY, "an SSH private key"
    if base in (".netrc", "_netrc"):
        return DENY, "~/.netrc"
    if _SOFT_FILES.search(n):
        return ASK, "a credential file"
    if _ENV_FILE.match(base) and not _ENV_SAMPLE.search(base):
        return ASK, "an environment file"
    if _BROWSER_FILE.search(n) and _BROWSER.search(n):
        return ASK, "a browser credential store"
    if _KEYISH.search(base) or _APP_SECRET.search(n):
        return ASK, "a key or secret file"
    return None


# Programs that read a file argument and show or pass on what is in it.
_READERS = frozenset({"cat", "bat", "batcat", "less", "more", "most", "head", "tail", "tac", "nl", "od", "xxd", "hexdump", "hd",
                      "strings", "base64", "openssl", "cp", "rsync", "scp", "tar", "zip", "7z", "7za", "gzip", "bzip2", "xz",
                      "zstd", "cut", "sort", "uniq", "tee", "paste", "rev", "fold", "grep", "egrep", "fgrep", "rg", "ag", "ack",
                      "awk", "gawk", "sed", "open", "vim", "vi", "nano", "emacs", "code", "view", "pbcopy", "xclip", "diff",
                      "cmp", "jq", "yq", "sqlite3", "split", "dd", "curl", "wget", "ditto", "cpio", "pax", "ln", "install",
                      "mail", "mailx", "sendmail", "ftp", "sftp", "nc", "ncat", "netcat", "socat", "base32", "uuencode",
                      "gpg", "age", "find", "xargs", "type", "echo-file", "source", "."})
_PATTERN_FIRST = frozenset({"grep", "egrep", "fgrep", "rg", "ag", "ack", "awk", "gawk", "sed"})
_CRED_TEXT = re.compile(r"\.ssh/(?:id_|\w{1,20}_rsa)|\.aws/credentials|\.netrc|/etc/shadow|\.vault-token|library/keychains|"
                        r"\.gnupg/private-keys|\.config/gcloud/(?:credentials|application_default)", re.I)
_CLI_SECRETS = (
    (("security", "find-generic-password"), DENY), (("security", "find-internet-password"), DENY),
    (("security", "dump-keychain"), DENY), (("security", "export"), DENY),
    (("gpg", "--export-secret-keys"), DENY), (("gpg2", "--export-secret-keys"), DENY),
    (("git", "credential", "fill"), DENY), (("git", "credential-osxkeychain", "get"), DENY),
    (("gcloud", "auth", "print-access-token"), ASK), (("gcloud", "auth", "print-identity-token"), ASK),
    (("gcloud", "auth", "application-default", "print-access-token"), ASK),
    (("aws", "configure", "get"), ASK), (("aws", "configure", "export-credentials"), ASK),
    (("aws", "sts", "get-session-token"), ASK), (("aws", "sts", "assume-role"), ASK),
    (("az", "account", "get-access-token"), ASK), (("gh", "auth", "token"), ASK), (("gh", "auth", "status", "-t"), ASK),
    (("gh", "auth", "status", "--show-token"), ASK), (("kubectl", "config", "view", "--raw"), ASK),
    (("kubectl", "get", "secret"), ASK), (("kubectl", "get", "secrets"), ASK), (("heroku", "auth:token"), ASK),
    (("fly", "auth", "token"), ASK), (("npm", "token", "list"), ASK), (("vault", "read"), ASK), (("vault", "kv", "get"), ASK),
    (("op", "read"), ASK), (("op", "item", "get"), ASK), (("doppler", "secrets"), ASK), (("pass", "show"), ASK),
    (("lpass", "show"), ASK), (("terraform", "show"), ASK), (("docker", "config"), ASK), (("pulumi", "config", "get"), ASK),
)


def _in_order(argv: list[str], needle: tuple[str, ...]) -> bool:
    it = iter(argv)
    return all(any(token == want for token in it) for want in needle)


def _candidates(arg: str) -> list[str]:
    """The paths one argument may carry: itself, the part after ``=`` (``if=file``) and after ``@`` (``-F f=@file``)."""
    out = [arg]
    for sep in ("=", "@"):
        if sep in arg:
            out.append(arg.rpartition(sep)[2])
    return out


def _cred_args(argv: list[str]) -> tuple[str, str, str] | None:
    """(decision, what, path) for the first credential path among the arguments of a reading program."""
    args = argv[1:]
    name = _bin(argv[0])
    if name in ("cp", "mv", "ln", "install", "rsync", "scp", "ditto"):  # the last path is where it goes, not what it reads
        positional = [i for i, a in enumerate(args) if not a.startswith("-")]
        if len(positional) > 1:
            args = args[:positional[-1]] + args[positional[-1] + 1:]
    if name in _PATTERN_FIRST and not any(a in ("-e", "-f", "--regexp", "--file") or a.startswith(("-e", "--regexp=")) for a in args):
        skipped = False
        trimmed = []
        for a in args:
            if not skipped and not a.startswith("-"):
                skipped = True
                continue
            trimmed.append(a)
        args = trimmed
    best = None
    for a in args:
        if a.startswith("-") and "=" not in a and "@" not in a:
            continue
        for c in _candidates(a):
            hit = _cred_level(c)
            if hit and (best is None or hit[0] == DENY and best[0] != DENY):
                best = (hit[0], hit[1], c)
    return best


# --- the rules ---------------------------------------------------------------------------------------------------

_FORK_BOMB = re.compile(r"([\w:.-]{1,40})\s{0,3}\(\s{0,3}\)\s{0,3}\{[^}]{0,120}?\|\s{0,3}[\w:.-]{1,40}\s{0,3}&?[^}]{0,60}\}")
_FORK_LOOP = re.compile(r"\bwhile\s+(?:true|:|\[\s{0,3}1\s{0,3}\]|\(\(\s{0,3}1\s{0,3}\)\))\s{0,3};\s{0,3}do\s[^;&|]{0,60}"
                        r"(?:\$0|\bsh\b|\bbash\b|\bzsh\b|\byes\b|\$SHELL)[^;|]{0,40}&\s{0,3}(?:;\s{0,3})?done")
_FORK_CODE = re.compile(r"os\.fork\(\)|\bfork\s+while\b|while\s*\(?\s*(?:1|true)\s*\)?\s*[{:]?\s*(?:os\.)?fork\b|"
                        r"forkbomb|:\(\)\s*\{", re.I)
_PIPE_SHELL_SUBST = re.compile(r"(?:\b(?:ba|z|da|k)?sh|\beval|\bsource|\bpython3?|\bperl|\bruby|\bnode|\.)\s{1,5}"
                               r"(?:-[a-z]{1,3}\s{1,5})?(?:[\"']?\$\(|<\(|[\"']?`)\s{0,5}(?:sudo\s{1,5})?(?:curl|wget|fetch)\b")
_REVERSE_SHELL = re.compile(r"/dev/(?:tcp|udp)/[^\s/'\"]{1,100}/\d{1,5}|\bnc(?:at)?\s[^;|&]{0,60}-[a-z]{0,4}[ec]\s|"
                            r"\bsocat\b[^;|&]{0,80}\bexec:|\bbash\s{1,4}-i\s{1,4}>&|\bsh\s{1,4}-i\s{1,4}>&", re.I)
_REVERSE_STRICT = re.compile(r"(?:\bbash|\bsh|\bzsh)\s{1,4}-i\s{1,4}>&?\s{0,3}/dev/(?:tcp|udp)/|\bnc(?:at)?\s[^;|&]{0,60}\s-[a-z]{0,4}[ec]\s{1,4}"
                             r"[\w/.-]{1,40}\b|\bsocat\b[^;|&]{0,80}\bexec:|\bexec\s{1,4}\d{1,2}<>\s{0,3}/dev/(?:tcp|udp)/", re.I)

_RM_SHORT_RECURSIVE = frozenset("rR")
_PROTECTED_BRANCH = re.compile(r"^(?:main|master|develop|development|dev|trunk|prod|production|stable|staging|release|"
                               r"release[/-][\w.-]{1,40}|releases/[\w.-]{1,40}|hotfix|next|latest|HEAD)$")
_WORLD_WRITABLE = re.compile(r"^[0-7]?[0-7]{2}[2367]$|(?:^|,)(?:[ao]|ugo)[+=][rwxXst]{0,4}w|^a[+=]rwx|^[+=]rwx")
_SETUID = re.compile(r"^[4-7][0-7]{3}$|(?:^|,)[ugo]{0,3}\+[rwxXt]{0,3}s")
_CRON = re.compile(r"(?:^|/)(?:etc/(?:cron[\w.]*|anacrontab)|var/(?:spool/cron|at/tabs)|crontab)(?:/|$)")
_PERSIST = re.compile(
    r"(?:^|/)(?:\.(?:bash|zsh|ksh|csh|tcsh)rc|\.bash_(?:profile|login|logout|aliases)|\.profile|\.zprofile|\.zshenv|\.zlogin|"
    r"\.zlogout|\.zsh_?aliases|\.config/fish/(?:config\.fish|conf\.d/)|\.oh-my-zsh/custom/|\.envrc|etc/(?:profile|bashrc|zshrc|zshenv|"
    r"environment|bash\.bashrc|rc\.local|zsh/|profile\.d/|init\.d/|ld\.so\.preload|launchd\.conf)|"
    r"library/launch(?:agents|daemons)/|etc/systemd/|lib/systemd/|\.config/systemd/|\.config/autostart/|"
    r"\.git/(?:hooks/|config$)|\.githooks/|\.husky/|\.git/modules/[\w./-]{0,200}hooks/|"
    r"\.github/(?:workflows|actions)/|\.github/dependabot\.ya?ml|\.gitlab-ci\.ya?ml|\.gitlab/|\.circleci/|jenkinsfile|"
    r"azure-pipelines\.ya?ml|\.travis\.ya?ml|bitbucket-pipelines\.ya?ml|\.buildkite/|\.drone\.ya?ml|cloudbuild\.ya?ml|"
    r"\.woodpecker/|\.ssh/(?:authorized_keys2?|config|rc|environment))", re.I)
_PERSIST_DENY = re.compile(r"(?:^|/)(?:\.ssh/authorized_keys2?|etc/sudoers(?:\.d/[\w.-]+)?|etc/(?:passwd|shadow)|etc/ld\.so\.preload)$", re.I)
_MALICIOUS_CONTENT = re.compile(
    r"\b(?:curl|wget)\b[^|;\n]{0,300}\|\s{0,3}(?:sudo\s{1,3})?(?:ba|z|da)?sh\b|/dev/(?:tcp|udp)/|\bnc(?:at)?\s[^\n;|&]{0,60}-[a-z]{0,4}e\s|"
    r"\bbase64\s{1,3}(?:-d|--decode|-D)\b[^|;\n]{0,100}\|\s{0,3}(?:ba|z)?sh\b|\bmkfifo\b[^\n]{0,80}\bnc\b|"
    r"\bssh-(?:rsa|ed25519)\s{1,3}AAAA[\w+/]{20,}", re.I)


def persistence_path(path: str) -> tuple[str, str] | None:
    """(decision, why) when writing ``path`` sets up code that runs later or changes who can log in."""
    n = _norm(path).lower() if path.startswith(("~", "$", "/")) else path.strip().replace("\\", "/").lower()
    if not n or len(n) > 1000:
        return None
    if _PERSIST_DENY.search(n):
        return DENY, "an access file (authorized_keys, sudoers, passwd)"
    if _PERSIST.search(n) or _CRON.search(n):
        return ASK, "a file that runs code later (shell startup, cron, launchd, systemd, a git hook or a CI workflow)"
    return None


def path_risk(path: str) -> bool:
    """True for a path the file rules look at."""
    return bool(_cred_level(path) or persistence_path(path))


def _git(argv: list[str]) -> tuple[str, list[str], list[str]]:
    """(subcommand, its arguments, the ``-c k=v`` settings) of a git command."""
    args, settings, i = argv[1:], [], 0
    while i < len(args):
        a = args[i]
        if a == "-c" and i + 1 < len(args):
            settings.append(args[i + 1])
            i += 2
        elif a in ("-C", "--git-dir", "--work-tree", "--namespace", "--exec-path") and i + 1 < len(args):
            i += 2
        elif a.startswith("-c") and len(a) > 2 and "=" in a:
            settings.append(a[2:])
            i += 1
        elif a.startswith("-"):
            i += 1
        else:
            return a, args[i + 1:], settings
    return "", [], settings


def _branch(ref: str) -> str:
    ref = ref.lstrip("+")
    ref = ref.rpartition(":")[2] if ":" in ref else ref
    ref = ref.removeprefix("refs/heads/")
    return ref


def _git_hit(argv: list[str], assigns: list[str]) -> Hit | None:
    sub, args, settings = _git(argv)
    flags = [a for a in args if a.startswith("-")]
    hooks = [s for s in settings if s.lower().startswith(("core.hookspath", "core.fsmonitor"))]
    if hooks:
        return Hit(ASK, "git run with a hooks path or fsmonitor override, which bypasses or replaces the repository's hooks.")
    if any(a.split("=")[0].upper() in ("HUSKY", "HUSKY_SKIP_HOOKS", "SKIP", "PRE_COMMIT_ALLOW_NO_CONFIG") for a in assigns):
        return Hit(ASK, "git run with the hook-skipping environment variable set.")
    if sub in ("commit", "push", "merge", "am", "cherry-pick", "rebase", "revert") and "--no-verify" in args:
        return Hit(ASK, f"git {sub} --no-verify skips the repository's hooks.")
    if sub == "commit":
        for a in flags:
            if a.startswith("--"):
                continue
            for ch in a[1:]:
                if ch in "mFcCtSu":
                    break
                if ch == "n":
                    return Hit(ASK, "git commit -n skips the repository's pre-commit hooks.")
    if sub == "config" and any(a.lower().startswith("core.hookspath") for a in args):
        return Hit(ASK, "git config core.hooksPath replaces the repository's hooks.")
    if sub == "push":
        pos = [a for a in args if not a.startswith("-")]
        refs = pos[1:]
        forced = any(a in ("-f", "--force") or a.startswith(("--force-with-lease", "--force-if-includes")) for a in flags) or any(
            len(a) > 1 and a[0] == "-" and a[1] != "-" and "f" in a[1:] and "n" not in a[1:] for a in flags) or any(
            r.startswith("+") for r in refs)
        deleting = "--delete" in flags or "-d" in flags or any(r.startswith(":") for r in refs)
        branches = {_branch(r) for r in refs}
        protected = any(_PROTECTED_BRANCH.match(b) for b in branches) or any(
            _PROTECTED_BRANCH.match(b) for b in {_branch(r.partition(":")[0]) for r in refs if ":" in r})
        if "--mirror" in flags:
            return Hit(ASK, "git push --mirror overwrites every ref of the remote.")
        if (forced or deleting) and protected:
            return Hit(DENY, "force-push or deletion of a shared branch rewrites history others build on.")
        if forced or deleting:
            return Hit(ASK, "git force-push or branch deletion on the remote rewrites or removes history; confirm it.")
    if sub in ("filter-branch", "filter-repo"):
        return Hit(ASK, f"git {sub} rewrites the whole history.")
    if sub == "reset" and "--hard" in args:
        return Hit(ASK, "git reset --hard discards uncommitted work and moves the branch.")
    if sub == "clean" and any(a.startswith("-") and not a.startswith("--") and "f" in a for a in args) or (
            sub == "clean" and "--force" in args):
        return Hit(ASK, "git clean -f deletes untracked files for good.")
    if sub == "reflog" and "expire" in args or sub == "gc" and any(a.startswith("--prune=now") for a in args):
        return Hit(ASK, "this removes the reflog or unreachable commits, the way back from a bad rewrite.")
    if sub == "update-ref" and "-d" in args:
        return Hit(ASK, "git update-ref -d deletes a ref.")
    if sub == "branch" and any(a in ("-D", "-d", "--delete") for a in flags) and any(_PROTECTED_BRANCH.match(a) for a in args if not a.startswith("-")):
        return Hit(DENY, "deleting a shared branch.")
    if sub == "checkout" and args and args[-1] in (".", "--") or sub == "restore" and "." in args:
        return Hit(ASK, "this discards every uncommitted change in the tree.")
    return None


def _rm_hit(argv: list[str], sudo: bool) -> Hit | None:
    flags, targets, done = [], [], False
    for a in argv[1:]:
        if not done and a == "--":
            done = True
        elif not done and a.startswith("-") and len(a) > 1:
            flags.append(a)
        else:
            targets.append(a)
    recursive = any(a in ("--recursive",) or (not a.startswith("--") and any(c in _RM_SHORT_RECURSIVE for c in a[1:])) for a in flags)
    force = any(a == "--force" or (not a.startswith("--") and "f" in a[1:]) for a in flags)
    if "--no-preserve-root" in flags and any(_norm(t) == "/" for t in targets):
        return Hit(DENY, "rm --no-preserve-root on /.", "/")
    if not recursive and not (force and len(targets) > 0 and any(_norm(t) in ("/", "~") for t in targets)):
        return None
    for t in targets:
        if _protected(t):
            return Hit(DENY, f"recursive delete of {t}, a root, home or system directory.", t)
        if sudo and _system(t) and _norm(t).count("/") <= 2:
            return Hit(DENY, f"sudo recursive delete inside the system directory {t}.", t)
    for t in targets:
        if _is_empty_var_target(t) and (force or recursive):
            return Hit(ASK, f"recursive delete of {t}: if the variable is empty this is the root directory.", t)
        if _norm(t) in (".", "*", "..", "../..") or t in ("*", ".*", "./*", "../*", ".", ".."):
            return Hit(ASK, f"recursive delete of {t} removes everything in or above the working directory.", t)
    return None


def _find_hit(argv: list[str]) -> Hit | None:
    args = argv[1:]
    starts = []
    for a in args:
        if a.startswith("-") or a in ("(", "!", ")"):
            break
        starts.append(a)
    if "-delete" in args or ("-exec" in args and any(_bin(a) in ("rm", "shred", "unlink") for a in args)):
        for s in starts:
            if _protected(s):
                return Hit(DENY, f"find {s} deletes everything under a root, home or system directory.", s)
    return None


def _disk_hit(name: str, argv: list[str], sudo: bool) -> Hit | None:
    args = argv[1:]
    dev = [a for a in args if _device(a)]
    if name == "dd":
        for a in args:
            if a.startswith("of=") and _device(a[3:]):
                return Hit(DENY, f"dd writes to the block device {a[3:]}.", a[3:])
        return None
    if name.startswith("mkfs") or name in ("mke2fs", "mkswap", "mkdosfs", "mkntfs", "newfs", "mkfs.ext4") or name.startswith("newfs_"):
        return Hit(DENY, f"{name} formats {dev[0]}.", dev[0]) if dev else None
    if name == "wipefs":
        return Hit(DENY, "wipefs erases filesystem signatures.", dev[0] if dev else "")
    if name == "shred":
        return Hit(DENY, f"shred overwrites the device {dev[0]}.", dev[0]) if dev else Hit(ASK, "shred destroys files for good.")
    if name in ("blkdiscard", "ddrescue", "dcfldd", "pv") and dev and name != "pv":
        return Hit(DENY, f"{name} writes over {dev[0]}.", dev[0])
    if name == "diskutil" and args:
        verbs = {"erasedisk", "erasevolume", "reformat", "zerodisk", "randomdisk", "secureerase", "partitiondisk",
                 "splitpartition", "mergepartitions", "deletecontainer", "deletevolume"}
        if any(a.lower() in verbs for a in args) or (args[0].lower() in ("apfs", "corestorage") and any(
                a.lower() in ("deletecontainer", "deletevolume", "delete", "erasevolume") for a in args)):
            return Hit(DENY, "diskutil erases or repartitions a disk.")
    if name in ("sgdisk", "sfdisk", "gdisk", "fdisk", "cfdisk", "parted") and dev:
        if any(a in ("--zap-all", "-Z", "--zap", "mklabel", "rm", "mkpart", "--delete", "-o", "--clear") for a in args):
            return Hit(DENY, f"{name} rewrites the partition table of {dev[0]}.", dev[0])
        return Hit(ASK, f"{name} edits the partition table of {dev[0]}.", dev[0])
    if name == "hdparm" and any(a.startswith(("--security-erase", "--trim-sector", "--security-set-pass", "--yes-i-know")) for a in args):
        return Hit(DENY, "hdparm security-erase destroys the disk.")
    if name == "nvme" and "format" in args or name == "cryptsetup" and any(a in ("luksFormat", "erase", "luksErase") for a in args):
        return Hit(DENY, f"{name} destroys the device's data.")
    if name in ("zpool", "zfs") and "destroy" in args or name in ("lvremove", "vgremove", "pvremove"):
        return Hit(DENY if name in ("zpool", "zfs") else ASK, f"{name} removes storage.")
    if name in ("cp", "mv", "tee", "cat", "pv", "install") and name != "cat":
        pos = [a for a in args if not a.startswith("-")]
        if name == "tee":
            hit = [a for a in pos if _device(a)]
        else:
            hit = [pos[-1]] if pos and _device(pos[-1]) else []
        if hit:
            return Hit(DENY, f"{name} writes to the block device {hit[0]}.", hit[0])
    return None


def _mode_hit(name: str, argv: list[str], sudo: bool) -> Hit | None:
    flags = [a for a in argv[1:] if a.startswith("-") and len(a) > 1 and not a[1:].isdigit()]
    pos = [a for a in argv[1:] if a not in flags]
    recursive = any(a == "--recursive" or (not a.startswith("--") and "R" in a[1:]) for a in flags)
    if not pos:
        return None
    mode, targets = pos[0], pos[1:]
    if name == "chmod" and mode.startswith("-") and len(pos) > 1:
        mode, targets = pos[1], pos[2:]
    if name in ("chown", "chgrp") and any(a.startswith("--reference") for a in argv[1:]):
        targets = pos
    prot = [t for t in targets if _protected(t)]
    syst = [t for t in targets if _system(t)]
    note = " (with sudo)" if sudo else ""
    if name == "chmod":
        bad = bool(_WORLD_WRITABLE.search(mode)) or mode in ("000", "0000", "a-rwx", "ugo-rwx", "a=")
        if bad and recursive and prot:
            return Hit(DENY, f"recursive chmod {mode} on {prot[0]}{note}.", prot[0])
        if bad and syst:
            return Hit(ASK, f"chmod {mode} on the system path {syst[0]}{note}.", syst[0])
        if bad and recursive and _WORLD_WRITABLE.search(mode):
            return Hit(ASK, f"recursive chmod {mode} makes the whole tree world-writable.")
        if _WORLD_WRITABLE.search(mode) and re.fullmatch(r"0?777|a\+rwx|ugo\+rwx", mode):
            return Hit(ASK, f"chmod {mode} makes files writable by everyone.")
        if _SETUID.search(mode) and targets:
            return Hit(ASK, f"chmod {mode} sets a setuid or setgid bit{note}.")
        return None
    if recursive and prot and (_norm(prot[0]) != "~" or sudo) and any(_norm(t) != "~" for t in prot):
        return Hit(DENY, f"recursive {name} on {prot[0]}{note}.", prot[0])
    if recursive and prot:
        return Hit(ASK, f"recursive {name} on the home directory{note}.", prot[0])
    if syst:
        return Hit(ASK, f"{name} on the system path {syst[0]}{note}.", syst[0])
    return None


_PERSIST_WRITERS = frozenset({"cp", "mv", "ln", "install", "rsync", "ditto", "dd"})


def _persist_hit(name: str, argv: list[str], stage: _Stage) -> Hit | None:
    args = argv[1:]
    targets = [t for op, t in stage.redirects if op.startswith(">") and t not in ("/dev/null", "/dev/stderr", "/dev/stdout")]
    pos = [a for a in args if not a.startswith("-")]
    if name == "tee":
        targets += pos
    elif name in _PERSIST_WRITERS:
        if name == "dd":
            targets += [a[3:] for a in args if a.startswith("of=")]
        elif pos:
            targets.append(pos[-1])
    elif name in ("sed", "perl", "ruby", "python3") and any(a.startswith("-i") or a == "--in-place" for a in args):
        targets += pos[1:] if name == "sed" else pos
    elif name == "touch" or name == "chmod":
        targets += []
    elif name == "crontab":
        if not any(a == "-l" for a in args):
            return Hit(ASK, "crontab installs or removes scheduled jobs.")
    elif name == "launchctl" and any(a in ("load", "bootstrap", "submit", "enable", "bootout", "unload", "kickstart") for a in args):
        return Hit(ASK, "launchctl loads or changes a launch agent or daemon.")
    elif name == "systemctl" and any(a in ("enable", "link", "mask", "edit", "preset") for a in args):
        return Hit(ASK, "systemctl enables or edits a unit that starts later.")
    elif name in ("at", "batch", "atq"):
        return Hit(ASK, "at schedules a job.") if name != "atq" else None
    elif name == "gh" and "secret" in args and any(a in ("set", "delete", "remove") for a in args):
        return Hit(ASK, "gh secret changes a repository's CI secrets.")
    elif name == "defaults" and "write" in args and any("LoginItems" in a or "loginwindow" in a for a in args):
        return Hit(ASK, "defaults write sets up a login item.")
    for t in targets:
        hit = persistence_path(t)
        if hit:
            return Hit(hit[0], f"writes {t}, {hit[1]}.", t)
    return None


_REMOTE = re.compile(r"^(?:[\w.+-]{1,64}@)?[\w.-]{1,255}:(?!//)[^\s]*$|^[a-z]{2,10}://")
_URL = re.compile(r"[a-z][a-z0-9+.-]{1,10}://[^\s'\"<>]{1,500}", re.I)
_CURL_DATA = frozenset({"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "-F", "--form",
                        "--form-string", "-T", "--upload-file", "--json"})
_NET_SINKS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "sftp", "rsync", "ssh", "ftp", "telnet", "http", "https",
                        "xh", "rclone", "gsutil", "mail", "mailx", "sendmail", "aws", "az"})


def _remote_hosts(argv: list[str]) -> list[str]:
    """Hosts the arguments reach that are not this machine."""
    hosts = []
    for a in argv[1:]:
        for url in _URL.findall(a) or ([a] if "." in a and not a.startswith(("-", "/", ".", "~")) and "/" not in a.split(":")[0] else []):
            for v in shell.network_values(url):
                if not shell.is_loopback(v):
                    hosts.append(shell.host(v))
    return hosts


def _data_files(name: str, argv: list[str]) -> list[str]:
    """Files a curl or wget command sends: ``-d @f``, ``-F x=@f``, ``-T f``, ``--post-file f``."""
    out, args = [], argv[1:]
    for i, a in enumerate(args):
        val = None
        if a in _CURL_DATA and i + 1 < len(args):
            val = args[i + 1]
            if a in ("-T", "--upload-file"):
                out.append(val)
                continue
        elif a.startswith(("--data", "--form", "--json", "--upload-file=")) and "=" in a:
            val = a.partition("=")[2]
            if a.startswith("--upload-file="):
                out.append(val)
                continue
        elif a.startswith("--post-file=") or a.startswith("--body-file="):
            out.append(a.partition("=")[2])
            continue
        elif a in ("--post-file", "--body-file") and i + 1 < len(args):
            out.append(args[i + 1])
            continue
        elif len(a) > 2 and a.startswith(("-d", "-F", "-T")) and a[1] in "dFT":
            val = a[2:]
            if a[1] == "T":
                out.append(val)
                continue
        if val is not None and "@" in val:
            out.append(val.partition("@")[2])
    return out


def _sensitive_source(path: str) -> bool:
    return path == "-" or bool(_cred_level(path)) or _protected(path) or bool(re.search(r"(?:^|/)\.(?:ssh|aws|gnupg|kube)(?:/|$)", _norm(path)))


def _net_hit(name: str, stage: _Stage, argv: list[str], sensitive_upstream: bool, intent: str) -> Hit | None:
    if name in ("curl", "wget", "http", "https", "xh"):
        hosts = _remote_hosts(argv) or ([] if any(shell.is_loopback(v) for a in argv[1:] for v in shell.network_values(a)) else ["?"])
        if not hosts:
            return None
        named = all(h.lower() in intent.lower() for h in hosts if h != "?") and "?" not in hosts
        files = [f for f in _data_files(name, argv) if f]
        if named:  # a destination the user named takes their files, unless it is a key or a cloud credential
            files = [f for f in files if (_cred_level(f) or ("", ""))[0] == DENY or f != "-" and _protected(f)]
        stdin_data = "-" in files or stage.piped and any(a in ("-d", "@-", "--data-binary", "-T") or a.endswith("@-") for a in argv[1:])
        for f in files:
            if f != "-" and _sensitive_source(f):
                return Hit(DENY, f"uploads {f}, a sensitive file, to {hosts[0]}.", f)
        if sensitive_upstream and (stdin_data or files):
            return Hit(DENY, f"sends credential or home-directory data on to {hosts[0]}.")
        if files and not named:
            return Hit(ASK, f"uploads {files[0]} to {hosts[0]}, which the user did not name.", hosts[0])
        for a in argv[1:]:
            if re.search(r"\$\(\s{0,3}(?:cat|base64|tar|printenv|env|zip)\b|`\s{0,3}(?:cat|base64|tar|printenv)\b", a):
                if _cred_args(["cat", *shlex_args(a)]):
                    return Hit(DENY, f"sends the contents of a credential file to {hosts[0]}.")
                if not named and any(_data_flag_before(argv, a)):
                    return Hit(ASK, f"sends command output to {hosts[0]}, which the user did not name.", hosts[0])
        return None
    if name in ("scp", "sftp", "rsync", "rclone", "gsutil"):
        pos = [a for a in argv[1:] if not a.startswith("-")]
        if name in ("rclone", "gsutil") and pos:
            pos = pos[1:] if pos[0] in ("copy", "sync", "copyto", "move", "moveto", "cp", "rsync", "mv") else pos
        if len(pos) < 2:
            return None
        dest, srcs = pos[-1], pos[:-1]
        if not _REMOTE.match(dest) or shell.is_loopback(shell.host(next(iter(shell.network_values(dest)), dest))):
            return None
        if any(_REMOTE.match(s) for s in srcs):
            return None
        for s in srcs:
            if _sensitive_source(s):
                return Hit(DENY, f"{name} sends {s}, a sensitive path, to {dest}.", s)
        host = dest.partition(":")[0].rpartition("@")[2]
        if host.lower() in intent.lower() and host:
            return None
        return Hit(ASK, f"{name} copies local files to the remote {dest}, which the user did not name.", dest)
    if name in ("nc", "ncat", "netcat", "socat"):
        pos = [a for a in argv[1:] if not a.startswith("-")]
        if any(a in ("-e", "-c", "--exec", "--sh-exec") for a in argv[1:]) and pos:
            return Hit(DENY, f"{name} hands a shell to {pos[0]}: a reverse or bind shell.")
        if any(a.startswith(("exec:", "EXEC:", "system:", "SYSTEM:")) for a in pos):
            return Hit(DENY, "socat hands a shell to a remote peer.")
        if any(a in ("-l", "-lp", "-lvp", "-lk") or (a.startswith("-") and "l" in a[1:]) for a in argv[1:]) and not stage.piped and not stage.redirects:
            return None
        if pos and not all(shell.is_loopback(p) for p in pos[:1]):
            fed = [t for op, t in stage.redirects if op == "<"]
            if any(_sensitive_source(t) for t in fed) or sensitive_upstream:
                return Hit(DENY, f"{name} sends a sensitive file to {pos[0]}.")
            if fed or stage.piped:
                return Hit(ASK, f"{name} sends data to {pos[0]}.", pos[0])
        return None
    if name in ("mail", "mailx", "sendmail"):
        fed = [t for op, t in stage.redirects if op == "<"]
        if any(_sensitive_source(t) for t in fed) or sensitive_upstream:
            return Hit(DENY, f"{name} mails a sensitive file.")
        return None
    if name == "aws" and len(argv) > 3 and argv[1] == "s3" and argv[2] in ("cp", "sync", "mv"):
        pos = [a for a in argv[3:] if not a.startswith("-")]
        if len(pos) >= 2 and pos[-1].startswith("s3://") and not pos[0].startswith("s3://"):
            if any(_sensitive_source(p) for p in pos[:-1]):
                return Hit(DENY, f"aws s3 {argv[2]} uploads {pos[0]}, a sensitive path.", pos[0])
            return Hit(ASK, f"aws s3 {argv[2]} uploads local files to {pos[-1]}.", pos[-1])
    return None


def shlex_args(text: str) -> list[str]:
    try:
        return shlex.split(text.replace("$(", " ").replace("`", " ").replace(")", " "))
    except ValueError:
        return text.split()


def _data_flag_before(argv: list[str], arg: str) -> list[bool]:
    i = argv.index(arg)
    return [i > 0 and argv[i - 1] in _CURL_DATA]


def _stage_hits(stage: _Stage, intent: str, depth: int, state: dict[str, Any]) -> list[Hit]:
    bare, _ = _unwrap(stage)
    argv = bare.argv
    out: list[Hit] = []
    if not argv:
        for op, target in bare.redirects:
            if op.startswith(">"):
                if _device(target):
                    out.append(Hit(DENY, f"redirect into the block device {target}.", target))
                elif (p := persistence_path(target)):
                    out.append(Hit(p[0], f"writes {target}, {p[1]}.", target))
        return out
    name = _bin(argv[0])
    sudo = bare.sudo
    # text a shell runs: bash -c '...', eval ..., su -c
    if name in _SHELLS or name in ("su", "eval"):
        code = None
        if name == "eval":
            code = " ".join(argv[1:])
        else:
            for k, a in enumerate(argv[1:], 1):
                if a.startswith("-") and not a.startswith("--") and "c" in a[1:] and k + 1 < len(argv):
                    code = argv[k + 1]
                    break
        if code and depth < _MAX_DEPTH:
            out.extend(_analyse(code, intent, depth + 1, state, sudo))
    for op, target in bare.redirects:
        if op.startswith(">"):
            if _device(target):
                out.append(Hit(DENY, f"redirect into the block device {target}.", target))
        elif op == "<" and _cred_level(target) and _cred_level(target)[0] == DENY and name in _READERS | _NET_SINKS:
            out.append(Hit(DENY, f"{name} reads {target}, {_cred_level(target)[1]}.", target))
    # destruction
    if name == "rm" or name == "unlink" or name == "rmdir":
        hit = _rm_hit(argv, sudo)
        if hit:
            out.append(hit)
    elif name == "find":
        hit = _find_hit(argv)
        if hit:
            out.append(hit)
    elif name == "mv" and any(_protected(a) for a in argv[1:-1] if not a.startswith("-")):
        out.append(Hit(DENY, "mv moves a root, home or system directory away.", argv[1]))
    elif name == "git":
        hit = _git_hit(argv, bare.assigns)
        if hit:
            out.append(hit)
    elif name in ("chmod", "chown", "chgrp"):
        hit = _mode_hit(name, argv, sudo)
        if hit:
            out.append(hit)
    hit = _disk_hit(name, argv, sudo)
    if hit:
        out.append(hit)
    # credential reads
    cred = None
    if name in _READERS or name in _INTERPRETERS:
        cred = _cred_args(argv) if name in _READERS and name not in _NET_SINKS else None  # those are read by _net_hit
        if name in _INTERPRETERS:
            m = _CRED_TEXT.search(" ".join(argv[1:]))
            if m:
                cred = (DENY, "a credential store", m[0])
        if name == "find" and cred and "-exec" not in argv:
            cred = None
        if name in ("ln", "install") and cred:
            cred = None
        if name == "grep" and cred and any(a in ("-l", "-L", "-c", "-q", "--files-with-matches", "-lr", "-rl") for a in argv[1:]):
            cred = None
    if cred:
        out.append(Hit(cred[0], f"{name} reads {cred[2]}, {cred[1]}.", cred[2]))
        if cred[0] == ASK:
            state["weak_secret"] = True
        else:
            state["secret"] = True
    for needle, decision in _CLI_SECRETS:
        if _bin(argv[0]) == needle[0] and _in_order([_bin(argv[0]), *argv[1:]], needle):
            out.append(Hit(decision, f"{' '.join(needle)} prints credentials."))
            state["secret"] = state.get("secret") or decision == DENY
            break
    # exfiltration, persistence
    hit = _net_hit(name, bare, argv, bool(state.get("secret") or (bare.piped and state.get("prev_secret"))), intent)
    if hit:
        out.append(hit)
    hit = _persist_hit(name, argv, bare)
    if hit:
        out.append(hit)
    if name in _FETCHERS or name == "nc":
        state["fetched"] = True
    return out


def _writes(argv: list[str]) -> bool:
    return any(a in ("-o", "-O", "--output", "--remote-name") or a.startswith(("-o", "--output=")) for a in argv[1:])


def _pipe_hits(stages: list[_Stage], intent: str) -> list[Hit]:
    """Downloads run as code, and sensitive data on the way to the network."""
    out: list[Hit] = []
    by_pipe: dict[int, list[_Stage]] = {}
    for s in stages:
        by_pipe.setdefault(s.pipeline, []).append(s)
    for chain in by_pipe.values():
        fetched: str | None = None
        secret = False
        for st in chain:
            bare, _ = _unwrap(st)
            if not bare.argv:
                continue
            name = _bin(bare.argv[0])
            reader = _cred_args(bare.argv) if name in _READERS else None
            if reader and reader[0] == DENY or (reader and reader[0] == ASK):
                secret = True
            if bare.piped and secret and name in _NET_SINKS:
                host = (_remote_hosts(bare.argv) or ["a remote host"])[0]
                if name in ("curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "ssh", "ftp", "telnet", "http", "https", "xh"):
                    out.append(Hit(DENY, f"credential data is piped to {name} for {host}."))
            if bare.piped and fetched and (name in _SHELLS or (name in _INTERPRETERS and not [a for a in bare.argv[1:] if not a.startswith("-")]) or name in ("xargs",)):
                plain = _tls_less(chain)
                sudo = st.sudo or bare.sudo or any(_bin(x.argv[0]) in ("sudo", "doas") for x in chain if x.argv)
                out.append(Hit(DENY if (sudo or plain) else ASK,
                               f"{fetched} output is piped into {name}: code downloaded and run unread"
                               f"{' as root' if sudo else ''}.", ""))
            if name in _FETCHERS and not _writes(bare.argv):
                fetched = name
            elif name in ("nc", "ncat", "netcat") and bare.argv[1:] and not any(a.startswith("-l") for a in bare.argv[1:]) and not bare.piped:
                fetched = name
    return out


def _tls_less(chain: list[_Stage]) -> bool:
    """A download over plain http, or from a bare IP address, that is then run."""
    for st in chain:
        bare, _ = _unwrap(st)
        if bare.argv and _bin(bare.argv[0]) in _FETCHERS:
            for a in bare.argv[1:]:
                if a.lower().startswith("http://") and not shell.is_loopback(a):
                    return True
                if re.match(r"^(?:https?://)?\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|$)", a):
                    return True
    return False


def _download_run(stages: list[_Stage]) -> Hit | None:
    """curl -o x ... ; bash x   (a download, then the file run)."""
    saved: set[str] = set()
    for st in stages:
        bare, _ = _unwrap(st)
        if not bare.argv:
            continue
        name = _bin(bare.argv[0])
        if name in _FETCHERS:
            args = bare.argv[1:]
            for i, a in enumerate(args):
                if a in ("-o", "-O", "--output", "--output-document") and i + 1 < len(args):
                    saved.add(posixpath.basename(args[i + 1]))
                elif a.startswith("-o") and len(a) > 2 and not a.startswith("--"):
                    saved.add(posixpath.basename(a[2:]))
                elif a.startswith("--output="):
                    saved.add(posixpath.basename(a.partition("=")[2]))
        elif saved:
            run = None
            if name in _SHELLS | _INTERPRETERS:
                run = next((a for a in bare.argv[1:] if not a.startswith("-")), None)
            elif name in ("chmod",) and any("x" in a or a[:1] in "0123456789" for a in bare.argv[1:2] + bare.argv[2:3]):
                run = next((a for a in bare.argv[2:] if not a.startswith("-")), None)
            elif name.startswith("./") or bare.argv[0].startswith(("./", "/")):
                run = bare.argv[0]
            if run and posixpath.basename(run) in saved:
                return Hit(ASK, "a downloaded file is made executable or run straight after the download.")
    return None


def _analyse(command: str, intent: str, depth: int, state: dict[str, Any], sudo: bool = False) -> list[Hit]:
    hits: list[Hit] = []
    text = command[:_MAX]
    if _FORK_BOMB.search(text) and re.search(r"\|\s{0,3}[\w:.-]{1,40}\s{0,3}&", text) or _FORK_LOOP.search(text):
        hits.append(Hit(DENY, "a fork bomb: a function or loop that starts copies of itself until the machine stops."))
    if _FORK_CODE.search(text) and ("while" in text.lower() or "fork" in text.lower()) and re.search(r"fork\s{0,3}\(\)\s{0,3}(?:#|;|\n|$|\))|fork\s+while|:\(\)", text, re.I) and len(text) < 2000:
        if re.search(r"while[^;\n]{0,40}fork|fork\s+while|:\(\)\s*\{", text, re.I):
            hits.append(Hit(DENY, "a fork bomb: code that forks without end."))
    if _PIPE_SHELL_SUBST.search(text):
        plain = bool(re.search(r"http://|\b\d{1,3}(?:\.\d{1,3}){3}\b", text))
        hits.append(Hit(DENY if sudo or plain else ASK, "code downloaded and run unread (a shell or eval given a download's output)."))
    if _REVERSE_STRICT.search(text):
        hits.append(Hit(DENY, "a reverse shell: a shell handed to a network socket."))
    elif "/dev/tcp/" in text or "/dev/udp/" in text:
        for m in re.finditer(r"/dev/(?:tcp|udp)/([^/\s'\"]{1,100})/\d{1,5}", text):
            if not shell.is_loopback(m[1]):
                hits.append(Hit(ASK, f"a raw network socket to {m[1]}.", m[1]))
                break
    if re.search(r"rmtree\(\s{0,3}(?:os\.path\.expanduser\(\s{0,3}['\"]~['\"]\s{0,3}\)|['\"](?:/|~|\$HOME)['\"]|Path\.home\(\)|"
                 r"os\.environ\[['\"]HOME['\"]\])", text):
        hits.append(Hit(DENY, "code that deletes the home or root directory tree."))
    stages = _stages(text)
    if stages is None:
        return hits
    state_pipe_secret = False
    for st in stages:
        local = dict(state)
        local["prev_secret"] = state_pipe_secret
        st.sudo = st.sudo or sudo
        found = _stage_hits(st, intent, depth, local)
        hits.extend(found)
        if not st.piped:
            state_pipe_secret = False
        if local.get("secret") and not state.get("secret"):
            state_pipe_secret = True
    for pipe in _pipe_hits(stages, intent):
        if not any(h.reason == pipe.reason for h in hits):
            hits.append(pipe)
    run = _download_run(stages)
    if run:
        hits.append(run)
    for inner in _SUBST.finditer(text):
        body = inner[1] or inner[2]
        if body and depth < _MAX_DEPTH and len(hits) < 50:
            hits.extend(_analyse(body, intent, depth + 1, {}, sudo))
    return hits


def _worst(hits: list[Hit], intent: str, review: str = "tainted") -> Hit | None:
    if not hits:
        return None
    best = next((h for h in hits if h.decision == DENY), hits[0])
    if best.decision == DENY and best.trigger and len(best.trigger) > 3 and best.trigger in intent:
        return Hit(ASK, best.reason + " (the user named it, so confirm it)", best.trigger)
    if best.decision == ASK and best.trigger and len(best.trigger) > 3 and best.trigger in intent and (
            "did not name" in best.reason):
        return None
    return best


def assess_shell(command: str, intent: str = "") -> Hit | None:
    """The verdict on a shell command by its text, or None when nothing here objects."""
    if not command or not command.strip():
        return None
    hits = _analyse(command, intent, 0, {})
    if command.strip() and command.strip() in intent and hits and all(h.decision == DENY for h in hits):
        return Hit(ASK, hits[0].reason + " (the user typed this command, so confirm it)")
    return _worst(hits, intent)


def assess_file(path: str, content: Any = None, write: bool = False, intent: str = "") -> Hit | None:
    """The verdict on a file read or write by a built-in tool."""
    if not path:
        return None
    if not write:
        cred = _cred_level(path)
        if cred:
            hit = Hit(cred[0], f"reading {path}, {cred[1]}.", path)
            return _worst([hit], intent)
        return None
    pers = persistence_path(path)
    text = _text(content)[:_MAX]
    hits: list[Hit] = []
    if pers:
        hits.append(Hit(pers[0], f"writing {path}, {pers[1]}.", path))
        if _MALICIOUS_CONTENT.search(text) or any(h.decision == DENY for h in _analyse(text, intent, 1, {})):
            hits.append(Hit(DENY, f"the new text of {path} downloads and runs code, opens a shell or sends data out."))
    cred = _cred_level(path)
    if cred and cred[0] == DENY and path.strip():
        hits.append(Hit(ASK, f"writing {path}, {cred[1]}.", path))
    return _worst(hits, intent)


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, (list, tuple)):
        return "\n".join(_text(c) for c in content)
    if isinstance(content, dict):
        return "\n".join(_text(c) for c in content.values())
    return "" if content is None else str(content)
