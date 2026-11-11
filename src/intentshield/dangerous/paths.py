"""Paths as the rules read them (home, system and protected directories, devices) and the credential stores."""
from __future__ import annotations

import os
import posixpath
import re

from .core import _PATH_CAP, _PATH_CAP_WHY, _WORKDIR, ASK, DENY, _bin

# --- paths -----------------------------------------------------------------------------------------------------

_HOME = re.compile(r"^(?:\$\{?(?:HOME|USERPROFILE)\}?|~[\w.-]{0,32}|/Users/[^/]+|/home/[^/]+|/root|/var/root)(?=/|$)")
_GLOB_TAIL = re.compile(r"/(?:\.?\*{1,2}|\.\[!\.\]\*|\.\[\^\.\]\*|\.\?\*)$")
_BRACKET = re.compile(r"\[[^\]/\s]{1,30}\]")


def _glob_only(segment: str) -> bool:
    """A path part made of glob characters alone (``?``, ``[a-z]*``, ``[!x]``): every name of that shape in the directory,
    so at the root ``/[a-z]*`` and ``/?`` are the entries of the root. A dot first and a star later (``.[a-z]*``, ``.??*``) is
    the same as ``.*`` for the entries of a home directory: nearly all of its hidden ones."""
    rest = _BRACKET.sub("", segment)
    if rest[:1] == "." and "*" in rest[1:] and set(rest[1:]) <= {"?", "*"}:
        return True
    return bool(segment) and set(rest) <= {"?", "*"} and (rest != segment or "?" in segment or "*" in segment)
_SYSTEM_ROOTS = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var", "/boot", "/System", "/Library", "/opt", "/private",
                 "/dev", "/sys", "/proc", "/Applications", "/srv", "/mnt", "/Volumes", "/Users", "/home", "/root", "/snap",
                 "/run", "/nix", "/cores", "/lost+found")
_PROTECTED = frozenset({"/", "~", *_SYSTEM_ROOTS, "/usr/bin", "/usr/lib", "/usr/local", "/usr/local/bin", "/usr/sbin",
                        "/usr/share", "/var/lib", "/var/log", "/var/root", "/System/Library", "/Library/Frameworks",
                        "/private/etc", "/private/var", "/etc/ssh", "/lib/modules"})
_HOME_DIRS = frozenset({"Documents", "Desktop", "Downloads", "Pictures", "Music", "Movies", "Library", "Developer", ".ssh",
                        ".aws", ".gnupg", ".config", ".kube", ".local"})


_HOME_HEAD = re.compile(r"^(?:~[\w.-]{0,32}|\$\{?(?:HOME|USERPROFILE)\}?|\$\{(?:HOME|USERPROFILE):?[-?=][^}]{0,60}\})(?=/|$)")


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
        home = _HOME.match(p)
        if home:
            p = "~" + p[home.end():]
    for _ in range(3):
        stripped = _GLOB_TAIL.sub("", p)
        if stripped == p:
            parent, slash, segment = p.rpartition("/")
            if not (slash and _glob_only(segment)):
                break
            stripped = parent
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
    return any(p == r or p.startswith(r + "/") for r in _SYSTEM_ROOTS if r not in ("/Users", "/home", "/root", "/mnt", "/Volumes",
                                                                                   "/srv"))


_DEVICE = re.compile(r"^/dev/(?:r?disk\d|sd[a-z]|hd[a-z]|nvme\d|mmcblk\d|vd[a-z]|xvd[a-z]|md\d|dm-\d|loop\d|mapper/|sr\d|"
                     r"disk/|zd\d|mtd|ram\d)")
_SAFE_DEVICE = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty", "/dev/zero", "/dev/random",
                          "/dev/urandom"})


def _device(path: str) -> bool:
    return bool(_DEVICE.match(path)) and path not in _SAFE_DEVICE


# A variable that alone (or after ``/``, ``~/`` or ``$HOME/``) is the target: when it is empty the target is the root or
# home directory.
_EMPTY_VAR = re.compile(r"\"?(?:/\*?|~/?|\$\{?(?:HOME|USERPROFILE)\}?/)?\$\{?[A-Za-z_]\w{0,40}\}?\"?(?:/\*?)?")
_DEFAULTED = re.compile(r"\$\{[A-Za-z_]\w{0,40}:?-([^}]{0,60})\}(/?\*?)")


def _is_empty_var_target(arg: str) -> bool:
    """``$DIR``, ``$DIR/``, ``${DIR}/*``: whatever the variable holds, the target is that, and an empty one is root."""
    m = _EMPTY_VAR.fullmatch(arg)
    return bool(m) and not re.match(r"\"?\$\{?(?:HOME|USERPROFILE)\}?\"?(?:/\*?)?$", arg)


def _default_target(arg: str) -> str | None:
    """``${DIR:-/}``: the text the variable stands for when it is unset, with what follows it, or None."""
    m = _DEFAULTED.fullmatch(arg.strip("\"'"))
    return m[1] + m[2] if m else None


# --- credential stores -----------------------------------------------------------------------------------------

_BACKUP = r"(?:\.(?:bak|old|orig|backup|save)|~)"   # a copy of a key keeps the key
_KEY_NAME = re.compile(r"^(?:id_(?:rsa|dsa|ecdsa|ed25519|ecdsa_sk|ed25519_sk)|identity|[\w.-]{1,40}_(?:rsa|dsa|ecdsa|ed25519))"
                       + _BACKUP + "?$")
_ENV_FILE = re.compile(r"^(?:\.env(?:\.[\w-]{1,30})?|[\w-]{1,30}\.env)$")
_ENV_SAMPLE = re.compile(r"\.(?:example|sample|template|dist|defaults|schema|tpl|md)$")
_CLOUD_FILES = re.compile(r"(?:^|/)(?:\.aws/(?:credentials|sso/cache|cli/cache)|\.vault-token|\.config/gcloud/"
                          r"(?:credentials\.db|access_tokens\.db|application_default_credentials\.json|legacy_credentials)|"
                          r"\.gnupg/(?:private-keys-v1\.d|secring\.gpg|trustdb\.gpg)|library/keychains|\.local/share/keyrings)")
_SOFT_FILES = re.compile(r"(?:^|/)(?:\.kube/config|\.docker/config\.json|\.npmrc|\.pypirc|\.azure/(?:accesstokens|msal|cred"
                         r"entials)|"
                         r"\.config/doppler/|\.doppler\.ya?ml|"
                         r"\.config/gcloud|\.config/gh/hosts\.yml|\.config/hub|\.terraform\.d/credentials|\.heroku/|"
                         r"\.config/doctl|\.config/op/|\.pgpass|\.my\.cnf|\.s3cfg|\.boto|\.gnupg|\.password-store/|\.cargo/"
                         r"credentials|"
                         r"\.config/rclone/rclone\.conf|\.oci/config|\.git-credentials|"
                         r"\.codex/auth\.json|\.gemini/(?:oauth_creds|mcp-oauth-tokens)\.json|\.claude/\.credentials\.json|"
                         r"\.claude\.json$)")
# The directory of a credential store, or a glob over it (``~/.aws/*``, ``~/.aws/c*``): everything in it is read.
_SECRET_DIR = re.compile(r"(?:^|/)\.(?:aws|gnupg)(?:/[^/]*[*?\[][^/]*)?$")
_SOFT_DIR = re.compile(r"(?:^|/)\.(?:kube|docker|config/gh|config/gcloud)(?:/[^/]*[*?\[][^/]*)?$")
_ETC_SECRET = re.compile(r"^/(?:private/)?etc/(?:shadow|gshadow|master\.passwd|ssh/ssh_host_[\w_]+_key)$")
_SUDOERS = re.compile(r"^/(?:private/)?etc/sudoers(?:\.d/[\w.-]+)?$")   # a read shows rules, not secrets; a write is a deny
_PROC_SECRET = re.compile(r"^/proc/(?:self|\d{1,8})/(?:environ|mem|maps)$")
_BROWSER = re.compile(r"(?:chrome|chromium|firefox|mozilla|brave|safari|microsoft edge|vivaldi)")
_BROWSER_FILE = re.compile(r"(?:^|/)(?:login data|cookies|cookies\.sqlite|logins\.json|key[34]\.db|web data)$")
_KEYISH = re.compile(r"\.(?:p12|pfx|ppk|key|keystore|jks)$")
_PEMISH = re.compile(r"\.(?:pem|asc)$")
# A .pem or .asc that is a certificate, a CA bundle or a public key (the usual ones), unless the name says private or secret.
_PUBLIC_NAME = re.compile(r"(?:^|[-_.])(?:certs?|certificates?|chain|fullchain|ca|bundle|pub|public|sig|signature)(?:[-_.]|$)")
_APP_SECRET = re.compile(r"(?:^|/)(?:credentials\.json|client_secrets?[\w-]{0,20}\.json|service[-_]?account[\w-]{0,30}\.json|"
                         r"secrets\.(?:ya?ml|json|toml)|terraform\.tfstate|[\w-]{1,30}\.tfvars)$")


_SLASHES = re.compile(r"/(?:\.?/)+")
_TEST_DIRS = frozenset({"test", "tests", "testdata", "fixtures", "fixture", "__fixtures__", "spec", "specs", "__tests__"})


def _clean_path(path: str) -> str:
    """``path`` without NUL bytes (the shell ignores them) and with repeated slashes and ``/./`` collapsed, which is how the
    system reads them: ``~/.ssh//./id_rsa`` is ``~/.ssh/id_rsa``."""
    if "\x00" in path:
        path = path.replace("\x00", "")
    return _SLASHES.sub("/", path) if "/" in path else path


def _pathlike(word: str) -> bool:
    """A word that is probably a path rather than a pattern, a program text or a URL."""
    return word.startswith(("/", "~", "$", ".")) or ("/" in word and "://" not in word and not any(c.isspace() for c in word))


def _test_fixture(path: str, n: str) -> bool:
    """``n`` (the lower-cased, normalised ``path``) lies in a test directory and in no directory that starts with a dot. A
    relative path is the project's by being relative; an absolute one must lie inside the call's working directory, which must
    itself be neither the home directory nor the root (``~/tests/id_rsa`` is the user's own)."""
    folders = n.split("/")[:-1]
    if not _TEST_DIRS & set(folders) or any(f.startswith(".") and f not in (".", "..") for f in folders):
        return False
    if not path.startswith(("/", "~", "$")):
        return True
    try:
        cwd = _WORKDIR.get() or os.getcwd()
    except OSError:
        return False
    if _norm(cwd) in ("", "~", "/"):
        return False
    if path.startswith("/") and cwd.startswith("/"):   # as spelled: _norm would make /Users/a and /Users/b the same ~
        here, project = posixpath.normpath(path).lower(), posixpath.normpath(cwd).lower()
    else:
        here, project = n, _norm(cwd).lower()
    return here.startswith(project.rstrip("/") + "/")


# What a file in ~/.ssh is, by its name. A key is named like one (``id_ed25519``, ``work_rsa``, ``deploy.pem``) or holds the
# text that starts a private key; the names below are lists of hosts, options and public keys that hold no secret.
_SSH_KEYISH = re.compile(r"^(?:id_|identity)|[_.-](?:rsa|dsa|ecdsa|ed25519)(?:[_.-]|$)|\.(?:pem|key|ppk|p12|pfx)$|private|secret")
_SSH_PLAIN = re.compile(r"^(?:config|known_hosts|authorized_keys2?)(?:\.[\w.-]{1,40}|~)?$|^(?:allowed_signers|environment|rc)$")
_PRIVATE_KEY_TEXT = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File")
_SSH_OTHER = "a file in the SSH directory that is not a known public one, so it may be a private key"


def _from_workdir(path: str) -> str | None:
    """``path`` read from the working directory of the call, when it is relative and the directory is known (absolute)."""
    cwd = _WORKDIR.get()
    path = path.strip().strip("\"'")
    if not cwd.startswith("/") or not path or path.startswith(("/", "~", "$", "-")) or "://" in path:
        return None
    return posixpath.normpath(posixpath.join(cwd, path))


def _file_of(path: str) -> str | None:
    """The file a path names on this machine (``~`` and ``$HOME`` spelled out, a relative path from the working directory), or
    None when it is a glob, has a variable or is not a regular file."""
    path = path.strip().strip("\"'")
    if re.match(r"^\$\{?HOME\}?(?=/|$)", path):
        path = "~" + re.sub(r"^\$\{?HOME\}?", "", path)
    if "$" in path or any(c in path for c in "*?["):
        return None
    full = os.path.expanduser(path) if path.startswith("~") else _from_workdir(path) or path
    return full if full.startswith("/") and os.path.isfile(full) else None


def _holds_private_key(path: str) -> bool:
    """The file exists and starts like a private key (a PEM or OpenSSH header, a PuTTY key file)."""
    full = _file_of(path)
    if full is None:
        return False
    try:
        with open(full, "rb") as handle:
            return bool(_PRIVATE_KEY_TEXT.search(handle.read(4096).decode("latin-1")))
    except OSError:
        return False


def _ssh_level(path: str, n: str, base: str, raw: str) -> tuple[str, str] | None:
    """The verdict on a path in ``~/.ssh``. A key by its name, or by the text it holds when the file is there to read, is a deny.
    A list of hosts, an options file or a public-key list is not secret. Any other name could be a key, and is asked about."""
    if base == ".ssh" or n.endswith(".ssh/*") or raw.endswith(".ssh/*"):
        return DENY, "the SSH directory"
    if _KEY_NAME.match(base) or _SSH_KEYISH.search(base):
        return DENY, "an SSH private key"
    if any(c in base for c in "*?[") and "/config.d/" not in "/" + n:
        return DENY, "the SSH directory"   # a glob over the directory reaches its keys
    if _SSH_PLAIN.match(base) or "/config.d/" in "/" + n or n.startswith("config.d/"):
        return (DENY, "an SSH private key") if _holds_private_key(path) else None
    return (DENY, "an SSH private key") if _holds_private_key(path) else (ASK, _SSH_OTHER)


def _cred_level(path: str) -> tuple[str, str] | None:
    """(decision, what) when ``path`` names a credential store. A path over ``_PATH_CAP`` characters (after repeated slashes are
    collapsed) is not read: it is asked about, never passed as safe."""
    if not path:
        return None
    path = _clean_path(path)
    if len(path) > _PATH_CAP:
        return (ASK, _PATH_CAP_WHY) if _pathlike(path) else None
    n = _norm(path).lower() if path.startswith(("~", "$", "/")) else posixpath.normpath(path.strip()).lower()
    raw = path.strip().lower()
    base = n.rpartition("/")[2]
    anchored = [n]   # the system files are named from the root, so a relative path is also read from the working directory
    if (resolved := _from_workdir(path)) is not None:
        anchored.append(_norm(resolved).lower())
    if any(_ETC_SECRET.match(a) or _PROC_SECRET.match(a) for a in anchored):
        return DENY, "a system secret file"
    if any(_SUDOERS.match(a) for a in anchored):
        return ASK, "the sudo rules"
    if base.endswith(".pub"):
        return None
    if _CLOUD_FILES.search(n):
        return DENY, "a cloud credential store or keychain"
    if _SECRET_DIR.search(n):
        return DENY, "a directory of credentials"
    if _SOFT_DIR.search(n):
        return ASK, "a directory of credential files"
    if "/.ssh/" in "/" + n + "/" or n.endswith("/.ssh") or n == ".ssh" or n.startswith(".ssh/"):
        return _ssh_level(path, n, base, raw)
    if _KEY_NAME.match(base):
        if _test_fixture(path, n):   # tests/fixtures/id_rsa, relative or absolute: a sample key
            return ASK, "a file named like an SSH private key, in a test directory"
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
    if _PEMISH.search(base):
        private = bool(re.search(r"priv|secret", base))
        if private or (base.endswith(".pem") and not _PUBLIC_NAME.search(base)):
            return ASK, "a key or secret file"
    return None


def overwrite_level(path: str) -> tuple[str, str] | None:
    """(ASK, what) when writing, appending to or emptying ``path`` would replace a key or a cloud credential (or a file of
    ``~/.ssh`` that may be one): a write is never a deny, since the user may be installing the file."""
    cred = _cred_level(path) if path.strip() else None
    if cred and (cred[0] == DENY or cred[1] == _SSH_OTHER):
        return ASK, cred[1]
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


# Long options of the programs in ``_CLI_SECRETS`` that the program accepts cut short, with the shortest cut it takes for that one
# option alone (gpg: ``--export-secret-k``, since ``--export`` and ``--export-secret-subkeys`` are options of their own).
_CUT_OPTIONS = {"--export-secret-keys": 17}


def _in_order(argv: list[str], needle: tuple[str, ...]) -> bool:
    it = iter(argv)
    return all(any(token == want or (shortest := _CUT_OPTIONS.get(want)) is not None and len(token) >= shortest
                   and want.startswith(token) for token in it) for want in needle)


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
    if name in _PATTERN_FIRST and not any(a in ("-e", "-f", "--regexp", "--file") or a.startswith(("-e", "--regexp="))
                                          for a in args):
        skipped = False
        trimmed = []
        for a in args:
            if not skipped and not a.startswith("-"):
                skipped = True
                continue
            trimmed.append(a)
        args = trimmed
    if name == "openssl":  # -out and -keyout name files it writes
        args = [a for k, a in enumerate(args) if not (k and args[k - 1] in ("-out", "-keyout", "-outform", "-passout", "-new",
                                                                            "-newkey"))]
    best = None
    for a in args:
        if a.startswith("-") and "=" not in a and "@" not in a:
            continue
        for c in _candidates(a):
            hit = _cred_level(c)
            if hit and (best is None or hit[0] == DENY and best[0] != DENY):
                best = (hit[0], hit[1], c)
    return best


# Programs that name a file without reading or sending what is in it: a listing, a mode, a count, a signing login, a message.
_NAMES_ONLY = frozenset({"ls", "ll", "stat", "file", "test", "[", "[[", "wc", "du", "df", "realpath", "readlink", "dirname",
                         "basename", "ssh", "ssh-keygen", "ssh-add", "ssh-keyscan", "ssh-copy-id", "chmod", "chown", "chgrp",
                         "touch", "mkdir", "cd", "pushd", "popd", "echo", "printf", "which", "command", "type", "rm", "unlink",
                         "rmdir", "mv", "shred", "truncate", "find", "grep", "egrep", "fgrep", "rg", "ag", "ack", "open"})
_IDENTITY_OPTIONS = frozenset({"-i", "-I", "--identity-file"})


def _named_secret(argv: list[str]) -> tuple[str, str, str] | None:
    """(decision, what, path) for a key, cloud credential or system secret that any program but a listing or a login names
    among its arguments: not read by a rule of its own (``git add ~/.ssh/id_rsa``, ``gh gist create``, ``zip``, ``curl
    file://...``, ``rsync`` to a local directory), so asked about. A path that is only the identity a login signs with
    (``-i``, ``-o IdentityFile=``) is not named for reading."""
    name = _bin(argv[0])
    if name in _NAMES_ONLY:
        return None
    args = argv[1:]
    for k, a in enumerate(args):
        if (k and args[k - 1] in _IDENTITY_OPTIONS) or a in _IDENTITY_OPTIONS or a.lower().startswith("identityfile"):
            continue
        for c in [*_candidates(a), a[7:] if a.lower().startswith("file://") else a]:
            c = c.strip("\"'")
            hit = _cred_level(c) if _pathlike(c) and "://" not in c else None
            if hit and (hit[0] == DENY or hit[1] == _SSH_OTHER):
                return ASK, hit[1], c
    return None


_CRON = re.compile(r"(?:^|/)(?:etc/(?:cron[\w.]*|anacrontab)|var/(?:spool/cron|at/tabs)|crontab)(?:/|$)")
_PERSIST = re.compile(
    r"(?:^|/)(?:\.(?:bash|zsh|ksh|csh|tcsh)rc|\.bash_(?:profile|login|logout|aliases)|\.profile|\.zprofile|\.zshenv|\.zlogin|"
    r"\.zlogout|\.zsh_?aliases|\.config/fish/(?:config\.fish|conf\.d/)|\.oh-my-zsh/custom/|\.envrc|etc/(?:profile|bashrc|zs"
    r"hrc|zshenv|"
    r"environment|bash\.bashrc|rc\.local|zsh/|profile\.d/|init\.d/|ld\.so\.preload|launchd\.conf)|"
    r"library/launch(?:agents|daemons)/|etc/systemd/|lib/systemd/|\.config/systemd/|\.config/autostart/|"
    r"\.git/(?:hooks/|config$)|\.githooks/|\.husky/|\.git/modules/[\w./-]{0,200}hooks/|"
    r"\.github/(?:workflows|actions)/|\.github/dependabot\.ya?ml|\.gitlab-ci\.ya?ml|\.gitlab/|\.circleci/|jenkinsfile|"
    r"azure-pipelines\.ya?ml|\.travis\.ya?ml|bitbucket-pipelines\.ya?ml|\.buildkite/|\.drone\.ya?ml|cloudbuild\.ya?ml|"
    r"\.woodpecker/|\.ssh/(?:authorized_keys2?|config|rc|environment))"
    r"(?!\.(?:bak|orig|old|backup|save|swp|tmp|dist|sample|example)(?:$|[.\d])|~$)", re.I)   # a copy that nothing runs
_PERSIST_DENY = (re.compile(r"(?:^|/)(?:\.ssh/authorized_keys2?|etc/sudoers(?:\.d/[\w.-]+)?|etc/(?:passwd|shadow)|e"
                            r"tc/ld\.so\.preload)$", re.I))
_MALICIOUS_CONTENT = re.compile(
    r"\b(?:curl|wget)\b[^|;\n]{0,300}\|\s{0,3}(?:sudo\s{1,3})?(?:ba|z|da)?sh\b|/dev/(?:tcp|udp)/|\bnc(?:at)?\s[^\n;|&]{0,60"
    r"}-[a-z]{0,4}e\s|"
    r"\bbase64\s{1,3}(?:-d|--decode|-D)\b[^|;\n]{0,100}\|\s{0,3}(?:ba|z)?sh\b|\bmkfifo\b[^\n]{0,80}\bnc\b|"
    r"\bssh-(?:rsa|ed25519)\s{1,3}AAAA[\w+/]{20,}", re.I)


def persistence_path(path: str) -> tuple[str, str] | None:
    """(decision, why) when writing ``path`` sets up code that runs later or changes who can log in."""
    path = _clean_path(path)
    if len(path) > _PATH_CAP:
        return (ASK, _PATH_CAP_WHY) if _pathlike(path) else None
    n = _norm(path).lower() if path.startswith(("~", "$", "/")) else path.strip().replace("\\", "/").lower()
    if not n:
        return None
    if _PERSIST_DENY.search(n):
        return DENY, "an access file (authorized_keys, sudoers, passwd)"
    if _PERSIST.search(n) or _CRON.search(n):
        return ASK, "a file that runs code later (shell startup, cron, launchd, systemd, a git hook or a CI workflow)"
    return None
