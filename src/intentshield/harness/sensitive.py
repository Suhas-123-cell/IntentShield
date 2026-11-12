"""Names the rules look for: where a write sets up code or settings that later sessions run, which arguments of a tool
name a command, a path or text, and how a shell script or a JSON text is recognised."""
from __future__ import annotations

import re

# What an MCP tool's arguments are called when it takes a command, a path or the text it writes (``--builtin-tools`` reads them
# with the rules for the harness's own tools), and the words of a tool name that mean it only lists names or changes the file.
_COMMAND_ARGUMENTS = frozenset({"command", "cmd"})
_PATH_ARGUMENTS = frozenset({"path", "paths", "file", "filename", "file_path", "filepath", "source", "destination", "dest",
                             "target"})
_CONTENT_ARGUMENTS = ("content", "contents", "text", "data", "new_string", "new_text", "body")
_NAMES_ONLY_TOOLS = ("list", "tree", "info", "exists", "search")
_WRITING_TOOLS = ("write", "edit", "create", "move", "rename", "copy", "delete", "remove", "append", "save", "put", "upload",
                  "mkdir", "patch", "replace", "insert", "update", "touch", "set_")
# The header's path is read to the end of the line and trimmed afterwards: a lazy ``(.+?)\s*$`` is quadratic on a
# long run of spaces, and a hook that times out fails open.
_PATCH_FILE = re.compile(r"^[ \t]*\*\*\* (?:(?:Update|Add|Delete) File|Move to): ([^\r\n]*)|^\+\+\+ (?:b/)?(\S+)", re.M)
# Where a write sets up code or settings that later sessions run with: shell startup files and aliases, SSH access,
# git configuration and hooks (core.fsmonitor, hooksPath), direnv, autostart entries, programs on the user's PATH, the
# harnesses' settings, hooks, commands and agents (the hooks themselves live there), the instruction files agents
# read at the start of every session, editor tasks and package-manager configuration.
_PERSISTENT_PATHS = (
    r"\.(?:bash|zsh|ksh)rc|\.(?:bash_)?profile|\.zprofile|\.zshenv|\.zlogin|\.bash_login|\.bash_logout|"
    r"\.bash_aliases|\.config/fish/config\.fish|\.ssh/(?:authorized_keys|config)|\.git/(?:hooks/|config(?![\w.-]))|"
    r"\.gitconfig|\.config/git/|\.githooks/|\.husky/|\.pre-commit-config\.yaml|\.envrc|\.oh-my-zsh/custom/|"
    r"\.local/bin/|\.claude/(?:settings[\w.]*\.json|hooks/|commands/|agents/|skills/)|\.codex/config\.toml|"
    r"\.gemini/settings\.json|\.cursor/(?:hooks\.json|rules/)|\.cursorrules|\.mcp\.json|"
    r"\.vscode/(?:tasks|launch|settings)\.json|(?:claude|agents|gemini)\.md(?![\w-])|pip\.conf|\.pip/|"
    r"library/launch(?:agents|daemons)/|\.config/autostart/|\.config/systemd/user/|crontab|"
    r"\.windsurfrules|\.clinerules|copilot-instructions\.md|claude\.local\.md|agents\.override\.md|\.vimrc|"
    r"\.tmux\.conf|\.config/fish/conf\.d/|\.aws/(?:config|credentials)|\.git/modules/|"
    r"\.gemini/(?:commands|extensions)/|\.claude/(?:output-styles|rules)/|/etc/cron|/var/spool/cron"
)
# Files a build or test command reads and runs without being told to: written after a flagged result, they run the
# next time make, pytest, cargo or a CI job does. Only as a path (a command may name them: git add Makefile).
_BUILD_FILES = (r"(?:gnu)?makefile|justfile|conftest\.py|noxfile\.py|tox\.ini|build\.rs|rakefile|cmakelists\.txt|"
                r"\.github/workflows/|\.gitlab-ci\.yml|\.devcontainer/|pytest\.ini|setup\.py|setup\.cfg|"
                r"(?:jest|vitest|vite|webpack|rollup|babel|eslint|playwright|karma)\.config\.[cm]?[jt]s|"
                r"(?:build|settings)\.gradle(?:\.kts)?|pom\.xml|gulpfile\.[cm]?js|gruntfile\.[cm]?js")
# More places a write sets up code later sessions or the user's tools run. Only as a path: a command may name
# them (git add .npmrc) and /usr/local/bin/git is the program, not a write to that directory.
_WRITE_ONLY_PATHS = (
    r"\.claude\.json$|claude_desktop_config\.json|\.cargo/config|\.yarnrc|\.npmrc|\.aider\.conf|"
    r"\.idea/runconfigurations/|(?:users|home)/[^/]+/bin/|usr/local/bin/|opt/homebrew/bin/|"
    r"site-packages/[^/]*\.pth|\.config/starship\.toml|\.zlogout|\.git/config\.worktree|"
    r"code/user/(?:tasks|settings)\.json|\.config/(?:helix|nvim|zed|alacritty)/|\.codex/prompts/|\.windsurf/|"
    r"\.t?cshrc|\.xinitrc|\.xprofile|\.config/environment\.d/|\.zsh/|\.github/actions/|\.circleci/|jenkinsfile|"
    r"lefthook\.ya?ml|\.pre-commit-hooks\.yaml|taskfile\.ya?ml|\.?pylintrc|mypy\.ini|\.flake8|\.coveragerc|"
    r"\.mocharc|\.rspec|gemfile|\.(?:eslintrc|prettierrc|babelrc)\.[cm]?js|(?:prettier|next|nuxt|svelte|astro|"
    r"tailwind|postcss)\.config\.[cm]?[jt]s"
)
# A copy of a file that nothing runs (``.zshrc.bak``, ``.bashrc~``) is not the file.
_NOT_A_COPY = r"(?!\.(?:bak|orig|old|backup|save|swp|tmp|dist|sample|example)(?:$|[.\d])|~$)"
_PERSISTENT = re.compile(r"(?:^|/)(?:" + _PERSISTENT_PATHS + "|" + _BUILD_FILES + "|" + _WRITE_ONLY_PATHS + ")" + _NOT_A_COPY,
                         re.I)
# The same inside a command line, where a path follows a space, a quote or an operator, not only a slash.
_PERSISTENT_IN_COMMAND = re.compile(r"(?:^|[/\s'\"=:<>])(?:" + _PERSISTENT_PATHS + ")" + _NOT_A_COPY, re.I)
# Fields of a built-in result that describe it rather than carry what the tool read.
_RESULT_META = frozenset({"url", "filePath", "file_path", "durationMs", "durationSeconds", "code", "codeText", "bytes",
                          "query", "interrupted", "isImage", "numLines", "startLine", "totalLines", "type",
                          "returnCodeInterpretation", "noOutputExpected", "backgroundTaskId", "returnDisplay"})
_JSON_STRING = re.compile(r'"[\w:.-]+"\s*:\s*"((?:[^"\\\n]|\\.)*)"')
_SHELL_FILE = re.compile(r"\.(?:sh|bash|zsh|ksh|command|bats)$", re.I)
_SHELL_SHEBANG = re.compile(r"#![ \t]*(?:\S*/)?(?:env[ \t]+(?:-S[ \t]+)?)?(?:ba|z|da|k|a)?sh\b")


def _shell_script(path: str, text: str) -> bool:
    """A file a shell runs: a shell extension or a shell shebang."""
    return bool(_SHELL_FILE.search(path)) or bool(_SHELL_SHEBANG.match(text))
