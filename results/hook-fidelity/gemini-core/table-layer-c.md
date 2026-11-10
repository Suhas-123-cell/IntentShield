## Layer C: the real HookSystem built from a settings-shaped hooks.BeforeTool config

| scenario | `0.20.2 .. 0.22.5` | `0.24.5 .. 0.25.2` | `0.26.0 .. 0.29.7` | `0.30.0 .. 0.35.3` | `0.36.0 .. 0.67.0-preview.0` |
|---|---|---|---|---|---|
| allow | allow/yes | allow/yes | allow/yes | allow/yes | allow/yes |
| ask | allow/yes | allow/yes | allow/yes | allow/yes | ask/ask-kept |
| deny | deny/no | deny/no | deny/no | deny/no | deny/no |
| block | deny/no | deny/no | deny/no | deny/no | deny/no |
| empty_exit0 | none/yes | none/yes | none/yes | none/yes | none/yes |
| malformed_json_exit0 | allow/yes | allow/yes | allow/yes | allow/yes | allow/yes |
| malformed_json_exit2 | deny/no | deny/no | deny/no | deny/no | deny/no |
| exit1_empty | none/yes | none/yes | none/yes | none/yes | none/yes |
| exit1_stderr | allow/yes | allow/yes | allow/yes | allow/yes | allow/yes |
| exit2_empty | none/yes | none/yes | none/yes | none/yes | none/yes |
| exit2_stderr | deny/no | deny/no | deny/no | deny/no | deny/no |
| exit2_json_allow | none/yes | none/yes | none/yes | allow/yes | allow/yes |
| exit2_json_deny | none/yes | none/yes | none/yes | deny/no | deny/no |
| exit3_text | none/yes | none/yes | none/yes | deny/no | deny/no |
| exit3_empty | none/yes | none/yes | none/yes | none/yes | none/yes |
| intentshield_crash_exit2 | deny/no | deny/no | deny/no | deny/no | deny/no |
| python_uncaught_exit1 | allow/yes | allow/yes | allow/yes | allow/yes | allow/yes |
| exit126_script_empty | none/yes | none/yes | none/yes | none/yes | none/yes |
| exit126_script_stderr | allow/yes | allow/yes | allow/yes | deny/no | deny/no |
| exit127_script_empty | none/yes | none/yes | none/yes | none/yes | none/yes |
| nonexec_file_126 | allow/yes | allow/yes | allow/yes | deny/no | deny/no |
| bad_interpreter_shebang | allow/yes | allow/yes | allow/yes | deny/no | deny/no |
| missing_command_127 | allow/yes | allow/yes | allow/yes | deny/no | deny/no |
| timeout | none/yes | none/yes | none/yes | none/yes | none/yes |
| continue_false | stop/no | stop/no | stop/no | stop/no | stop/no |
| unknown_decision | allow/yes | allow/yes | allow/yes | allow/yes | allow/yes |
| exit2_json_on_stderr | deny/no | deny/no | deny/no | deny/no | deny/no |
| exit1_json_deny_stdout | none/yes | none/yes | none/yes | deny/no | deny/no |
| python3_missing_on_path | allow/yes | allow/yes | allow/yes | deny/no | deny/no |
| timeout_grandchild_holds_pipe | no-return/hang | no-return/hang | no-return/hang | no-return/hang | no-return/hang |
| multi_ask_plus_allow | allow/yes | allow/yes | allow/yes | allow/yes | ask/ask-kept |
| multi_deny_plus_allow | deny/no | deny/no | deny/no | deny/no | deny/no |
| multi_crash_exit1_then_deny | deny/no | deny/no | deny/no | deny/no | deny/no |
| multi_ask_plus_ask | allow/yes | allow/yes | allow/yes | allow/yes | ask/ask-kept |
| trust_folderTrust_on_folder_trusted | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 |
| trust_folderTrust_on_folder_untrusted | deny/no hook-runs=1 | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 |
| groups_ask_then_allow | allow/yes hook-runs=2 | allow/yes hook-runs=2 | allow/yes hook-runs=2 | allow/yes hook-runs=2 | ask/ask-kept hook-runs=2 |
| groups_allow_then_ask | allow/yes hook-runs=2 | allow/yes hook-runs=2 | allow/yes hook-runs=2 | allow/yes hook-runs=2 | ask/ask-kept hook-runs=2 |
| groups_deny_then_allow | deny/no hook-runs=2 | deny/no hook-runs=2 | deny/no hook-runs=2 | deny/no hook-runs=2 | deny/no hook-runs=2 |
| seq_ask_then_deny | deny/no hook-runs=2 | deny/no hook-runs=2 | deny/no hook-runs=2 | deny/no hook-runs=2 | deny/no hook-runs=2 |
| dedupe_identical_hook_twice | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 |
| matcher_exact_shell_vs_shell | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 |
| matcher_exact_shell_vs_mcp | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 |
| matcher_substring_vs_shell | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 |
| matcher_dotstar_search_notes_vs_mcp | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 |
| matcher_dotstar_search_notes_vs_mcp_dunder | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 |
| matcher_claude_style_mcp_vs_mcp | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 |
| matcher_claude_style_mcp_vs_dunder | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 |
| matcher_mcp_prefix_vs_mcp | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 |
| matcher_bash_vs_shell | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 |
| matcher_write_alt_vs_write_file | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 |
| matcher_write_alt_vs_shell | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 | none/yes hook-runs=0 |
| matcher_star_vs_shell | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 |
| matcher_empty_vs_shell | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 |
| matcher_absent_vs_shell | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 |
| matcher_invalid_regex_literal_vs_literal | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 | deny/no hook-runs=1 |
| config_default_enableHooks | getEnableHooks=False | getEnableHooks=False | getEnableHooks=True | getEnableHooks=True | getEnableHooks=True |

Version groups: [0.20.2 .. 0.22.5] = 0.20.2, 0.22.5; [0.24.5 .. 0.25.2] = 0.24.5, 0.25.2; [0.26.0 .. 0.29.7] = 0.26.0, 0.27.4, 0.28.2, 0.29.7; [0.30.0 .. 0.35.3] = 0.30.0, 0.30.1, 0.32.1, 0.33.2, 0.34.0, 0.35.3; [0.36.0 .. 0.67.0-preview.0] = 0.36.0, 0.37.1, 0.38.2, 0.40.1, 0.45.3, 0.50.0, 0.55.1, 0.60.0, 0.66.0, 0.67.0-nightly.20261031.g6814e00d6, 0.67.0-preview.0

Cells are `decision/proceeds`; `hook-runs` is how many times a hook process ran (a matcher that does not select the tool gives none/yes with 0 runs). One Config, one HookSystem, the event handler of that release; nothing downstream of the hook output is driven here (see table-consumer.md).
