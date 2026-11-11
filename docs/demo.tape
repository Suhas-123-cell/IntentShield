# Renders docs/demo.gif with VHS (https://github.com/charmbracelet/vhs).
# Run from the repo root with intentshield on your PATH (for example after `uv tool install intentshield-mcp`):  vhs docs/demo.tape

Output docs/demo.gif

Set Shell bash
Set FontSize 14
Set Width 1200
Set Height 480
Set Padding 20
Set TypingSpeed 40ms
Set Theme "Catppuccin Mocha"

Hide
Type "export PS1='$ ' INTENTSHIELD_HOOK_DB=$(mktemp -d)/hooks.db && clear"
Enter
Show

Type "# Sample calls through the real hook. Nothing is run."
Enter
Sleep 1s
Type "intentshield demo"
Enter
Sleep 12s
