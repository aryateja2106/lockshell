# lockshell — install + multi-account + dashboard demo
#
# Renders to demo/install-and-broker.gif via:
#   vhs demo/install-and-broker.tape
#
# Goals (in 30s):
#   1. Show one-line install
#   2. Show `lockshell help-me` (briefly)
#   3. Show multi-account list with --grep
#   4. Open the dashboard
#
# Notes:
#   - The actual API call demo lives as static example output in README,
#     because VHS subshells don't inherit the agent-password session.

Output demo/install-and-broker.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 720
Set Padding 20
Set TypingSpeed 35ms
Set PlaybackSpeed 1.0
Set Theme "TokyoNight"

# ─── Scene 1: install ──────────────────────────────────────────────────────────
Type "# Install on macOS. No Rust required."
Sleep 700ms
Enter
Type "curl -fsSL https://raw.githubusercontent.com/aryateja2106/lockshell/main/install.sh | bash"
Sleep 500ms
Enter
Sleep 5s

# ─── Scene 2: help-me ──────────────────────────────────────────────────────────
Ctrl+L
Type "# Beginner-friendly tour, all in one screen."
Sleep 500ms
Enter
Type "lockshell help-me | head -28"
Sleep 400ms
Enter
Sleep 4s

# ─── Scene 3: multi-account ────────────────────────────────────────────────────
Ctrl+L
Type "# Multiple accounts? Use suffix conventions, then --grep to find them."
Sleep 500ms
Enter
Type "lockshell list"
Sleep 400ms
Enter
Sleep 2s
Type "lockshell list --grep supabase"
Sleep 400ms
Enter
Sleep 3s

# ─── Scene 4: audit log ────────────────────────────────────────────────────────
Ctrl+L
Type "# Every brokered call records template + reason. Never values."
Sleep 500ms
Enter
Type "lockshell audit -n 3"
Sleep 400ms
Enter
Sleep 4s

# ─── Scene 5: dashboard ────────────────────────────────────────────────────────
Ctrl+L
Type "# Local HTML dashboard. No daemon, no server."
Sleep 500ms
Enter
Type "lockshell dashboard --no-open --out /tmp/lockshell-dash.html"
Sleep 400ms
Enter
Sleep 2s
Type "echo 'open' /tmp/lockshell-dash.html"
Sleep 400ms
Enter
Sleep 2s
