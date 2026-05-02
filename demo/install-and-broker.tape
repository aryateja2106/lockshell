# lockshell — install + brokered API call demo
#
# Renders to demo/install-and-broker.gif via:
#   vhs demo/install-and-broker.tape
#
# Goals (in 30s):
#   1. Show one-line install
#   2. Show `lockshell help-me`
#   3. Show `lockshell list` with multi-account
#   4. Run a real brokered API call
#   5. Open the dashboard
#
# Constraints:
#   - No real secret values on screen (the vault entries are demo placeholders)
#   - Output redactor catches the token format if it slips
#   - Frame size tuned for README hero placement

Output demo/install-and-broker.gif

Set Shell "bash"
Set FontSize 13
Set Width 1100
Set Height 680
Set Padding 20
Set TypingSpeed 35ms
Set PlaybackSpeed 1.0
Set Theme "TokyoNight"

# ─── Scene 1: install ──────────────────────────────────────────────────────────
Type "# Install lockshell with one curl. macOS, no Rust required."
Sleep 700ms
Enter
Type "curl -fsSL https://raw.githubusercontent.com/aryateja2106/lockshell/main/install.sh | bash"
Sleep 700ms
Enter
Sleep 4s

# ─── Scene 2: help-me ──────────────────────────────────────────────────────────
Ctrl+L
Type "# Step-by-step beginner tour, all in one screen."
Sleep 700ms
Enter
Type "lockshell help-me | head -30"
Sleep 500ms
Enter
Sleep 3s

# ─── Scene 3: multi-account ────────────────────────────────────────────────────
Ctrl+L
Type "# Multiple accounts? Use suffixed placeholders."
Enter
Type "lockshell list"
Sleep 400ms
Enter
Sleep 1500ms
Type "lockshell list --grep supabase"
Sleep 400ms
Enter
Sleep 2s

# ─── Scene 4: real API call ────────────────────────────────────────────────────
Ctrl+L
Type "# Run a real Linear API call. The agent never sees the key."
Enter
Type `lockshell run --reason "fetch viewer info" -- \`
Enter
Type `  'curl -s -X POST -H "Authorization: {{LINEAR_API_KEY}}" \`
Enter
Type `    -H "Content-Type: application/json" \`
Enter
Type `    --data "{\"query\":\"{ viewer { name } }\"}" \`
Enter
Type `    https://api.linear.app/graphql'`
Enter
Sleep 4s

# ─── Scene 5: audit log ────────────────────────────────────────────────────────
Ctrl+L
Type "# Audit log records the template + reason. Never values."
Enter
Type "lockshell audit -n 3"
Sleep 400ms
Enter
Sleep 4s

# ─── Scene 6: dashboard ────────────────────────────────────────────────────────
Ctrl+L
Type "# Local HTML dashboard. No daemon, no server."
Enter
Type "lockshell dashboard --no-open --out /tmp/lockshell-dash.html"
Sleep 400ms
Enter
Sleep 1500ms
Type "echo 'Open with: open /tmp/lockshell-dash.html'"
Enter
Sleep 2s
