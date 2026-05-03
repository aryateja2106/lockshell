// SPDX-License-Identifier: Apache-2.0
//
// `lockshell dashboard` — renders a self-contained HTML page summarising
// the local lockshell state: registered placeholders, recent audit log,
// and (best-effort) the agent-password session status. No daemon, no
// server, no extra deps. The page is regenerated each time the command
// is run.
//
// This is the v0.1 ancestor of the v0.4 menu bar app. The data shape is
// the same; the renderer is just HTML instead of SwiftUI.

use crate::audit_log;
use crate::cli::DashboardArgs;
use crate::registry;
use crate::ui;
use anyhow::Result;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run(args: DashboardArgs) -> Result<()> {
    let registry = registry::load()?;
    let audit = audit_log::tail(args.lines).unwrap_or_default();
    let session_text = session_summary();

    let html = render(&registry, &audit, &session_text);

    let out_path = match args.out {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            std::env::temp_dir().join(format!("lockshell-dashboard-{}.html", ts))
        }
    };

    std::fs::write(&out_path, html)?;
    ui::ok(&format!("dashboard rendered to {}", out_path.display()));

    if !args.no_open {
        // Open in default browser via macOS `open`. On other platforms this
        // would use xdg-open, but lockshell is macOS-only in v0.1.
        let _ = Command::new("open").arg(&out_path).status();
    } else {
        println!("Open with: open {}", out_path.display());
    }

    Ok(())
}

fn session_summary() -> String {
    // Best-effort. If agent-password is missing or unresponsive, show a friendly note.
    let status = Command::new("agent-password")
        .args(["session", "status"])
        .output();
    match status {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
        Ok(out) => format!(
            "agent-password reported a non-zero exit:\n{}",
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(_) => "agent-password is not installed or could not be invoked.".to_string(),
    }
}

fn render(
    registry: &[registry::Mapping],
    audit: &[audit_log::Entry],
    session_text: &str,
) -> String {
    let registry_rows = if registry.is_empty() {
        "<tr><td colspan=\"3\" class=\"muted\">No placeholders registered yet. \
         Run <code>lockshell register &lt;ENV_NAME&gt; &lt;vault-id&gt; &lt;field&gt;</code>.</td></tr>"
            .to_string()
    } else {
        registry
            .iter()
            .map(|m| {
                format!(
                    "<tr><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td></tr>",
                    escape(&m.env_name),
                    escape(&m.vault_id),
                    escape(&m.field)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let audit_rows = if audit.is_empty() {
        "<tr><td colspan=\"4\" class=\"muted\">No audit entries yet. \
         Run a command with <code>lockshell run --reason \"...\" -- ...</code>.</td></tr>"
            .to_string()
    } else {
        audit
            .iter()
            .rev()
            .map(|e| {
                let secrets = if e.secrets.is_empty() {
                    "<span class=\"muted\">(none)</span>".to_string()
                } else {
                    e.secrets
                        .iter()
                        .map(|s| format!("<code>{}</code>", escape(s)))
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                format!(
                    "<tr><td class=\"ts\">{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
                    escape(&e.timestamp),
                    escape(&e.reason),
                    escape(&truncate(&e.template, 120)),
                    secrets
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let version = env!("CARGO_PKG_VERSION");

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>lockshell dashboard</title>
<style>
:root {{
  --bg: #0f1115;
  --panel: #161922;
  --border: #262b38;
  --text: #e6e8ee;
  --muted: #8a93a6;
  --accent: #8aff80;
  --warn: #ffcd5b;
  --danger: #ff6b6b;
  --code-bg: #0a0c11;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}}
.container {{ max-width: 980px; margin: 0 auto; padding: 32px 24px; }}
header {{ display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 24px; }}
header h1 {{ margin: 0; font-size: 28px; font-weight: 600; letter-spacing: -0.02em; }}
header .meta {{ color: var(--muted); font-size: 13px; }}
.tagline {{ color: var(--muted); margin: -16px 0 32px 0; font-size: 14px; }}
.panel {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px 24px;
  margin-bottom: 24px;
}}
.panel h2 {{
  margin: 0 0 12px 0;
  font-size: 14px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
}}
.panel .count {{ color: var(--accent); font-weight: 600; }}
table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
th {{
  text-align: left;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
  padding: 8px 8px;
  border-bottom: 1px solid var(--border);
}}
td {{ padding: 10px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }}
tr:last-child td {{ border-bottom: none; }}
code {{
  background: var(--code-bg);
  padding: 2px 6px;
  border-radius: 4px;
  font-family: ui-monospace, "SF Mono", Menlo, monospace;
  font-size: 12.5px;
  color: var(--text);
  word-break: break-all;
}}
.muted {{ color: var(--muted); }}
.ts {{ font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12.5px; color: var(--muted); white-space: nowrap; }}
pre.session {{
  background: var(--code-bg);
  padding: 12px 16px;
  border-radius: 8px;
  font-size: 12.5px;
  overflow-x: auto;
  color: var(--text);
  margin: 0;
}}
.actions {{ margin-top: 16px; }}
.actions code {{ display: block; padding: 8px 12px; margin: 4px 0; }}
footer {{
  color: var(--muted);
  font-size: 12px;
  margin-top: 24px;
  text-align: center;
}}
footer a {{ color: var(--muted); }}
.legend {{ font-size: 12px; color: var(--muted); margin-top: 8px; }}
</style>
</head>
<body>
<div class="container">

  <header>
    <h1>lockshell dashboard</h1>
    <div class="meta">v{version} · generated {now}</div>
  </header>

  <div class="tagline">
    Read-only snapshot of your local broker. Re-run <code>lockshell dashboard</code> to refresh. No values shown — by design.
  </div>

  <section class="panel">
    <h2>Session <span class="count">·</span> agent-password</h2>
    <pre class="session">{session}</pre>
  </section>

  <section class="panel">
    <h2>Registered placeholders <span class="count">{registry_count}</span></h2>
    <table>
      <thead><tr><th>Placeholder</th><th>Vault ID</th><th>Field</th></tr></thead>
      <tbody>
{registry_rows}
      </tbody>
    </table>
    <div class="legend">Add another with <code>lockshell register &lt;ENV_NAME&gt; &lt;vault-id&gt; &lt;field&gt;</code>.</div>
  </section>

  <section class="panel">
    <h2>Recent audit entries <span class="count">{audit_count}</span></h2>
    <table>
      <thead><tr><th>When</th><th>Reason</th><th>Template (truncated)</th><th>Secrets used</th></tr></thead>
      <tbody>
{audit_rows}
      </tbody>
    </table>
    <div class="legend">No values are ever stored. Templates show the placeholder names that were resolved.</div>
  </section>

  <section class="panel">
    <h2>Quick actions</h2>
    <div class="actions">
      <code>lockshell help-me</code>
      <code>lockshell doctor</code>
      <code>lockshell run --reason &quot;...&quot; -- &lt;cmd&gt;</code>
      <code>agent-password session close</code>
      <code>agent-password session create</code>
    </div>
  </section>

  <footer>
    lockshell · <a href="https://github.com/aryateja2106/lockshell">github.com/aryateja2106/lockshell</a> · Apache-2.0
  </footer>
</div>
</body>
</html>
"#,
        version = version,
        now = escape(&now),
        session = escape(session_text),
        registry_count = registry.len(),
        registry_rows = registry_rows,
        audit_count = audit.len(),
        audit_rows = audit_rows,
    )
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut t = s.chars().take(n).collect::<String>();
        t.push('…');
        t
    }
}
