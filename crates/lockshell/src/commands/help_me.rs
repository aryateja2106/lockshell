// SPDX-License-Identifier: Apache-2.0
//
// `lockshell help-me` — a beginner-friendly tour written for someone who
// has never used a terminal-first secret manager before. We render this
// as a single, scrollable narrative so anyone can read it top-to-bottom
// and copy each command they need.

use crate::ui;

const GUIDE: &str = r#"
WHAT IS LOCKSHELL?
──────────────────
Lockshell is a tiny program that lets AI agents call APIs on your behalf
WITHOUT ever seeing your API keys.

The agent writes a command like:

    curl -H "Authorization: {{LINEAR_API_KEY}}" https://api.linear.app/graphql

Lockshell looks at {{LINEAR_API_KEY}}, fetches the real value from your
local vault, runs the command, and shows you only the response. The key
itself never enters the chat, never enters the cloud, never enters your
shell history, never enters the process argument list.

You only have to grant access ONCE per session (with Touch ID).


THE FIVE COMMANDS YOU WILL USE
──────────────────────────────
  lockshell setup            ← run this ONCE the first time
  lockshell list             ← see what placeholders are registered
  lockshell run              ← the daily-driver. Runs a brokered command.
  lockshell status           ← shows session unlock state
  lockshell audit            ← shows recent invocations (no values)

That is it. The other commands (register, unregister, request, doctor,
version, help-me) are utilities you will reach for occasionally.


YOUR FIRST FIVE MINUTES (do these IN ORDER)
───────────────────────────────────────────

STEP 1.  Make sure agent-password is installed.

    lockshell doctor

If the doctor says "agent-password not found", install it like this:

    cargo install --git https://github.com/tartavull/agent-password agent-password

(If you do not have Rust, install it first with:
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh)


STEP 2.  Initialize your vault and start a session.

    agent-password vault init     ← only the first time, ever
    agent-password session create ← every time you reboot or close the session


STEP 3.  Add your first secret WITHOUT typing it into chat.

    Suppose you have a Linear API key. In your terminal (NOT in chat):

      printf '%s' 'YOUR_LINEAR_KEY_HERE' | agent-password login add linear-api \
        --username you --url https://linear.app \
        --password-stdin --tag agent

    The 'printf | agent-password' part means the value travels through
    a pipe directly into the vault. It is not visible in your shell
    history, not visible to other processes, not visible to anyone
    looking over your shoulder unless they were watching when you
    pasted.

    TIP: paste-from-clipboard is even safer:
      pbpaste | agent-password login add linear-api \
        --username you --url https://linear.app \
        --password-stdin --tag agent


STEP 4.  Tell lockshell what placeholder name to use for that secret.

    lockshell register LINEAR_API_KEY linear-api password

    Now whenever any agent writes {{LINEAR_API_KEY}} in a command,
    lockshell knows to look up the 'linear-api' secret's 'password'
    field.


STEP 5.  Approve the secret for this session (one Touch ID).

    agent-password secrets request linear-api --requester you \
      --reason "first call"
    agent-password requests list
    agent-password requests approve <ID> all

    The third line will prompt for Touch ID. After that, every
    'lockshell run' that uses LINEAR_API_KEY in this session works
    without re-prompting.


YOU ARE DONE. TRY IT:

    lockshell run --reason "verify linear works" -- \
      'curl -s -X POST -H "Authorization: {{LINEAR_API_KEY}}" \
        -H "Content-Type: application/json" \
        --data "{\"query\":\"{ viewer { name } }\"}" \
        https://api.linear.app/graphql'

You will see your Linear viewer name. Your key was never visible.


COMMON PROVIDERS — RECIPES
──────────────────────────
For each provider below, the FIRST line is what to paste into a
terminal (replacing YOUR_KEY). The SECOND line tells lockshell the
placeholder name to use.

  Linear:
    pbpaste | agent-password login add linear-api --username you \
      --url https://linear.app --password-stdin --tag agent
    lockshell register LINEAR_API_KEY linear-api password

  GitHub PAT:
    pbpaste | agent-password login add github-pat --username you \
      --url https://github.com --password-stdin --tag agent
    lockshell register GITHUB_TOKEN github-pat password

  OpenAI:
    pbpaste | agent-password login add openai --username you \
      --url https://platform.openai.com --password-stdin --tag agent
    lockshell register OPENAI_API_KEY openai password

  Anthropic:
    pbpaste | agent-password login add anthropic --username you \
      --url https://console.anthropic.com --password-stdin --tag agent
    lockshell register ANTHROPIC_API_KEY anthropic password

  Vercel:
    pbpaste | agent-password login add vercel --username you \
      --url https://vercel.com --password-stdin --tag agent
    lockshell register VERCEL_TOKEN vercel password

  Supabase:
    pbpaste | agent-password login add supabase --username you \
      --url https://supabase.com --password-stdin --tag agent
    lockshell register SUPABASE_ACCESS_TOKEN supabase password

  Cloudflare (be careful — Cloudflare tokens give wide access):
    pbpaste | agent-password login add cloudflare --username you \
      --url https://dash.cloudflare.com --password-stdin --tag agent
    lockshell register CLOUDFLARE_API_TOKEN cloudflare password


WHEN THINGS GO WRONG
────────────────────
  "not approved" error    → see Step 5 above (request → list → approve)
  "no shared session"     → run: agent-password session create
  "not registered"        → see Step 4 (lockshell register …)
  any other weird error   → run: lockshell doctor


HARD RULES (FOR YOU AND YOUR AGENTS)
────────────────────────────────────
  1. NEVER paste a secret value into chat. Always pipe via stdin.
  2. NEVER write the literal value of a secret into a command.
     Always use {{PLACEHOLDER}} syntax.
  3. NEVER share your ~/.config/lockshell/ or ~/.agent-password/
     directories. They contain your vault and audit history.
  4. The redactor catches KNOWN token formats only. Always assume it
     might miss novel formats; do not treat it as a guarantee.

That's it. Welcome to lockshell. For more, run:

    lockshell --help
    lockshell <subcommand> --help

Or visit: https://github.com/aryateja2106/lockshell

"#;

pub fn run() -> anyhow::Result<()> {
    print!("{}", GUIDE);
    let _ = ui::ok;
    Ok(())
}
