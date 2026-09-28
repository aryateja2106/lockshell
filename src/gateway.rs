// SPDX-License-Identifier: Apache-2.0
//
// `lockshell gateway`: a local, OpenAI-compatible front door to model providers.
//
// Agents and tools call http://127.0.0.1:8787/v1 with a LOCAL client token and
// name models "<provider>/<model>". The gateway is the only process that holds
// provider API keys (read from the Keychain once, at startup). Per request it:
//   1. checks the local client token (constant-time)
//   2. allows only providers/models listed in gateway.json
//   3. masks outgoing text (message content AND earlier tool-call arguments),
//      and unmasks the reply locally
//   4. enforces a daily token budget and a max_tokens cap
//   5. appends an audit line with hashes and counts, never text
// Upstream is always called non-streaming (so the full reply can be unmasked);
// clients that ask for `stream: true` get the finished reply replayed as SSE.

use crate::{keychain, mask, registry, ui};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Provider {
    pub base_url: String,
    /// lockshell key name (see `lockshell key add`); null for local providers
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default = "yes")]
    pub mask: bool,
    pub models: Vec<String>,
}

fn yes() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub max_tokens_cap: u64,
    pub daily_token_budget: u64,
    pub max_body_bytes: u64,
    #[serde(default)]
    pub terms_file: Option<String>,
    #[serde(default)]
    pub allowlist_file: Option<String>,
    pub providers: BTreeMap<String, Provider>,
}

impl Default for Config {
    fn default() -> Self {
        let mut providers = BTreeMap::new();
        providers.insert(
            "fireworks".into(),
            Provider {
                base_url: "https://api.fireworks.ai/inference/v1".into(),
                key: Some("fireworks".into()),
                mask: true,
                models: vec!["accounts/fireworks/models/deepseek-v4p1-flash".into()],
            },
        );
        providers.insert(
            "apple".into(),
            Provider {
                base_url: "http://127.0.0.1:1976/v1".into(), // `fm serve --port 1976`
                key: None,
                mask: false, // on-device: nothing leaves the machine
                models: vec!["system".into()],
            },
        );
        Config {
            host: "127.0.0.1".into(),
            port: 8787,
            max_tokens_cap: 8192,
            daily_token_budget: 2_000_000,
            max_body_bytes: 8 * 1024 * 1024,
            terms_file: None,
            allowlist_file: None,
            providers,
        }
    }
}

pub fn config_path() -> PathBuf {
    registry::config_dir().join("gateway.json")
}
pub fn token_path() -> PathBuf {
    registry::config_dir().join("gateway-token")
}
pub fn audit_path() -> PathBuf {
    registry::config_dir().join("gateway-audit.jsonl")
}

fn write_private(path: &PathBuf, data: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(data.as_bytes())?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(())
}

pub fn load_config() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        write_private(&path, &serde_json::to_string_pretty(&Config::default())?)?;
        ui::info(&format!("wrote default gateway config to {}", path.display()));
    }
    let cfg: Config = serde_json::from_str(&fs::read_to_string(&path)?)
        .with_context(|| format!("parsing {}", path.display()))?;
    let ip: IpAddr = cfg.host.parse().context("gateway host must be an IP address")?;
    if !ip.is_loopback() {
        bail!("refusing to listen on {}: the gateway only binds to loopback (127.0.0.1 / ::1)", cfg.host);
    }
    Ok(cfg)
}

pub fn client_token() -> Result<String> {
    let path = token_path();
    if !path.exists() {
        let mut buf = [0u8; 32];
        fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
        let tok: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
        write_private(&path, &tok)?;
    }
    Ok(fs::read_to_string(path)?.trim().to_string())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn short_sha(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

fn tokens_used_today() -> u64 {
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    fs::read_to_string(audit_path())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["ts"].as_str().is_some_and(|t| t.starts_with(&today)))
        .map(|e| e["total_tokens"].as_u64().unwrap_or(0))
        .sum()
}

fn audit(mut entry: Value) {
    entry["ts"] = json!(chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string());
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).mode(0o600).open(audit_path()) {
        let _ = writeln!(f, "{}", entry);
    }
}

struct State {
    cfg: Config,
    token: String,
    keys: HashMap<String, Zeroizing<String>>,
    http: ureq::Agent,
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("valid header")
}

fn send_json(rq: Request, code: u16, body: &Value) {
    let _ = rq.respond(
        Response::from_string(body.to_string())
            .with_status_code(code)
            .with_header(header("Content-Type", "application/json")),
    );
}

fn err(rq: Request, code: u16, msg: &str) {
    send_json(rq, code, &json!({"error": {"message": msg, "code": code}}));
}

/// Replay a finished completion as Server-Sent Events.
fn send_as_stream(rq: Request, resp: &Value) {
    let base = json!({
        "id": resp.get("id").cloned().unwrap_or(json!("lockshell")),
        "object": "chat.completion.chunk",
        "created": resp.get("created").cloned().unwrap_or(json!(0)),
        "model": resp.get("model").cloned().unwrap_or(json!("")),
    });
    let mut out = String::new();
    let mut push = |choices: Value, extra: Option<(&str, Value)>| {
        let mut chunk = base.clone();
        chunk["choices"] = choices;
        if let Some((k, v)) = extra {
            chunk[k] = v;
        }
        out.push_str(&format!("data: {}\n\n", chunk));
    };
    for ch in resp["choices"].as_array().cloned().unwrap_or_default() {
        let idx = ch.get("index").cloned().unwrap_or(json!(0));
        let msg = &ch["message"];
        let mut delta = json!({"role": "assistant"});
        if !msg["content"].is_null() {
            delta["content"] = msg["content"].clone();
        }
        if let Some(tcs) = msg["tool_calls"].as_array() {
            let tcs: Vec<Value> = tcs
                .iter()
                .enumerate()
                .map(|(i, tc)| {
                    let mut tc = tc.clone();
                    tc["index"] = json!(i);
                    tc
                })
                .collect();
            delta["tool_calls"] = json!(tcs);
        }
        push(json!([{"index": idx, "delta": delta, "finish_reason": null}]), None);
        push(json!([{"index": idx, "delta": {}, "finish_reason": ch["finish_reason"]}]), None);
    }
    if !resp["usage"].is_null() {
        push(json!([]), Some(("usage", resp["usage"].clone())));
    }
    out.push_str("data: [DONE]\n\n");
    let _ = rq.respond(
        Response::from_string(out)
            .with_header(header("Content-Type", "text/event-stream"))
            .with_header(header("Cache-Control", "no-cache")),
    );
}

fn mask_value(masker: &mask::Masker, map: &mut mask::Mapping, v: &mut Value) {
    if let Some(s) = v.as_str() {
        *v = json!(masker.mask(s, map));
    }
}

/// Replace every occurrence of a secret the gateway itself knows (the local client
/// token and every loaded provider key) with a fixed marker, whatever the provider.
/// An agent that read one of these by mistake (or was tricked into it) cannot pass it
/// upstream. Unlike masking, this is never reversed in the reply.
fn scrub_secrets(secrets: &[&str], v: &mut Value, scrubbed: &mut usize) {
    if let Some(s) = v.as_str() {
        let mut out = s.to_string();
        for sec in secrets.iter().filter(|x| x.len() >= 8) {
            let n = out.matches(sec).count();
            if n > 0 {
                *scrubbed += n;
                out = out.replace(sec, "[SECRET_REDACTED]");
            }
        }
        if out != s {
            *v = json!(out);
        }
    }
}

fn unmask_value(map: &mask::Mapping, v: &mut Value) {
    if let Some(s) = v.as_str() {
        *v = json!(mask::Masker::unmask(s, map));
    }
}

fn handle(state: Arc<State>, mut rq: Request) {
    let auth = rq
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .map(|h| h.value.as_str().trim_start_matches("Bearer ").trim().to_string())
        .unwrap_or_default();
    if !ct_eq(auth.as_bytes(), state.token.as_bytes()) {
        return err(rq, 401, "bad client token");
    }
    let path = rq.url().split('?').next().unwrap_or("").trim_end_matches('/').to_string();
    let cfg = &state.cfg;

    match (rq.method(), path.as_str()) {
        (Method::Get, "/health") => {
            let fps: BTreeMap<_, _> =
                state.keys.iter().map(|(k, v)| (k.clone(), keychain::fingerprint(v))).collect();
            return send_json(rq, 200, &json!({"ok": true, "tokens_today": tokens_used_today(), "keys": fps}));
        }
        (Method::Get, "/v1/models") => {
            let data: Vec<Value> = cfg
                .providers
                .iter()
                .flat_map(|(p, pc)| {
                    pc.models.iter().map(move |m| json!({"id": format!("{p}/{m}"), "object": "model", "owned_by": p}))
                })
                .collect();
            return send_json(rq, 200, &json!({"object": "list", "data": data}));
        }
        (Method::Post, "/v1/chat/completions") => {}
        _ => return err(rq, 404, "only GET /v1/models, GET /health, POST /v1/chat/completions"),
    }

    let mut body = String::new();
    if rq.as_reader().take(cfg.max_body_bytes + 1).read_to_string(&mut body).is_err() {
        return err(rq, 400, "unreadable body");
    }
    if body.len() as u64 > cfg.max_body_bytes {
        return err(rq, 413, "request too large");
    }
    let mut req: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return err(rq, 400, "invalid JSON"),
    };

    let full_model = req["model"].as_str().unwrap_or("").to_string();
    let (provider, model) = full_model.split_once('/').unwrap_or((&full_model, ""));
    let pc = match cfg.providers.get(provider) {
        Some(pc) if pc.models.iter().any(|m| m == model) => pc.clone(),
        _ => return err(rq, 403, &format!("not on allowlist: {full_model} (see GET /v1/models)")),
    };
    let key = match &pc.key {
        Some(k) => match state.keys.get(k) {
            Some(v) => Some(v.clone()),
            None => return err(rq, 503, &format!("no key loaded for '{provider}'. Run: lockshell key add {k}")),
        },
        None => None,
    };
    if tokens_used_today() >= cfg.daily_token_budget {
        return err(rq, 429, "daily token budget reached");
    }

    // Mask everything text-like that goes upstream, including tool-call arguments
    // from earlier turns (those were unmasked on the way back to the client).
    let masker = match mask::Masker::load(
        &cfg.terms_file.as_ref().map(PathBuf::from).unwrap_or_else(mask::default_terms_path),
        &cfg.allowlist_file.as_ref().map(PathBuf::from).unwrap_or_else(mask::default_allowlist_path),
    ) {
        Ok(m) => m,
        Err(e) => return err(rq, 500, &format!("masker failed to load: {e}")),
    };
    let mut map = mask::Mapping::default();
    let mut scrubbed = 0usize;
    let secrets: Vec<&str> = std::iter::once(state.token.as_str())
        .chain(state.keys.values().map(|k| k.as_str()))
        .collect();
    if let Some(msgs) = req["messages"].as_array_mut() {
        for msg in msgs {
            if msg["content"].is_array() {
                return err(rq, 400, "only plain-text message content is allowed");
            }
            scrub_secrets(&secrets, &mut msg["content"], &mut scrubbed);
            if let Some(tcs) = msg["tool_calls"].as_array_mut() {
                for tc in tcs {
                    scrub_secrets(&secrets, &mut tc["function"]["arguments"], &mut scrubbed);
                }
            }
            if pc.mask {
                mask_value(&masker, &mut map, &mut msg["content"]);
                if let Some(tcs) = msg["tool_calls"].as_array_mut() {
                    for tc in tcs {
                        mask_value(&masker, &mut map, &mut tc["function"]["arguments"]);
                    }
                }
            }
        }
    }

    let wants_stream = req["stream"].as_bool().unwrap_or(false);
    req["model"] = json!(model);
    req["stream"] = json!(false);
    if let Some(o) = req.as_object_mut() {
        o.remove("stream_options");
    }
    for field in ["max_tokens", "max_completion_tokens"] {
        let asked = req[field].as_u64().unwrap_or(cfg.max_tokens_cap);
        if field == "max_tokens" || !req[field].is_null() {
            req[field] = json!(asked.min(cfg.max_tokens_cap));
        }
    }

    let outgoing = req.to_string();
    let url = format!("{}/chat/completions", pc.base_url.trim_end_matches('/'));
    let mut call = state.http.post(&url).set("Content-Type", "application/json");
    if let Some(k) = &key {
        call = call.set("Authorization", &format!("Bearer {}", k.as_str()));
    }
    let (status, mut resp): (u16, Value) = match call.send_string(&outgoing) {
        Ok(r) => (r.status(), r.into_json().unwrap_or(json!({"error": "unparseable upstream reply"}))),
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            (code, serde_json::from_str(&text).unwrap_or(json!({"error": text.chars().take(2000).collect::<String>()})))
        }
        Err(e) => return err(rq, 502, &format!("{provider} unreachable: {e}")),
    };

    if let Some(choices) = resp["choices"].as_array_mut() {
        for ch in choices {
            let msg = &mut ch["message"];
            unmask_value(&map, &mut msg["content"]);
            unmask_value(&map, &mut msg["reasoning_content"]);
            if let Some(tcs) = msg["tool_calls"].as_array_mut() {
                for tc in tcs {
                    unmask_value(&map, &mut tc["function"]["arguments"]);
                }
            }
        }
    }

    audit(json!({
        "provider": provider, "model": model, "status": status,
        "sent_sha": short_sha(&outgoing), "masked": map.counts(), "secrets_scrubbed": scrubbed,
        "prompt_tokens": resp["usage"]["prompt_tokens"].as_u64().unwrap_or(0),
        "total_tokens": resp["usage"]["total_tokens"].as_u64().unwrap_or(0),
    }));

    if wants_stream && status == 200 {
        send_as_stream(rq, &resp);
    } else {
        send_json(rq, status, &resp);
    }
}

pub fn serve() -> Result<()> {
    let cfg = load_config()?;
    let token = client_token()?;
    let mut keys = HashMap::new();
    for (name, pc) in &cfg.providers {
        match &pc.key {
            None => println!("  {:<12} local, no key", name),
            Some(k) => match keychain::get(k) {
                Ok(v) => {
                    println!("  {:<12} key {}", name, keychain::fingerprint(&v));
                    keys.insert(k.clone(), v);
                }
                Err(_) => println!("  {:<12} NO KEY. Add it with: lockshell key add {}", name, k),
            },
        }
    }
    let http = ureq::AgentBuilder::new().timeout(Duration::from_secs(300)).build();
    let addr = format!("{}:{}", cfg.host, cfg.port);
    let server = Server::http(&addr).map_err(|e| anyhow!("cannot listen on {addr}: {e}"))?;
    println!("lockshell gateway on http://{addr}/v1  (client token: {})  Ctrl-C to stop",
        token_path().display());
    let state = Arc::new(State { cfg, token, keys, http });
    for rq in server.incoming_requests() {
        let st = Arc::clone(&state);
        std::thread::spawn(move || handle(st, rq));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"", b"x"));
    }

    #[test]
    fn known_secrets_are_scrubbed_and_counted() {
        let secrets = ["local-client-token-123", "fw_realproviderkey456"];
        let mut v = json!("token local-client-token-123 and fw_realproviderkey456 twice fw_realproviderkey456");
        let mut n = 0;
        scrub_secrets(&secrets, &mut v, &mut n);
        assert_eq!(n, 3);
        assert_eq!(v, json!("token [SECRET_REDACTED] and [SECRET_REDACTED] twice [SECRET_REDACTED]"));
        let mut clean = json!("nothing secret here");
        scrub_secrets(&secrets, &mut clean, &mut n);
        assert_eq!(n, 3);
    }

    #[test]
    fn default_config_is_loopback_and_masks_cloud() {
        let c = Config::default();
        assert!(c.host.parse::<IpAddr>().unwrap().is_loopback());
        assert!(c.providers["fireworks"].mask);
        assert!(c.providers["fireworks"].key.is_some());
        assert!(c.providers["apple"].key.is_none());
    }
}
