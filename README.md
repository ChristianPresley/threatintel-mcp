# threatintel-mcp

An [MCP](https://modelcontextprotocol.io) server that wraps threat-intelligence
lookup APIs — **urlscan.io** and **VirusTotal** — so an AI agent (e.g. Claude)
can pivot on indicators during an investigation the way an analyst does at a
terminal.

> **This is a portfolio demonstration.** It is a compact, self-contained example
> built to show design judgment around MCP servers for threat intelligence:
> tool ergonomics, compact/structured output, rate-limit hygiene, OPSEC, and
> treating tool output as untrusted. It is not a production incident-response
> platform, and it wraps only a small slice of each provider's API.

---

## Why this exists

When you investigate a suspicious indicator, you pivot: a URL leads to a domain,
the domain resolves to an IP, the IP belongs to an ASN, a dropped file has a
hash, that hash shows up on other scans. Each hop is an API call to a different
threat-intel platform.

Exposing those platforms as **MCP tools** lets an agent do that pivoting
autonomously and in natural language — "is this domain malicious, and what else
lives on its hosting?" — while the human stays in the loop for judgment. MCP is
the clean seam for this: one small server, any MCP-capable client.

## What it does — the tools

| Tool | Provider | Purpose |
|------|----------|---------|
| `scan_url` | urlscan.io | Submit a URL for a live sandbox scan (returns a `uuid`). |
| `get_url_result` | urlscan.io | Poll a scan `uuid` for the verdict + contacted infrastructure. |
| `search_urlscan` | urlscan.io | Passively search historical scans (Elasticsearch query syntax). |
| `lookup_hash` | VirusTotal v3 | Multi-engine verdict + threat label for a file hash (MD5/SHA-1/SHA-256). |
| `lookup_domain` | VirusTotal v3 | Reputation, registrar, creation date, categories for a domain. |
| `lookup_ip` | VirusTotal v3 | Reputation + hosting context (ASN, owner, country) for an IP. |

Each tool's docstring is written as a **"when to call me"** prompt — FastMCP
turns the type hints and docstring into the JSON Schema and description the model
sees, so the tools are self-documenting to the agent.

## Architecture & design decisions

**Three urlscan primitives, three VT lookups.** urlscan is modeled around its own
submit → poll → search loop; VirusTotal around direct object lookups. That
mapping keeps each tool a thin, predictable wrapper over one endpoint.

**Compact, structured output — not raw API JSON.** A single VirusTotal file
report or urlscan result can be hundreds of KB (every AV engine's verdict, the
full DOM, every request/response). Dumping that into a model's context is
wasteful and buries the signal. Every tool projects the response down to the
handful of fields an investigator actually pivots on — detection ratio, threat
label, reputation, ASN/owner, contacted domains/IPs, first/last seen. This is a
deliberate design choice, commented at each `summarize_*` function in
`virustotal.py` / `urlscan.py`.

**All tool output is treated as untrusted and defanged.** Threat-intel responses
contain *attacker-controlled* content — a phishing page's title, a malicious
domain, a WHOIS record. MCP tool output is a **prompt-injection surface** for the
model and a **click-hazard** for a human reading a terminal. So every indicator
is defanged on the way out (`http` → `hxxp`, `evil.test` → `evil[.]test`,
`1.2.3.4` → `1[.]2[.]3[.]4`) at a single central choke point (`sanitize.py`).

**Client-side rate limiting.** The VirusTotal public tier allows 4 req/min and
500/day. A per-API sliding-window limiter (`ratelimit.py`) throttles locally so a
well-behaved server never trips the upstream 429 under normal single-analyst use.

**Structured errors, never raw tracebacks.** Auth failures, 404s, upstream 429s,
timeouts and local rate-limit hits are all mapped to small categorized dicts
(`errors.py`) so the agent can decide whether to retry, back off, or ask for a
key.

**Secrets from the environment only.** `VT_API_KEY` and `URLSCAN_API_KEY` are
read from the environment (or a local, gitignored `.env`). Nothing is hardcoded.

### Transports: stdio vs. Streamable HTTP

- **stdio** (default) — the client spawns the server as a subprocess over
  stdin/stdout. Best for a **single local analyst** running Claude Desktop or an
  IDE MCP client on their own workstation with their own keys.
- **Streamable HTTP** (`--transport http`) — the server runs as a long-lived
  networked process. Best for a **shared team deployment**: one server holding
  the org's keys and rate-limit budget, many analysts pointing their clients at
  it.

## Setup

Requires Python 3.10+.

```bash
git clone https://github.com/ChristianPresley/threatintel-mcp.git
cd threatintel-mcp
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

cp .env.example .env             # then edit .env and add your keys
```

Get API keys:
- VirusTotal: <https://www.virustotal.com/gui/my-apikey>
- urlscan.io: <https://urlscan.io/user/profile/>

## Running

```bash
# stdio (local analyst) — this is what an MCP client launches for you:
threatintel-mcp --transport stdio

# Streamable HTTP (shared team) — long-lived server on a port:
threatintel-mcp --transport http --host 0.0.0.0 --port 8000
```

### Claude Desktop / MCP client config

Add to `claude_desktop_config.json` (macOS:
`~/Library/Application Support/Claude/`, Windows:
`%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "threatintel": {
      "command": "threatintel-mcp",
      "args": ["--transport", "stdio"],
      "env": {
        "VT_API_KEY": "your-virustotal-key",
        "URLSCAN_API_KEY": "your-urlscan-key"
      }
    }
  }
}
```

If `threatintel-mcp` isn't on the client's `PATH`, use the absolute path to the
venv entry point (e.g. `.venv/Scripts/threatintel-mcp.exe` on Windows) or invoke
via `python -m threatintel_mcp.server`.

## Worked example: pivoting a suspicious domain

An analyst hands the agent a suspicious link. A natural investigation flow:

1. **`scan_url("http://secure-login-microsoft.example/")`** — submits an
   *unlisted* scan (so the adversary isn't tipped off) and returns a `uuid`.
2. **`get_url_result(uuid)`** — comes back `malicious: true`, brand
   `Microsoft` (credential phish), and a set of contacted domains/IPs including
   `page_ip: 203[.]0[.]113[.]9` on ASN `EVIL-HOST`.
3. **`lookup_domain("secure-login-microsoft.example")`** — VT shows a creation
   date three days ago (newly-registered-domain signal) and a couple of engines
   already flagging it.
4. **`lookup_ip("203.0.113.9")`** — the hosting IP has poor reputation and hosts
   in a country inconsistent with the impersonated brand.
5. **`search_urlscan("page.ip:203.0.113.9")`** — passively reveals *other*
   phishing pages on the same box, expanding the campaign's footprint.

Five hops, two providers, one MCP server — and every indicator in the transcript
is defanged so nothing is accidentally clicked or re-interpreted downstream.

## Development

```bash
pytest          # runs the mocked test suite — no real API calls are made
ruff check .    # lint
```

Tests mock every HTTP interaction with `respx`; the suite never touches the
network and needs no real API keys.

## License

MIT © 2026 Christian Presley — see [LICENSE](LICENSE).
