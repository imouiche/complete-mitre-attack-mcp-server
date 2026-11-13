<div align="center">

# MITRE ATT&CK MCP Server

**65 MCP tools giving LLMs and agentic systems machine-callable access to the MITRE ATT&CK knowledge base**

[![MCP tools](https://img.shields.io/badge/MCP%20tools-65-0b7285)](#available-tools)
[![Domains](https://img.shields.io/badge/domains-Enterprise%20%7C%20Mobile%20%7C%20ICS-0b7285)](#available-tools)
[![ATT&CK](https://img.shields.io/badge/ATT%26CK-v20.1-1864ab)](#data-cache)
[![npm](https://img.shields.io/npm/v/@imouiche/mitre-attack-mcp-server.svg)](https://www.npmjs.com/package/@imouiche/mitre-attack-mcp-server)
[![npm downloads](https://img.shields.io/npm/dm/@imouiche/mitre-attack-mcp-server.svg)](https://www.npmjs.com/package/@imouiche/mitre-attack-mcp-server)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MCP Registry](https://img.shields.io/badge/MCP-Registered-success)](https://registry.modelcontextprotocol.io)
[![MCPRush security rating](https://mcprush.com/badge/imouiche-mitre-attack-mcp/compact.svg)](https://mcprush.com/to/imouiche-mitre-attack-mcp?ref=badge)

[Installation](#installation) · [Quick Start](#quick-start) · [Security](#security) · [Data Cache](#data-cache) · [Tools](#available-tools) · [Examples](#example-queries)

</div>

---

## Overview

The MITRE ATT&CK MCP Server exposes the MITRE ATT&CK framework over the Model
Context Protocol, giving LLMs and agentic systems structured, machine-callable
access to adversary tactics, techniques, threat groups, software, campaigns and
mitigations.

It reads the official STIX 2.1 bundles published by MITRE through the
`mitreattack-python` library. No scraping, no third-party API, no
reverse-engineered endpoints.

### 65 tools across three domains

| Area | Tools | Covers |
|---|---:|---|
| [Tactics, data sources and ICS](#tactics-data-sources-and-ics) | 12 | tactics, data components and what they detect, ICS assets, procedure examples |
| [Techniques](#techniques) | 11 | lookup by ATT&CK ID, keyword search, parent and sub-technique traversal, platform and tactic filters |
| [Generic STIX access](#generic-stix-access) | 10 | any object by STIX or ATT&CK ID, description search, created and modified filters, ID to name resolution |
| [Groups](#groups) | 10 | threat actors, aliases, the techniques and software they use, campaign attribution |
| [Software](#software) | 8 | malware and tools, aliases, the techniques they implement, who deploys them |
| [Campaigns](#campaigns) | 6 | campaigns, aliases, their techniques and software, attribution to groups |
| [Infrastructure and metadata](#infrastructure-and-metadata) | 5 | data status, entity counts, matrices, Navigator layer generation |
| [Mitigations](#mitigations) | 3 | mitigations and the techniques they address |

Covering **Enterprise, Mobile and ICS**, with relationship traversal throughout
— which groups use a technique, which software a campaign deployed, what
mitigates what — plus ATT&CK Navigator layer generation for coverage and gap
visualisation. All output is shaped for LLM consumption.

Registered in the official MCP Registry as
`io.github.imouiche/mitre-attack-mcp-server`.

---

## Installation

### Python (PyPI)

```bash
pip install mitre-mcp-server
```

Or with uv:

```bash
uv pip install mitre-mcp-server
```

### Node (npm)

```bash
npm install -g @imouiche/mitre-attack-mcp-server
```

Or without installing:

```bash
npx -y @imouiche/mitre-attack-mcp-server
```

> **The npm package needs a few minutes on first run.** It ships the Python
> source, not the Python dependencies. On first launch it creates a private
> virtualenv under `~/.mitre-mcp-server/runtime/`, installs the pinned
> dependencies into it, and downloads the ATT&CK STIX data. Subsequent runs
> start in a few seconds.
>
> Some MCP clients time out waiting for a server to respond, so warm the cache
> once from a terminal before configuring your client:
>
> ```bash
> npx -y @imouiche/mitre-attack-mcp-server --setup
> ```
>
> Python 3.12 or newer must be on `PATH`. `uv` is used when available and
> `venv` plus `pip` otherwise. Nothing is installed into your system or
> currently active Python environment.

#### Environment variables

| Variable | Effect |
|---|---|
| `MITRE_MCP_PYTHON` | Use this interpreter directly and skip virtualenv creation entirely. It must already satisfy the dependencies in `pyproject.toml`, including `mcp<2`. |
| `MITRE_MCP_RUNTIME_DIR` | Relocate the cached virtualenv. Default `~/.mitre-mcp-server/runtime/`. |
| `MITRE_MCP_DATA_DIR` | Relocate the ATT&CK data cache. Default `~/.mitre-mcp-server/data/`. |

### From source

```bash
git clone https://github.com/imouiche/complete-mitre-attack-mcp-server.git
cd complete-mitre-attack-mcp-server
uv sync
uv run python -m mitre_mcp_server.server
```

---

## Quick Start

### 1. Configure your client

Add the server to `claude_desktop_config.json`:

- **macOS** — `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows** — `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "mitre-attack": {
      "command": "npx",
      "args": ["-y", "@imouiche/mitre-attack-mcp-server"]
    }
  }
}
```

### 2. Restart the client

Quit Claude Desktop completely (Cmd+Q on macOS) and reopen it.

### 3. Query

> "What techniques does APT29 use for initial access?"
>
> "Generate an ATT&CK Navigator layer for ransomware groups"
>
> "Show me all Windows persistence techniques"

---

## Security

<div align="center">

<a href="https://mcprush.com/to/imouiche-mitre-attack-mcp?ref=badge"><img width="380" height="200" src="https://mcprush.com/badge/imouiche-mitre-attack-mcp/card.svg" alt="MITRE ATT&CK MCP Server on MCPRush: security rating A, low access, no sign-in, 65 tools, 14 compatible clients" /></a>

</div>

[MCPRush](https://mcprush.com/to/imouiche-mitre-attack-mcp?ref=badge) rates this
server **security A** with **low access** scope and **no sign-in** required.
That assessment is MCPRush's own, not an independent audit, but it reflects
properties you can verify directly in this repository:

- **No credentials.** The server reads no API keys, tokens or secrets. The only
  environment variables it consults are the three cache-location overrides
  documented above.
- **Narrow network scope.** The sole outbound request is the ATT&CK STIX
  download, performed by MITRE's own `mitreattack-python` library. There are no
  telemetry, analytics or third-party calls.
- **Integrity-checked data.** Downloads are verified against the expected hash
  published in MITRE's release manifest, so a corrupted or substituted bundle
  is rejected rather than loaded.
- **Local execution.** The server runs as a local stdio process. It opens no
  listening port and exposes no HTTP surface.
- **Read-only behaviour.** All 65 tools are queries over the cached STIX data.
  Nothing mutates state outside the cache directory, and no tool executes shell
  commands or evaluates caller-supplied code.

Found a security issue? Please
[open an issue](https://github.com/imouiche/complete-mitre-attack-mcp-server/issues).

---

## Data Cache

The server does not bundle ATT&CK data. On first start it downloads the
official STIX 2.1 bundles for all three domains and caches them on disk, then
loads them into memory. Later starts reuse the cache and skip the download.

**Location** — `~/.mitre-mcp-server/data/v{version}/`, overridable with
`MITRE_MCP_DATA_DIR`.

**Current release** — ATT&CK v20.1, about 64MB across three files:

| Domain | File | Size |
|---|---|---|
| Enterprise | `enterprise-attack.json` | 52.7MB |
| Mobile | `mobile-attack.json` | 5.9MB |
| ICS | `ics-attack.json` | 5.1MB |

### Clearing the cache to force a re-download

The cache is never invalidated automatically. If the data is stale, partially
downloaded, or corrupted, clear it and the server will fetch a fresh copy the
next time it starts.

Inspect what is currently cached:

```bash
python -m mitre_mcp_server.data.download --stats
```

Re-download the current release, replacing what is there:

```bash
python -m mitre_mcp_server.data.download --force
```

Or simply delete the cache and let the server re-fetch on next start. This is
the most reliable method and the one to use with the npm install, which has no
convenient `python` on `PATH`:

```bash
rm -rf ~/.mitre-mcp-server/data
```

To refresh a single domain rather than all three:

```bash
python -m mitre_mcp_server.data.download --domain enterprise --force
```

### Reclaiming disk space from superseded releases

When MITRE publishes a new ATT&CK version, the server downloads it into a new
`v{version}` directory and **leaves the previous one in place**. Over time
these accumulate — a machine that has run through two releases will hold both:

```
~/.mitre-mcp-server/data/
├── v18.1/   56MB   <- superseded, safe to delete
└── v20.1/   64MB   <- in use
```

Only the directory matching the current `mitreattack-python` release is read.
Delete the others:

```bash
ls ~/.mitre-mcp-server/data/                       # list cached releases
python -m mitre_mcp_server.data.download --stats    # show which one is in use
rm -rf ~/.mitre-mcp-server/data/v18.1               # remove a superseded release
```

The npm install path keeps a second cache, the virtualenv under
`~/.mitre-mcp-server/runtime/`. It is keyed by package and Python version, so
upgrades create a new directory and leave the old one behind. Removing the
whole `runtime` directory is safe; it is rebuilt on the next launch.

---

## Available Tools

65 tools covering the major ATT&CK entities and their relationships. All tool
handlers are asynchronous. Most accept an optional `domain` argument of
`enterprise`, `mobile` or `ics`, defaulting to `enterprise`.

### Infrastructure and metadata

| Tool | Description |
|---|---|
| `get_data_stats` | Download status, file paths, sizes and ATT&CK release version |
| `get_stats` | Entity counts for a loaded domain |
| `get_all_matrices` | All ATT&CK matrices in a domain |
| `generate_layer` | Generate an ATT&CK Navigator layer as JSON |
| `get_layer_metadata` | Return a Navigator layer metadata template |

### Generic STIX access

Lower-level accessors that work across every object type, useful when you hold
a STIX ID rather than an ATT&CK ID.

| Tool | Description |
|---|---|
| `get_object_by_attack_id` | Any object by ATT&CK ID and STIX type |
| `get_object_by_stix_id` | Any object by STIX ID (UUID) |
| `get_objects_by_type` | All objects of a given STIX type |
| `get_objects_by_name` | Objects by exact name match (case-sensitive) |
| `get_objects_by_content` | Objects whose description contains given text |
| `get_attack_id` | Convert a STIX UUID to its ATT&CK ID |
| `get_name` | Resolve the display name for a STIX ID |
| `get_stix_type` | Determine the STIX object type for a STIX ID |
| `get_objects_created_after` | Objects created after a timestamp |
| `get_objects_modified_after` | Objects modified after a timestamp |

### Techniques

| Tool | Description |
|---|---|
| `get_technique_by_id` | Get a technique by ATT&CK ID, for example T1055 |
| `search_techniques` | Search techniques by name or description |
| `get_all_techniques` | Retrieve all techniques |
| `get_all_parent_techniques` | Parent techniques only |
| `get_all_subtechniques` | All sub-techniques |
| `get_subtechniques_of_technique` | Sub-techniques of a parent |
| `get_parent_technique_of_subtechnique` | Parent of a sub-technique |
| `get_technique_tactics` | Tactics associated with a technique |
| `get_techniques_by_tactic` | Techniques under a tactic |
| `get_techniques_by_platform` | Techniques for a platform |
| `get_revoked_techniques` | Revoked techniques |

### Groups

| Tool | Description |
|---|---|
| `get_group_by_name` | Find a group by name or alias |
| `search_groups` | Search groups |
| `get_all_groups` | All ATT&CK groups |
| `get_groups_by_alias` | Look up groups by alias |
| `get_groups_using_technique` | Groups using a technique |
| `get_groups_using_software` | Groups using software |
| `get_groups_attributing_to_campaign` | Groups attributed to a campaign |
| `get_group_techniques` | Techniques used by a group, by group name |
| `get_techniques_used_by_group` | Techniques used by a group, by STIX ID |
| `get_techniques_used_by_group_software` | Techniques reachable via a group's software (group to software to techniques) |

### Software

| Tool | Description |
|---|---|
| `get_software` | Get all software |
| `search_software` | Search software |
| `get_software_by_alias` | Look up software by alias |
| `get_software_used_by_group` | Software used by a group |
| `get_software_used_by_campaign` | Software used in campaigns |
| `get_software_using_technique` | Software using a technique |
| `get_all_software` | All malware and tools in a domain |
| `get_techniques_used_by_software` | Techniques used by specific software or malware |

### Campaigns

| Tool | Description |
|---|---|
| `get_all_campaigns` | Get all campaigns |
| `get_campaigns_by_alias` | Look up campaigns by alias |
| `get_campaigns_using_technique` | Campaigns using a technique |
| `get_campaigns_using_software` | Campaigns using software |
| `get_campaigns_attributed_to_group` | Campaign attribution |
| `get_techniques_used_by_campaign` | Techniques used in a campaign |

### Mitigations

| Tool | Description |
|---|---|
| `get_all_mitigations` | Get all mitigations |
| `get_mitigations_mitigating_technique` | Mitigations for a technique |
| `get_techniques_mitigated_by_mitigation` | Techniques mitigated by a mitigation |

### Tactics, data sources and ICS

| Tool | Description |
|---|---|
| `get_all_tactics` | Get all tactics |
| `get_all_datasources` | Get all data sources |
| `get_all_datacomponents` | Get all data components |
| `get_datacomponents_detecting_technique` | Data components detecting a technique |
| `get_all_assets` | Get ICS assets |
| `get_assets_targeted_by_technique` | Assets targeted by a technique |
| `get_techniques_targeting_asset` | Techniques targeting an ICS asset |
| `get_tactics_by_matrix` | Tactics belonging to a matrix |
| `get_tactics_by_technique` | Tactics associated with a technique, by STIX ID |
| `get_techniques_detected_by_datacomponent` | Techniques a data component can detect |
| `get_procedure_examples_by_technique` | Procedure examples showing how groups used a technique |
| `get_procedure_examples_by_tactic` | Procedure examples for all techniques in a tactic |

---

## Example Queries

```
What techniques does APT29 use for initial access?
Which groups use Cobalt Strike?
What are the aliases for the Lazarus Group?

What data sources detect credential dumping?
What can detect T1055 (Process Injection)?
List all techniques for Windows privilege escalation
Show me lateral movement techniques for Linux

What mitigations exist for phishing attacks?
What techniques does MFA mitigate?

Generate a layer for all techniques our EDR covers
Compare APT29 TTPs against our detection capabilities
Show unmitigated techniques in our environment
```

---

## ATT&CK Navigator Visualisation

The `generate_layer` tool produces ATT&CK Navigator-compatible JSON.

1. Ask your client to generate a layer, for example "Generate an ATT&CK
   Navigator layer for all techniques used by APT29"
2. Save the JSON output to a file, for example `apt29_layer.json`
3. Upload it to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

Typical uses include mapping red-team exercise coverage, highlighting
unmonitored techniques, profiling a threat actor's TTPs, and showing which
techniques are mitigated against which are exposed.

### Worked example with LangGraph

- **Article** — [From MITRE ATT&CK to agentic threat investigation](https://medium.com/@nsangouinoussa515/from-mitre-att-ck-to-agentic-threat-investigation-58336c22f482),
  on building a multi-agent LangGraph system over these tools
- **Live demo** — [Interactive Gradio demo on Hugging Face Spaces](https://huggingface.co/spaces/Inoussa-guru/mitre-agentic-threat-investigation)

---

## Technical Details

### Architecture

- **Language** — Python 3.12 or newer
- **Protocol** — Model Context Protocol via FastMCP, served over stdio
- **Data source** — official STIX 2.1 bundles through `mitreattack-python`
- **Concurrency** — asynchronous tool handlers
- **Caching** — all three domains loaded into memory at startup, so queries
  need no disk access

### Data

| Property | Value |
|---|---|
| ATT&CK release | v20.1 |
| Domains | Enterprise, Mobile, ICS |
| Techniques | 706 Enterprise, 125 Mobile, 104 ICS |
| Groups | 178 Enterprise, 20 Mobile, 14 ICS |
| Software | 842 Enterprise, 129 Mobile, 25 ICS |
| Mitigations | 44 Enterprise, 13 Mobile, 53 ICS |
| Tactics | 15 Enterprise, 12 Mobile, 12 ICS |
| Cache size | about 64MB |
| Cache location | `~/.mitre-mcp-server/data/v{version}/` |

Counts track the pinned ATT&CK release and change when MITRE publishes a new
one. See [Data Cache](#data-cache) for refreshing.

### Requirements

- **Python** — 3.12 or newer
- **Node.js** — 16 or newer, for the npm installation path only
- **Disk** — about 64MB of ATT&CK data plus about 200MB of Python
  dependencies. The npm path keeps its dependencies in its own virtualenv, so
  budget roughly 290MB under `~/.mitre-mcp-server/`.
- **Memory** — about 490MB resident with all three domains loaded, since every
  domain is held in memory for fast queries. Measured on Python 3.12 against
  ATT&CK v20.1.
- **`mcp`** — pinned to `>=1.1.0,<2`. The server uses the v1
  `mcp.server.fastmcp` API, which mcp 2.0 renamed to `MCPServer`. An unpinned
  install resolves 2.x and fails at import.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

Issues and pull requests are welcome at
[github.com/imouiche/complete-mitre-attack-mcp-server](https://github.com/imouiche/complete-mitre-attack-mcp-server/issues).

---

## Author

**Inoussa Mouiche, Ph.D.** — University of Windsor, WASP Lab. Research in
threat intelligence automation, machine learning, multi-agent security systems
and LLM-powered security operations.

[GitHub](https://github.com/imouiche) ·
[LinkedIn](https://www.linkedin.com/in/inoussa-mouiche-ph-d-b5b5138b/) ·
[Google Scholar](https://scholar.google.com/citations?user=_d4cEVoAAAAJ&hl=en) ·
mouiche@uwindsor.ca

---

## Acknowledgments

Built on [MITRE ATT&CK](https://attack.mitre.org/) using
[mitreattack-python](https://github.com/mitre-attack/mitreattack-python),
MITRE's official library, and implementing the
[Model Context Protocol](https://modelcontextprotocol.io). Thanks to the MCP
developer community, including
[R. Jasper](https://www.remyjaspers.com/blog/mitre_attack_mcp_server/).

MITRE ATT&CK is a registered trademark of The MITRE Corporation. This project
is not affiliated with or endorsed by The MITRE Corporation.
