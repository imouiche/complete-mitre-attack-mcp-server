<div align="center">

# 🛡️ MITRE ATT&CK MCP Server

**AI-Native Access to the World's Leading Threat Intelligence Framework**

[![npm](https://img.shields.io/npm/v/@imouiche/mitre-attack-mcp-server.svg)](https://www.npmjs.com/package/@imouiche/mitre-attack-mcp-server)
[![npm downloads](https://img.shields.io/npm/dm/@imouiche/mitre-attack-mcp-server.svg)](https://www.npmjs.com/package/@imouiche/mitre-attack-mcp-server)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MCP Registry](https://img.shields.io/badge/MCP-Registered-success)](https://registry.modelcontextprotocol.io)
[![GitHub release](https://img.shields.io/github/v/release/imouiche/complete-mitre-attack-mcp-server)](https://github.com/imouiche/complete-mitre-attack-mcp-server/releases)

[Features](#-key-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Tools](#-available-tools) • [Examples](#-example-queries) • [Roadmap](#-roadmap--vision)

</div>

---

## 🎯 Overview

The **MITRE ATT&CK MCP Server** transforms the world's leading adversary knowledge base into an **AI-native interface**. Built for the **Model Context Protocol**, it enables LLMs and agentic systems to:

- 🔍 **Query** 200+ techniques, 140+ groups, 700+ software entries
- 🧠 **Reason** over complex threat relationships and TTPs  
- 📊 **Visualize** coverage gaps with ATT&CK Navigator layers
- ⚡ **Scale** threat intelligence workflows with structured tools

**Perfect for**: Security teams, threat hunters, detection engineers, AI researchers, and anyone building intelligent security systems.

### What is this?

`mitre-attack-mcp-server` is a **self-contained MCP server** that provides **machine-callable access** to the MITRE ATT&CK framework using official STIX data with **LLMs** friendly **structured outputs**.

It enables:

- 🤖 **LLMs** to reason about ATT&CK techniques, groups, software, and mitigations
- 🧠 **Agentic workflows** to generate threat explanations and coverage maps
- 🔍 **Security teams** to query ATT&CK relationships programmatically
- 📊 **Visualization** via ATT&CK Navigator layers

No scraping.  
No fragile APIs.  
Just **official MITRE data**, structured and reliable.

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [MCP Registry](#-mcp-registry)
- [Available Tools](#-available-tools)
- [Example Queries](#-example-queries)
- [ATT&CK Navigator](#-attck-navigator-visualization)
- [Technical Details](#-technical-details)
- [Roadmap & Vision](#-roadmap--vision)
- [Contributing](#-contributing)
- [License](#-license)
- [About the Author](#-about-the-author)
- [Acknowledgments](#-acknowledgments)

---

## ✨ Key Features

- ✅ **50+ MCP tools** across ATT&CK domains (Enterprise, Mobile, ICS)
- ✅ Automatic **STIX download & caching** on first run
- ✅ Native **ATT&CK Navigator layer generation**
- ✅ Designed for **LLMs & MCP-compatible clients**
- ✅ **In-memory caching** for instant query responses
- ✅ **Type-safe** with Pydantic models
- ✅ Clean, production-ready, self-contained server
- ✅ Comprehensive test coverage

---

## 📦 Installation

### npm (recommended)

```bash
npm install -g @imouiche/mitre-attack-mcp-server
```

### npx (no installation required)

```bash
npx @imouiche/mitre-attack-mcp-server
```

### Local Development

```bash
git clone https://github.com/imouiche/complete-mitre-attack-mcp-server.git
cd complete-mitre-attack-mcp-server
npm install
```

### Using uv (Python package manager)

```bash
git clone https://github.com/imouiche/complete-mitre-attack-mcp-server.git
cd complete-mitre-attack-mcp-server
uv sync
```

---

## ⚡ Quick Start

### 1. Install

```bash
npm install -g @imouiche/mitre-attack-mcp-server
```

### 2. Configure Claude Desktop

Add to your `claude_desktop_config.json`:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

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

### 3. Restart Claude Desktop

Quit Claude Desktop completely (Cmd+Q on macOS) and reopen it.

### 4. Start Querying!

Ask Claude:
> "What techniques does APT29 use for initial access?"  
> "Generate an ATT&CK Navigator layer for ransomware groups"  
> "Show me all Windows persistence techniques"

**Data downloads automatically on first run** (~59MB, cached at `~/.mitre-mcp-server/data/`).

---

## 📦 MCP Registry

This server is officially registered in the **Model Context Protocol (MCP) Registry**.

**Registry ID**: `io.github.imouiche/mitre-attack-mcp-server`

**View in Official Registry**: [https://registry.modelcontextprotocol.io/?q=mitre-attack-mcp-server](https://registry.modelcontextprotocol.io/?q=mitre-attack-mcp-server)

### Installation Options

**Option 1: Direct NPM**
```bash
npm install -g @imouiche/mitre-attack-mcp-server
```

**Option 2: NPX (no installation)**
```bash
npx @imouiche/mitre-attack-mcp-server
```

**Option 3: Discover via Registry**
1. Visit [MCP Registry](https://registry.modelcontextprotocol.io)
2. Search for "mitre-attack"
3. Click the server card for installation instructions

---

## 🛠️ Available Tools

The server exposes **80+ MCP tools** covering all major MITRE ATT&CK entities and relationships.

---

### 📊 Infrastructure & Metadata

| Tool | Description |
|---|---|
| `get_data_stats` | Show download status, file paths, sizes, and ATT&CK release version |
| `generate_layer` | Generate an ATT&CK Navigator layer (JSON output) |
| `get_layer_metadata` | Return Navigator layer metadata template |

---

### 🎯 Techniques

| Tool | Description |
|---|---|
| `get_technique_by_id` | Get a technique by ATT&CK ID (e.g., T1055) |
| `search_techniques` | Search techniques by name or description |
| `get_all_techniques` | Retrieve all techniques |
| `get_all_parent_techniques` | Parent techniques only |
| `get_all_subtechniques` | All subtechniques |
| `get_subtechniques_of_technique` | Subtechniques of a parent |
| `get_parent_technique_of_subtechnique` | Parent of a subtechnique |
| `get_technique_tactics` | Tactics associated with a technique |
| `get_techniques_by_tactic` | Techniques under a tactic |
| `get_techniques_by_platform` | Techniques for a platform |
| `get_revoked_techniques` | Revoked techniques |

---

### 🧑‍💻 Groups (Threat Actors)

| Tool | Description |
|---|---|
| `get_group_by_name` | Find group by name or alias |
| `search_groups` | Search groups |
| `get_all_groups` | All ATT&CK groups |
| `get_groups_by_alias` | Lookup groups by alias |
| `get_groups_using_technique` | Groups using a technique |
| `get_groups_using_software` | Groups using software |
| `get_groups_attributing_to_campaign` | Groups attributed to a campaign |

---

### 🧪 Software (Malware & Tools)

| Tool | Description |
|---|---|
| `get_software` | Get all software |
| `search_software` | Search software |
| `get_software_by_alias` | Lookup software by alias |
| `get_software_used_by_group` | Software used by a group |
| `get_software_used_by_campaign` | Software used in campaigns |
| `get_software_using_technique` | Software using a technique |

---

### 📌 Campaigns

| Tool | Description |
|---|---|
| `get_all_campaigns` | Get all campaigns |
| `get_campaigns_by_alias` | Lookup campaigns by alias |
| `get_campaigns_using_technique` | Campaigns using a technique |
| `get_campaigns_using_software` | Campaigns using software |
| `get_campaigns_attributed_to_group` | Campaign attribution |

---

### 🛡️ Mitigations

| Tool | Description |
|---|---|
| `get_all_mitigations` | Get all mitigations |
| `get_mitigations_mitigating_technique` | Mitigations for a technique |
| `get_techniques_mitigated_by_mitigation` | Techniques mitigated by a mitigation |

---

### 🧭 Tactics, Data Sources & ICS

| Tool | Description |
|---|---|
| `get_all_tactics` | Get all tactics |
| `get_all_datasources` | Get all data sources |
| `get_all_datacomponents` | Get all data components |
| `get_datacomponents_detecting_technique` | Data components detecting a technique |
| `get_all_assets` | Get ICS assets |
| `get_assets_targeted_by_technique` | Assets targeted by a technique |

---

## 💡 Example Queries

### Threat Intelligence
```
"What techniques does APT29 use for initial access?"
"Which groups target financial institutions?"
"Show me all ransomware-related software"
"What are the aliases for the Lazarus Group?"
Blog demo coming soon...
```

### Detection Engineering
```
"What data sources detect credential dumping?"
"Generate a coverage map for EDR capabilities"
"List all techniques for Windows privilege escalation"
"What can detect T1055 (Process Injection)?"
Blog demo coming soon...
```

### Threat Hunting
```
"What techniques use PowerShell?"
"Show me lateral movement techniques for Linux"
"Which groups use Cobalt Strike?"
"What persistence techniques target macOS?"
Blog demo coming soon...
```

### Mitigation & Defense
```
"What mitigations exist for phishing attacks?"
"Show me all mitigations for privilege escalation"
"What techniques does MFA mitigate?"
Blog demo coming soon...
```

### Compliance & Gap Analysis
```
"Generate a layer for all techniques our EDR covers"
"Compare APT29 TTPs against our detection capabilities"
"Show unmitigated techniques in our environment"
Blog demo coming soon...
```

---

## 📊 ATT&CK Navigator Visualization

The `generate_layer` tool produces **ATT&CK Navigator–compatible JSON**.

### Usage:

1. Ask Claude to generate a layer:
   > "Generate an ATT&CK Navigator layer for all techniques used by APT29"

2. Save the JSON output to a file (e.g., `apt29_layer.json`)

3. Upload to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

4. Visualize technique coverage, threat actor usage, or mitigation mapping

### Example Layer Use Cases:

- **Red Team Coverage**: Map all techniques used in an exercise
- **Detection Gaps**: Highlight unmonitored techniques
- **Threat Actor Profile**: Visualize group TTPs
- **Mitigation Coverage**: Show what's protected vs. exposed

---

## 🔧 Technical Details

### Architecture

- **Language**: Python 3.12+
- **Framework**: FastMCP for Model Context Protocol
- **Data Library**: Official `mitreattack-python` (v5.3.0+)
- **Async/Await**: Optimal performance for concurrent queries
- **Type Safety**: Full Pydantic models for all data structures
- **Testing**: Comprehensive pytest coverage

### Data

- **Enterprise ATT&CK**: v18.1+ (~50.9MB)
- **Mobile ATT&CK**: v18.1+ (~4.9MB)
- **ICS ATT&CK**: v18.1+ (~3.5MB)
- **Total**: ~59MB cached locally
- **Storage**: `~/.mitre-mcp-server/data/v{version}/`
- **Update**: Auto-downloads on install, uses cached data on subsequent runs

### Performance

- **In-memory caching**: All domains loaded at startup
- **Query speed**: Sub-second for most operations
- **Graph traversal**: Efficient relationship queries
- **Concurrent**: Handles multiple simultaneous requests

### Requirements

- **Python**: 3.12 or higher
- **Node.js**: 16+ (for NPM installation)
- **Disk Space**: ~150MB (includes dependencies + data)
- **Memory**: ~200MB RAM when running

---

## 🚀 Roadmap & Vision

This project is the **first component** of a larger vision to build **comprehensive agentic security automation** by integrating multiple security knowledge bases and frameworks.

### Current Status
- ✅ **MITRE ATT&CK** - Threat intelligence & adversary TTPs (v18.1)

### Planned Integrations
- 🔜 **CVE/NVD** - Vulnerability intelligence and exploit mapping
- 🔜 **MITRE D3FEND** - Defensive countermeasure knowledge graph
- 🔜 **Sigma Rules** - Detection rule translation and management
- 🔜 **CAPEC** - Common Attack Pattern Enumeration
- 🔜 **CWE** - Software weakness enumeration
- 🔜 **Agentic Pentesting** - Multi-agent autonomous security testing

### Ultimate Goal

Enable **AI agents to autonomously**:
- 🎯 Map attack surfaces and identify vulnerabilities
- 🛡️ Recommend defensive countermeasures
- 🔍 Generate detection rules and validate coverage
- 🤖 Orchestrate multi-stage security assessments
- 📊 Reason about complete attack-defense lifecycles

### Get Involved

**We welcome contributions from:**
- 🎓 **Students** working on thesis projects (cybersecurity, AI, agentic systems)
- 🔬 **Researchers** in AI security, threat intelligence, or agent frameworks
- 💻 **Developers** passionate about security automation
- 🏢 **Organizations** interested in research partnerships or commercial applications

**Areas of Interest:**
- Integrating additional security frameworks (CVE, D3FEND, Sigma)
- Building agentic workflows for pentesting and red teaming
- Developing detection rule generation pipelines
- Creating threat intelligence reasoning systems
- Improving MCP tooling and documentation

📬 **Interested?** Open an issue, start a discussion, or reach out directly!

[Join the Discussion →](https://github.com/imouiche/complete-mitre-attack-mcp-server/discussions)

---

## 🤝 Contributing

Found a bug? Have a feature request? Want to contribute to the roadmap?

- 🐛 [Report Issues](https://github.com/imouiche/complete-mitre-attack-mcp-server/issues)
- 💡 [Request Features](https://github.com/imouiche/complete-mitre-attack-mcp-server/issues/new)
- 🔧 [Submit Pull Requests](https://github.com/imouiche/complete-mitre-attack-mcp-server/pulls)
- 💬 [Start a Discussion](https://github.com/imouiche/complete-mitre-attack-mcp-server/discussions)

All contributions welcome!

### Development Setup

```bash
git clone https://github.com/imouiche/complete-mitre-attack-mcp-server.git
cd complete-mitre-attack-mcp-server
uv sync
# uv run pytest (test/ folder not yet released)
uv run python -m mitre_mcp_server.server
```

---

## 📜 License

Apache License 2.0

See [LICENSE](LICENSE) for full details.

---

## 👨‍💻 About the Author

**Inoussa Mouiche, Ph.D.**  
AI/ML Researcher | Cybersecurity | Agentic AI Systems | Software Engineering

🎓 **University of Windsor** - WASP Lab  
🔬 **Research Focus**: Threat Intelligence Automation, Machine Learning, Multi-Agent Security Systems, LLM-Powered Security Operations

📫 **Connect**
- 🐙 GitHub: [@imouiche](https://github.com/imouiche)
- 📧 Email: mouiche@uwindsor.ca
- 💼 LinkedIn: [Inoussa Mouiche, Ph.D.](https://www.linkedin.com/in/inoussa-mouiche-ph-d-b5b5138b/)
- 📚 Google Scholar: [Publications](https://scholar.google.com/citations?user=_d4cEVoAAAAJ&hl=en)

💼 **Open to opportunities** in:
- AI/ML Engineering & Research
- Cybersecurity & Threat Intelligence
- Agentic AI Development
- Security Automation & Orchestration
- Academic & Industry Collaborations

---

## 🙏 Acknowledgments

- Built on [MITRE ATT&CK®](https://attack.mitre.org/) - the industry standard for adversary tactics and techniques
- Powered by [mitreattack-python](https://github.com/mitre-attack/mitreattack-python) - official MITRE library
- Implements [Model Context Protocol](https://modelcontextprotocol.io) - Anthropic's standard for AI-tool integration
- Inspired by the amazing MCP developer community including [R. Jasper](https://www.remyjaspers.com/blog/mitre_attack_mcp_server/)

**MITRE ATT&CK®** is a registered trademark of The MITRE Corporation.

---

<div align="center">

**⭐ Star this repo if you find it useful!**

**Interested in collaborating on agentic security systems?** [Let's connect!](https://www.linkedin.com/in/inoussa-mouiche-ph-d-b5b5138b/)

Made with ❤️ for the cybersecurity and AI communities

[⬆ Back to Top](#-mitre-attck-mcp-server)

</div>
