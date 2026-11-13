"""Verify every tool count the README advertises matches the code.

The tool count now appears in the tagline, a badge, a section heading and a
per-area table. Any of those can drift from reality. This asserts all of them
against the registered tools, and that the per-area counts sum correctly.
"""

import asyncio
import pathlib
import re
import sys

from mitre_mcp_server.server import mcp

rd = pathlib.Path("README.md").read_text()
tools = asyncio.run(mcp.list_tools())
names = {t.name for t in tools}
n = len(names)
problems = []

# Tool tables: rows like "| `get_technique_by_id` | ... |". Environment-variable
# rows use the same shape but uppercase names, so filter those out.
documented = {m for m in re.findall(r"^\| `(\w+)`", rd, re.M) if not m.isupper()}
if missing := sorted(names - documented):
    problems.append(f"tools missing from the README tables: {missing}")
if ghost := sorted(documented - names):
    problems.append(f"README documents tools that do not exist: {ghost}")

# Every advertised figure must equal the real count.
advertised = {
    "tagline": r"\*\*(\d+) MCP tools",
    "badge": r"MCP%20tools-(\d+)-",
    "heading": r"^### (\d+) tools across",
}
for label, pattern in advertised.items():
    found = re.search(pattern, rd, re.M)
    if not found:
        problems.append(f"could not find the tool count in the {label}")
    elif int(found.group(1)) != n:
        problems.append(f"{label} advertises {found.group(1)} tools, code has {n}")

# The per-area table in the overview must sum to the real count.
area_rows = re.findall(r"^\| \[([^\]]+)\]\(#[^)]+\) \| +(\d+) \|", rd, re.M)
if not area_rows:
    problems.append("could not find the per-area tool table")
else:
    total = sum(int(c) for _, c in area_rows)
    if total != n:
        problems.append(
            f"per-area table sums to {total} across {len(area_rows)} areas, code has {n}"
        )

if problems:
    for p in problems:
        print(f"::error::{p}")
    sys.exit(1)

print(f"{n} tools; README tagline, badge, heading and per-area table all agree.")
