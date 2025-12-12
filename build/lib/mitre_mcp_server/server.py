from __future__ import annotations

from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
import os

from mitreattack import download_stix, release_info
from mcp.server.fastmcp import FastMCP
from mitreattack.stix20 import MitreAttackData



# ---------------------------------------------------------------------------
# Configuration & shared constants
# ---------------------------------------------------------------------------

# Domains we support
DOMAINS: List[str] = ["enterprise", "mobile", "ics"]

APP_NAME = "mitre-mcp-server"

DATA_DIR: Path = Path(
    os.getenv(
        "MITRE_MCP_DATA_DIR",
        Path.home() / f".{APP_NAME}" / "data",
    )
).expanduser()


def get_version_dir() -> Path:
    """Return the versioned directory like DATA_DIR/v12.2."""
    return DATA_DIR / f"v{release_info.LATEST_VERSION}"


def get_stix_path(domain: str) -> Path:
    """Return the expected STIX JSON path for a given domain."""
    domain_key = f"{domain}-attack"
    return get_version_dir() / f"{domain_key}.json"


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------

def check_existing_data() -> List[str]:
    """Check which domains already have data downloaded.

    Returns:
        List of domain names that have existing data files.
    """
    existing_domains: List[str] = []

    for domain in DOMAINS:
        if get_stix_path(domain).exists():
            existing_domains.append(domain)

    return existing_domains


def download_domain_data(domain: str, force: bool = False) -> Tuple[str, Path]:
    """Download STIX data for a specific domain.

    Args:
        domain: Domain name ('enterprise', 'mobile', or 'ics')
        force: If True, download even if file already exists.

    Returns:
        Tuple of (domain, file_path) for the downloaded file.

    Raises:
        ValueError: If domain is not valid.
        RuntimeError: If download appears to succeed but file is missing.
    """
    if domain not in DOMAINS:
        raise ValueError(f"Invalid domain '{domain}'. Must be one of: {DOMAINS}")

    stix_path = get_stix_path(domain)

    # If file already exists and we're not forcing, just return it
    if stix_path.exists() and not force:
        return (domain, stix_path)

    # Get expected hash and version info
    releases = release_info.STIX21[domain]
    known_hash = releases[release_info.LATEST_VERSION]

    # Ensure base data directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Download STIX data into DATA_DIR (mitreattack will create the v<version> dir)
    download_stix.download_stix(
        stix_version="2.1",
        domain=domain,
        download_dir=str(DATA_DIR),
        release=release_info.LATEST_VERSION,
        known_hash=known_hash,
    )

    # Verify the file exists where we expect it
    if not stix_path.exists():
        raise RuntimeError(f"Download completed but file not found at {stix_path}")

    return (domain, stix_path)


def download_all_domains(force: bool = False) -> List[Tuple[str, Path]]:
    """Download STIX data for all domains (with caching).

    Args:
        force: If True, re-download even if files exist.

    Returns:
        List of tuples containing (domain, file_path) for each domain.
    """
    # Ensure base directory exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    downloaded_files: List[Tuple[str, Path]] = []

    for domain in DOMAINS:
        try:
            domain_data = download_domain_data(domain, force=force)
            downloaded_files.append(domain_data)
        except Exception:
            # You can add logging here later if you want
            pass

    return downloaded_files

# ---------------------------------------------------------------------------
# In-memory STIX loading helpers
# ---------------------------------------------------------------------------

# Cache of MitreAttackData objects keyed by e.g. "enterprise-attack"
attack_data: Dict[str, MitreAttackData] = {}

# Simple list of domains that have been successfully loaded
_loaded_domains: List[str] = []


def load_domain(domain: str) -> bool:
    """
    Load STIX data for a specific domain into memory.

    Args:
        domain: Domain name ('enterprise', 'mobile', or 'ics')

    Returns:
        True if loaded successfully, False otherwise.

    Raises:
        ValueError: If the domain is invalid.
        FileNotFoundError: If the expected STIX file is missing.
        RuntimeError: If MitreAttackData fails to load.
    """
    if domain not in DOMAINS:
        raise ValueError(f"Invalid domain '{domain}'. Must be one of: {DOMAINS}")

    domain_key = f"{domain}-attack"

    # Already loaded
    if domain_key in attack_data:
        return True

    stix_path = get_stix_path(domain)
    if not stix_path.exists():
        raise FileNotFoundError(
            f"STIX data file not found at {stix_path}. "
            "Ensure STIX data has been downloaded first (e.g., via download_all_domains "
            "or by starting the server once and checking get_data_stats)."
        )

    try:
        attack_data[domain_key] = MitreAttackData(str(stix_path))
        if domain not in _loaded_domains:
            _loaded_domains.append(domain)
        return True
    except Exception as e:
        raise RuntimeError(f"Failed to load {domain} domain data: {e}") from e


def load_all_domains() -> List[str]:
    """
    Load STIX data for all available domains into memory.

    Returns:
        List of successfully loaded domain names.
    """
    loaded: List[str] = []
    for domain in DOMAINS:
        try:
            if load_domain(domain):
                loaded.append(domain)
        except Exception as e:
            # For now, just warn; you can hook this into proper logging later
            print(f"Warning: Could not load {domain} domain: {e}")
    return loaded


def get_attack_data(domain: str = "enterprise") -> MitreAttackData:
    """
    Get the MitreAttackData object for a specific domain.

    Args:
        domain: Domain name (default: 'enterprise')

    Returns:
        MitreAttackData object for the specified domain.

    This will attempt to load the domain if it has not been loaded yet.
    """
    domain_key = f"{domain}-attack"

    if domain_key not in attack_data:
        # This will raise if the file is missing or invalid
        load_domain(domain)

    return attack_data[domain_key]


def get_loaded_domains() -> List[str]:
    """
    Get a copy of the list of currently loaded domains.
    """
    return _loaded_domains.copy()


def _compute_data_stats() -> Dict[str, Any]:
    """Internal helper: compute statistics about downloaded data."""
    stats: Dict[str, Any] = {}

    for domain in DOMAINS:
        stix_path = get_stix_path(domain)

        if stix_path.exists():
            file_size_mb = stix_path.stat().st_size / (1024 * 1024)
            stats[domain] = {
                "exists": True,
                "path": str(stix_path),
                "size_mb": round(file_size_mb, 2),
                "version": release_info.LATEST_VERSION,
            }
        else:
            stats[domain] = {
                "exists": False,
                "path": None,
                "size_mb": 0.0,
                "version": None,
            }

    return stats

def format_objects(
    objects: List[Any],
    include_description: bool = False,
    domain: str = "enterprise"
) -> str:
    """
    Format a list of MITRE ATT&CK objects into a clean, readable string.

    Args:
        objects: List of STIX objects or dicts containing {"object": obj}.
        include_description: Whether to include object descriptions.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").

    Returns:
        A formatted multi-line string.
    """
    attack_data = get_attack_data(domain)
    formatted = []

    for obj in objects:

        # Normalize {"object": x} format
        if isinstance(obj, dict) and "object" in obj:
            obj = obj["object"]

        lines = []

        # Name --------------------------------------------------------------
        name = getattr(obj, "name", None)
        if name:
            lines.append(f"Name: {name}")

        # External ATT&CK ID (e.g., T1059, G0032) ---------------------------
        try:
            external_id = attack_data.get_attack_id(obj)
            if external_id:
                lines.append(f"ID: {external_id}")
        except Exception:
            pass  # not all objects map cleanly

        # STIX ID -----------------------------------------------------------
        stix_id = getattr(obj, "id", None)
        if stix_id:
            lines.append(f"STIX ID: {stix_id}")

        # Source reference (relationships only) -----------------------------
        source_ref = getattr(obj, "source_ref", None)
        if source_ref:
            lines.append(f"Source Reference: {source_ref}")

        # Aliases -----------------------------------------------------------
        aliases = getattr(obj, "aliases", None)
        if aliases:
            lines.append(f"Aliases: {aliases}")

        # Description -------------------------------------------------------
        description = getattr(obj, "description", None)
        if include_description and description:
            lines.append(f"Description: {description}")

        formatted.append("\n".join(lines))

    return "\n---\n".join(formatted)


# ---------------------------------------------------------------------------
# MCP server & first tool
# ---------------------------------------------------------------------------

mcp = FastMCP("mitre-attack-mcp-server")


@mcp.tool()
async def get_data_stats() -> Dict[str, Any]:
    """
    Return statistics about downloaded MITRE ATT&CK STIX data.

    This confirms which domains are present on disk, their file paths,
    sizes, and ATT&CK release version. It assumes that downloads have
    already been attempted at server startup.
    """
    return _compute_data_stats()

@mcp.tool()
async def get_technique_by_id(
    technique_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
    ) -> Dict[str, Any]:

    """" 
    Retrieve a MITRE ATT&CK technique by its external ATT&CK ID (e.g., "T1055", "T1053.005").

    This tool searches the specified ATT&CK domain (enterprise, mobile, or ics)
    and returns both structured machine-readable data and an optional formatted
    human-readable text block. It is useful for user-facing responses as well
    as downstream programmatic reasoning.

    Args:
        technique_id: The external ATT&CK technique ID (e.g., "T1055").
        domain: ATT&CK domain to search in ("enterprise", "mobile", "ics").
        include_description: If True, returns the full ATT&CK description text.

    Returns:
        {
          "found": bool,
          "technique": {
              "id": "<ATT&CK ID>",
              "name": "<technique name>",
              "stix_id": "<STIX object ID>",
              "description": "<full description or null>"
          },
          "formatted": "<human-readable formatted block>",
          "message": "<status message>"
        }
    """

    attack_data = get_attack_data(domain)

    # Library already supports this lookup!
    tech = attack_data.get_object_by_attack_id(
        technique_id,
        "attack-pattern"
    )

    if tech is None:
        return {
            "found": False,
            "message": f"Technique '{technique_id}' not found in domain '{domain}'."
        }

    formatted = format_objects(
        [tech],
        include_description=include_description,
        domain=domain
    )

    return {
        "found": True,
        "technique": {
            "id": technique_id,
            "name": getattr(tech, "name", None),
            "stix_id": getattr(tech, "id", None),
            "description": getattr(tech, "description", None)
        },
        "formatted": formatted
    }

@mcp.tool()
async def get_object_by_attack_id(
    attack_id: str,
    stix_type: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Retrieve any MITRE ATT&CK object by its external ATT&CK ID and STIX type.

    This tool supports techniques, intrusion sets (APT groups), malware,
    tools, mitigations, campaigns, data sources, data components, and tactics.

    Args:
        attack_id: The external ATT&CK ID (e.g., "T1055", "G0016", "S0154", "M1013").
        stix_type: The STIX object type (e.g., "attack-pattern", "intrusion-set").
        domain: ATT&CK domain ("enterprise", "mobile", or "ics").
        include_description: Whether to include the object's description field.

    Returns:
        {
          "found": bool,
          "object": {
              "id": "<ATT&CK ID>",
              "name": "<object name>",
              "stix_id": "<STIX object ID>",
              "type": "<stix_type>",
              "description": "<description or null>"
          },
          "formatted": "<human-readable formatted output>",
          "message": "<status>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        obj = attack_data.get_object_by_attack_id(attack_id, stix_type)
    except Exception:
        obj = None

    if obj is None:
        return {
            "found": False,
            "object": None,
            "formatted": "",
            "message": (
                f"No object found for ATT&CK ID '{attack_id}' with STIX type "
                f"'{stix_type}' in domain '{domain}'."
            ),
        }

    # Handle object fields (works for dict and STIX object instances)
    name = getattr(obj, "name", None) if not isinstance(obj, dict) else obj.get("name")
    stix_id = getattr(obj, "id", None) if not isinstance(obj, dict) else obj.get("id")
    description = (
        getattr(obj, "description", None)
        if include_description and not isinstance(obj, dict)
        else (obj.get("description") if include_description else None)
    )

    formatted = format_objects(
        [obj],
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "object": {
            "id": attack_id,
            "name": name,
            "stix_id": stix_id,
            "type": stix_type,
            "description": description,
        },
        # "formatted": formatted,
        "message": f"Object found for ATT&CK ID '{attack_id}' in domain '{domain}'.",
    }

@mcp.tool()
async def get_object_by_stix_id(
    stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Retrieve any MITRE ATT&CK object by its STIX ID (UUID).

    STIX IDs are internal identifiers like:
      - attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b

    This tool is useful when you already have a STIX ID from another
    query or relationship and want to resolve it to the full object.

    Args:
        stix_id: STIX object ID (e.g., "attack-pattern--...").
        domain: ATT&CK domain to search in ("enterprise", "mobile", "ics").
        include_description: Whether to include the object's description.

    Returns:
        {
          "found": bool,
          "object": {
              "attack_id": "<ATT&CK external ID or null>",
              "name": "<object name>",
              "stix_id": "<STIX ID>",
              "type": "<stix type>",
              "description": "<description or null>"
          },
          "formatted": "<human-readable formatted text>",
          "message": "<status message>"
        }
    """
    attack_data = get_attack_data(domain)

    # Resolve the object by its STIX ID
    try:
        obj = attack_data.get_object_by_stix_id(stix_id)
    except Exception:
        obj = None

    if obj is None:
        return {
            "found": False,
            "object": None,
            "formatted": "",
            "message": f"No object found for STIX ID '{stix_id}' in domain '{domain}'.",
        }

    # Handle dict-like vs object-like STIX representations
    if isinstance(obj, dict):
        name = obj.get("name")
        stix_type = obj.get("type")
        raw_id = obj.get("id", stix_id)
        description = obj.get("description") if include_description else None
    else:
        name = getattr(obj, "name", None)
        stix_type = getattr(obj, "type", None)
        raw_id = getattr(obj, "id", stix_id)
        description = getattr(obj, "description", None) if include_description else None

    # Try to resolve external ATT&CK ID for this STIX object (if it has one)
    attack_id = None
    try:
        attack_id = attack_data.get_attack_id(raw_id)
    except Exception:
        pass

    formatted = format_objects(
        [obj],
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "object": {
            "attack_id": attack_id,
            "name": name,
            "stix_id": raw_id,
            "type": stix_type,
            "description": description,
        },
        # "formatted": formatted,
        "message": f"Object found for STIX ID '{stix_id}' in domain '{domain}'.",
    }

@mcp.tool()
async def get_objects_by_name(
    name: str,
    stix_type: str,
    domain: str = "enterprise",
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Retrieve MITRE ATT&CK objects by exact name match (case-sensitive).

    This tool performs an exact name match for a specific STIX type within
    a given ATT&CK domain. It is more strict than generic search methods,
    which typically perform partial or keyword matching.

    Examples:
        - Technique: get_objects_by_name("Phishing", "attack-pattern")
        - Group: get_objects_by_name("APT29", "intrusion-set")
        - Malware: get_objects_by_name("Cobalt Strike", "malware")

    Args:
        name: Exact object name to search for (case-sensitive).
        stix_type: STIX object type (same values as get_object_by_attack_id),
                   e.g. "attack-pattern", "intrusion-set", "malware",
                   "tool", "course-of-action", etc.
        domain: ATT&CK domain ("enterprise", "mobile", or "ics").
        include_description: Whether to include descriptions in the formatted output
                             and structured result.

    Returns:
        {
          "count": <number of matching objects>,
          "objects": [
            {
              "attack_id": "<ATT&CK external ID or null>",
              "name": "<object name>",
              "stix_id": "<STIX ID>",
              "type": "<stix_type>",
              "description": "<description or null>"
            },
            ...
          ],
          "formatted": "<human-readable multi-object formatted text>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        objs = attack_data.get_objects_by_name(name, stix_type)
    except Exception:
        objs = []

    if not objs:
        return {
            "count": 0,
            "objects": [],
            "formatted": "",
            "message": (
                f"No objects found with name '{name}' and type '{stix_type}' "
                f"in domain '{domain}'."
            ),
        }

    structured_objects: List[Dict[str, Any]] = []

    for obj in objs:
        # Handle dict-like vs object-like forms
        if isinstance(obj, dict):
            obj_name = obj.get("name")
            stix_id = obj.get("id")
            obj_type = obj.get("type", stix_type)
            description = obj.get("description") if include_description else None
            stix_id_for_attack = stix_id
        else:
            obj_name = getattr(obj, "name", None)
            stix_id = getattr(obj, "id", None)
            obj_type = getattr(obj, "type", stix_type)
            description = getattr(obj, "description", None) if include_description else None
            stix_id_for_attack = stix_id

        # Try to resolve ATT&CK external ID (if any)
        attack_id = None
        if stix_id_for_attack:
            try:
                attack_id = attack_data.get_attack_id(stix_id_for_attack)
            except Exception:
                attack_id = None

        structured_objects.append(
            {
                "attack_id": attack_id,
                "name": obj_name,
                "stix_id": stix_id,
                "type": obj_type,
                "description": description,
            }
        )

    formatted = format_objects(
        objs,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(structured_objects),
        "objects": structured_objects,
        # "formatted": formatted,
        "message": (
            f"Found {len(structured_objects)} object(s) with name '{name}' "
            f"and type '{stix_type}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_objects_by_content(
    content: str,
    object_type: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK objects by matching text inside their description field.

    This performs a full-text search over object descriptions. It is useful for:
      • Finding techniques related to specific technologies (e.g., “PowerShell”)
      • Finding groups mentioning a region or country (e.g., “Russia”)
      • Finding mitigations referencing specific defenses (e.g., “multi-factor”)
      • Searching malware or tool descriptions for keywords

    Args:
        content: The text to search for (case-insensitive, partial match).
        object_type: STIX object type, such as:
            - "attack-pattern" (techniques)
            - "intrusion-set" (APT groups)
            - "malware"
            - "tool"
            - "course-of-action" (mitigations)
            - "campaign"
            - "x-mitre-data-source"
            - "x-mitre-data-component"
            - etc.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to return descriptions in the structured output.

    Returns:
        {
          "count": <number of matches>,
          "objects": [
             {
                "attack_id": "<ATT&CK ID or null>",
                "name": "<object name>",
                "stix_id": "<STIX ID>",
                "type": "<object_type>",
                "description": "<description or null>"
             },
             ...
          ],
          "formatted": "<human-readable formatted list>",
          "message": "<status message>"
        }
    """
    attack_data = get_attack_data(domain)

    # Perform text search
    try:
        objs = attack_data.get_objects_by_content(content, object_type)
    except Exception:
        objs = []

    if not objs:
        return {
            "count": 0,
            "objects": [],
            "formatted": "",
            "message": (
                f"No {object_type} objects in domain '{domain}' contain the text '{content}'."
            ),
        }

    structured: List[Dict[str, Any]] = []

    for obj in objs:
        # Handle STIX objects that may be dict-like or class-like
        if isinstance(obj, dict):
            name = obj.get("name")
            stix_id = obj.get("id")
            stix_type = obj.get("type", object_type)
            description = obj.get("description") if include_description else None
        else:
            name = getattr(obj, "name", None)
            stix_id = getattr(obj, "id", None)
            stix_type = getattr(obj, "type", object_type)
            description = getattr(obj, "description", None) if include_description else None

        # Resolve external ATT&CK ID, if present
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "type": stix_type,
                "description": description,
            }
        )

    # Human-readable output using your formatter
    formatted = format_objects(
        objs,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(structured),
        "objects": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} '{object_type}' objects whose descriptions "
            f"contain the text '{content}'."
        ),
    }

@mcp.tool()
async def get_techniques_by_tactic(
    tactic: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques associated with a specific ATT&CK tactic.

    This uses the MITRE ATT&CK Navigator-style mapping between tactics and
    techniques for a given domain (e.g., "enterprise-attack").

    Examples:
        - get_techniques_by_tactic("Initial Access", "enterprise")
        - get_techniques_by_tactic("Execution", "enterprise")
        - get_techniques_by_tactic("Persistence", "enterprise")

    Args:
        tactic: Tactic name (e.g., "Initial Access", "Persistence").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include technique descriptions
                             in the structured and formatted output.

    Returns:
        {
          "count": <number of techniques>,
          "techniques": [
            {
              "attack_id": "<TXXXX or TXXXX.YYY>",
              "name": "<technique name>",
              "stix_id": "<attack-pattern--...>",
              "description": "<description or null>",
              "tactic": "<tactic name>",
            },
            ...
          ],
          "formatted": "<human-readable technique list>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        techniques = attack_data.get_techniques_by_tactic(
            tactic,
            f"{domain}-attack",
            remove_revoked_deprecated=True,
        )
    except Exception:
        techniques = []

    if not techniques:
        return {
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found for tactic '{tactic}' in domain '{domain}'."
            ),
        }

    structured: List[Dict[str, Any]] = []

    for tech in techniques:
        # Handle dict-like vs object-like STIX representations
        if isinstance(tech, dict):
            name = tech.get("name")
            stix_id = tech.get("id")
            description = tech.get("description") if include_description else None
        else:
            name = getattr(tech, "name", None)
            stix_id = getattr(tech, "id", None)
            description = getattr(tech, "description", None) if include_description else None

        # Resolve external ATT&CK ID (Txxxx / Txxxx.yyy)
        attack_id = None
        if stix_id:
            try:
                attack_id = attack_data.get_attack_id(stix_id)
            except Exception:
                attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "tactic": tactic,
            }
        )

    formatted = format_objects(
        techniques,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(structured),
        "techniques": structured,
        # "formatted": formatted,
        "message": (
            f"Found {len(structured)} technique(s) for tactic '{tactic}' "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool()
async def search_techniques(
    query: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK techniques by keyword in their name or description.

    This tool performs a case-insensitive search over all non-revoked,
    non-deprecated techniques in the given domain. A technique is matched if
    the query string appears in either:
      • the technique name, or
      • the technique description

    Examples:
        - search_techniques("PowerShell")
        - search_techniques("credential dumping")
        - search_techniques("initial access", domain="enterprise")

    Args:
        query: Text to search for in technique names and descriptions.
        domain: ATT&CK domain ("enterprise", "mobile", or "ics").
        include_description: Whether to include descriptions in the structured
                             result and formatted output.

    Returns:
        {
          "count": <number of matches>,
          "techniques": [
            {
              "attack_id": "<TXXXX or TXXXX.YYY>",
              "name": "<technique name>",
              "stix_id": "<attack-pattern--...>",
              "description": "<description or null>",
            },
            ...
          ],
          "formatted": "<human-readable formatted list>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        all_techniques = attack_data.get_techniques(remove_revoked_deprecated=True)
    except Exception:
        all_techniques = []

    query_lower = query.lower()
    matched: List[Any] = []

    for tech in all_techniques:
        # Handle dict-like vs object-like STIX representations
        if isinstance(tech, dict):
            name = tech.get("name") or ""
            description = tech.get("description") or ""
        else:
            name = getattr(tech, "name", "") or ""
            description = getattr(tech, "description", "") or ""

        if query_lower in name.lower() or query_lower in description.lower():
            matched.append(tech)

    if not matched:
        return {
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques in domain '{domain}' matched the query '{query}'."
            ),
        }

    structured: List[Dict[str, Any]] = []

    for tech in matched:
        if isinstance(tech, dict):
            name = tech.get("name")
            stix_id = tech.get("id")
            description = tech.get("description") if include_description else None
        else:
            name = getattr(tech, "name", None)
            stix_id = getattr(tech, "id", None)
            description = getattr(tech, "description", None) if include_description else None

        # Resolve ATT&CK external ID
        attack_id = None
        if stix_id:
            try:
                attack_id = attack_data.get_attack_id(stix_id)
            except Exception:
                attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
            }
        )

    formatted = format_objects(
        matched,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(structured),
        "techniques": structured,
        # "formatted": formatted,
        "message": (
            f"Found {len(structured)} technique(s) in domain '{domain}' "
            f"matching query '{query}'."
        ),
    }

@mcp.tool()
async def get_group_by_name(
    group_name: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Retrieve an intrusion set (APT group) by name or alias (case-insensitive match).

    This tool searches ATT&CK intrusion sets by name or alias and returns the first
    matching group. Matching is case-insensitive and supports partial matches.

    Examples:
        - get_group_by_name("APT29")
        - get_group_by_name("Lazarus")
        - get_group_by_name("Fancy Bear")

    Args:
        group_name: The group name or alias to search for (case-insensitive).
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include descriptions in the output.

    Returns:
        {
          "found": bool,
          "group": {
              "attack_id": "<GXXXX>",
              "name": "<group name>",
              "aliases": [...],
              "stix_id": "<intrusion-set--...>",
              "description": "<description or null>"
          },
          "formatted": "<human-readable text>",
          "message": "<status>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        groups = attack_data.get_groups(remove_revoked_deprecated=True)
    except Exception:
        groups = []

    query = group_name.lower()
    match = None

    # Search loop
    for grp in groups:
        # dict-like vs attribute-like STIX objects
        if isinstance(grp, dict):
            name = grp.get("name", "").lower()
            aliases = [a.lower() for a in grp.get("aliases", [])]
        else:
            name = getattr(grp, "name", "").lower()
            aliases = [a.lower() for a in getattr(grp, "aliases", [])]

        if query in name or any(query in alias for alias in aliases):
            match = grp
            break

    if match is None:
        return {
            "found": False,
            "group": None,
            "formatted": "",
            "message": (
                f"No intrusion set (APT group) found matching '{group_name}' "
                f"in domain '{domain}'."
            ),
        }

    # Extract fields consistently
    if isinstance(match, dict):
        name = match.get("name")
        stix_id = match.get("id")
        aliases = match.get("aliases", [])
        description = match.get("description") if include_description else None
    else:
        name = getattr(match, "name", None)
        stix_id = getattr(match, "id", None)
        aliases = getattr(match, "aliases", [])
        description = getattr(match, "description", None) if include_description else None

    # Resolve external attack ID (e.g., G0016)
    attack_id = None
    try:
        attack_id = attack_data.get_attack_id(stix_id)
    except Exception:
        pass

    formatted = format_objects(
        [match],
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "group": {
            "attack_id": attack_id,
            "name": name,
            "aliases": aliases,
            "stix_id": stix_id,
            "description": description,
        },
        # "formatted": formatted,
        "message": f"Found intrusion set matching '{group_name}' in domain '{domain}'.",
    }

@mcp.tool()
async def get_stix_type(
    stix_id: str,
    domain: str = "enterprise",
) -> Dict[str, Any]:
    """
    Determine the STIX object type for a given STIX ID.

    This is useful when you have a raw STIX UUID (e.g.,
    "attack-pattern--xxxx") but need to know whether it corresponds to a
    technique, intrusion set, malware, tool, mitigation, data source, etc.

    Args:
        stix_id: The STIX UUID identifier to look up.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").

    Returns:
        {
            "found": bool,
            "stix_type": "<type string or null>",
            "message": "<status message>"
        }

    Examples:
        get_stix_type("attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b")
        → "attack-pattern"
    """
    attack_data = get_attack_data(domain)

    try:
        stix_type = attack_data.get_stix_type(stix_id)
    except Exception:
        stix_type = None

    if stix_type is None:
        return {
            "found": False,
            "stix_type": None,
            "message": f"No STIX object found for ID '{stix_id}' in domain '{domain}'.",
        }

    return {
        "found": True,
        "stix_type": stix_type,
        "message": f"STIX object type for '{stix_id}' is '{stix_type}'.",
    }

@mcp.tool()
async def search_groups(
    query: str = "",
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK intrusion sets (APT groups) by name, alias, or
    description (case-insensitive).

    If the query is empty, all groups in the domain are returned.

    Args:
        query: Search keyword (name, alias, or any text in the description).
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include descriptions in the output.

    Returns:
        {
          "count": <number of matches>,
          "groups": [
            {
              "attack_id": "GXXXX",
              "name": "...",
              "aliases": [...],
              "stix_id": "...",
              "description": "..." | null
            },
            ...
          ],
          "formatted": "<LLM-friendly block>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        groups = attack_data.get_groups(remove_revoked_deprecated=True)
    except Exception:
        groups = []

    # Empty query → return all groups
    query_lower = query.lower().strip()
    matched = []

    for grp in groups:
        # extract fields safely
        if isinstance(grp, dict):
            name = grp.get("name", "").lower()
            description = grp.get("description", "").lower()
            aliases = [a.lower() for a in grp.get("aliases", [])]
        else:
            name = getattr(grp, "name", "").lower()
            description = getattr(grp, "description", "").lower()
            aliases = [a.lower() for a in getattr(grp, "aliases", [])]

        if not query_lower:
            matched.append(grp)
            continue

        if (
            query_lower in name
            or query_lower in description
            or any(query_lower in a for a in aliases)
        ):
            matched.append(grp)

    # If nothing matched
    if not matched:
        return {
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": f"No APT groups in domain '{domain}' matched query '{query}'.",
        }

    # Build structured output
    response_groups = []
    for grp in matched:
        if isinstance(grp, dict):
            name = grp.get("name")
            stix_id = grp.get("id")
            aliases = grp.get("aliases", [])
            description = grp.get("description") if include_description else None
        else:
            name = getattr(grp, "name", None)
            stix_id = getattr(grp, "id", None)
            aliases = getattr(grp, "aliases", [])
            description = getattr(grp, "description", None) if include_description else None

        # Resolve ATT&CK external ID (e.g., G0016)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        response_groups.append(
            {
                "attack_id": attack_id,
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "description": description,
            }
        )

    formatted = format_objects(
        matched,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(response_groups),
        "groups": response_groups,
        # "formatted": formatted,
        "message": (
            f"Found {len(response_groups)} APT group(s) in domain '{domain}' "
            f"matching query '{query}'."
        ),
    }

@mcp.tool()
async def get_group_techniques(
    group_name: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques used by a specific APT group (intrusion set).

    This tool:
      1) Locates a group by name or alias (case-insensitive, partial match).
      2) Uses MITRE's get_techniques_used_by_group() to retrieve techniques
         related to that group (via 'uses' relationships).

    Args:
        group_name: Group name or alias (e.g., "APT29", "Lazarus Group").
        domain: ATT&CK domain ("enterprise", "mobile", or "ics").
        include_description: Whether to include descriptions in the output.

    Returns:
        {
          "found": bool,  # whether the group was found
          "group": {
              "attack_id": "GXXXX",
              "name": "...",
              "aliases": [...],
              "stix_id": "intrusion-set--...",
              "description": "..." | null
          } | null,
          "count": <number of techniques>,
          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY",
              "name": "...",
              "stix_id": "attack-pattern--...",
              "description": "..." | null,
              "relationships": [
                {
                  "stix_id": "relationship--...",
                  "relationship_type": "uses",
                  "description": "..." | null,
                  "source_ref": "...",
                  "target_ref": "..."
                },
                ...
              ]
            },
            ...
          ],
          "formatted": "<human-readable technique list>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # --- 1) Find the group by name or alias (same semantics as get_group_by_name) ---
    try:
        groups = attack_data.get_groups(remove_revoked_deprecated=True)
    except Exception:
        groups = []

    query = group_name.lower()
    group = None

    for grp in groups:
        if isinstance(grp, dict):
            name = (grp.get("name") or "").lower()
            aliases = [a.lower() for a in grp.get("aliases", [])]
        else:
            name = (getattr(grp, "name", "") or "").lower()
            aliases = [a.lower() for a in getattr(grp, "aliases", [])]

        if query in name or any(query in alias for alias in aliases):
            group = grp
            break

    if group is None:
        return {
            "found": False,
            "group": None,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No intrusion set (APT group) found matching '{group_name}' "
                f"in domain '{domain}'."
            ),
        }

    # Extract basic group fields
    if isinstance(group, dict):
        group_name_val = group.get("name")
        group_stix_id = group.get("id")
        group_aliases = group.get("aliases", [])
        group_desc = group.get("description") if include_description else None
    else:
        group_name_val = getattr(group, "name", None)
        group_stix_id = getattr(group, "id", None)
        group_aliases = getattr(group, "aliases", [])
        group_desc = getattr(group, "description", None) if include_description else None

    try:
        group_attack_id = attack_data.get_attack_id(group_stix_id)
    except Exception:
        group_attack_id = None

    # --- 2) Get techniques used by this group ---
    try:
        rel_entries = attack_data.get_techniques_used_by_group(group_stix_id)
    except Exception:
        rel_entries = []

    # rel_entries is a list of RelationshipEntry[AttackPattern]:
    # each entry is like { "object": <Technique>, "relationships": [<Relationship>, ...] }

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # Defensive: handle dict vs object
        if isinstance(entry, dict):
            tech_obj = entry.get("object")
            rels = entry.get("relationships", [])
        else:
            # If the library ever changes the type, be conservative
            tech_obj = getattr(entry, "object", None)
            rels = getattr(entry, "relationships", [])

        if tech_obj is None:
            continue

        technique_objects_for_format.append(tech_obj)

        # Extract technique fields
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_stix_id = tech_obj.get("id")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_stix_id = getattr(tech_obj, "id", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

        # ATT&CK external ID (TXXXX / TXXXX.YYY)
        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id)
        except Exception:
            t_attack_id = None

        # Compact relationship info
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        techniques_structured.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix_id,
                "description": t_desc,
                "relationships": relationships_info,
            }
        )

    # Human-readable formatted list of techniques (ignore relationship metadata there)
    formatted = ""
    if technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "found": True,
        "group": {
            "attack_id": group_attack_id,
            "name": group_name_val,
            "aliases": group_aliases,
            "stix_id": group_stix_id,
            "description": group_desc,
        },
        "count": len(techniques_structured),
        "techniques": techniques_structured,
        # "formatted": formatted,
        "message": (
            f"Found {len(techniques_structured)} technique(s) used by group "
            f"'{group_name}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_software(
    domain: str = "enterprise",
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all software (malware and tools) in a given ATT&CK domain.

    This returns non-revoked, non-deprecated software objects, including
    both malware and tools, as defined by the MITRE ATT&CK dataset.

    Args:
        domain: ATT&CK domain to search ("enterprise", "mobile", or "ics").
        include_description: Whether to include descriptions in the output and
                             formatted text.

    Returns:
        {
          "count": <number of software objects>,
          "software": [
            {
              "attack_id": "<SXXXX or similar, if present>",
              "name": "<software name>",
              "stix_id": "<STIX ID>",
              "type": "<malware|tool|...>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<human-readable list>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        software_objs = attack_data.get_software(remove_revoked_deprecated=True)
    except Exception:
        software_objs = []

    if not software_objs:
        return {
            "count": 0,
            "software": [],
            "formatted": "",
            "message": f"No software objects found in domain '{domain}'.",
        }

    software_list: List[Dict[str, Any]] = []

    for obj in software_objs:
        if isinstance(obj, dict):
            name = obj.get("name")
            stix_id = obj.get("id")
            stix_type = obj.get("type")
            description = obj.get("description") if include_description else None
        else:
            name = getattr(obj, "name", None)
            stix_id = getattr(obj, "id", None)
            stix_type = getattr(obj, "type", None)
            description = getattr(obj, "description", None) if include_description else None

        # External ATT&CK ID (e.g., SXXXX)
        attack_id = None
        if stix_id:
            try:
                attack_id = attack_data.get_attack_id(stix_id)
            except Exception:
                attack_id = None

        software_list.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "type": stix_type,
                "description": description,
            }
        )

    formatted = format_objects(
        software_objs,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(software_list),
        "software": software_list,
        "formatted": formatted,
        "message": (
            f"Found {len(software_list)} software object(s) "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool()
async def search_software(
    query: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Search MITRE ATT&CK software (malware & tools) by keyword in name or
    description (case-insensitive).

    Args:
        query: Keyword to search for in software names and descriptions.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include descriptions in the response.

    Returns:
        {
          "count": <number of matches>,
          "software": [
            {
              "attack_id": "<SXXXX or similar>",
              "name": "...",
              "stix_id": "...",
              "type": "<tool|malware|...>",
              "description": "..." | null
            },
            ...
          ],
          "formatted": "<nicely formatted block>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Load all software objects
    try:
        all_sw = attack_data.get_software(remove_revoked_deprecated=True)
    except Exception:
        all_sw = []

    if not all_sw:
        return {
            "count": 0,
            "software": [],
            "formatted": "",
            "message": f"No software found in domain '{domain}'.",
        }

    query_lower = query.lower()
    matched = []

    # Software search loop
    for sw in all_sw:
        if isinstance(sw, dict):
            name = (sw.get("name") or "").lower()
            description = (sw.get("description") or "").lower()
        else:
            name = (getattr(sw, "name", "") or "").lower()
            description = (getattr(sw, "description", "") or "").lower()

        if query_lower in name or query_lower in description:
            matched.append(sw)

    if not matched:
        return {
            "count": 0,
            "software": [],
            "formatted": "",
            "message": (
                f"No software objects in domain '{domain}' matched query '{query}'."
            ),
        }

    # Build structured output
    structured = []

    for sw in matched:
        if isinstance(sw, dict):
            name = sw.get("name")
            stix_id = sw.get("id")
            sw_type = sw.get("type")
            desc = sw.get("description") if include_description else None
        else:
            name = getattr(sw, "name", None)
            stix_id = getattr(sw, "id", None)
            sw_type = getattr(sw, "type", None)
            desc = getattr(sw, "description", None) if include_description else None

        # ATT&CK external ID (SXXXX)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "type": sw_type,
                "description": desc,
            }
        )

    formatted = format_objects(
        matched,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(structured),
        "software": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} software object(s) in domain '{domain}' "
            f"matching '{query}'."
        ),
    }

@mcp.tool()
async def get_attack_id(
    stix_id: str,
    domain: str = "enterprise",
) -> Dict[str, Any]:
    """
    Convert a STIX UUID into its human-readable ATT&CK ID.

    This tool resolves internal STIX identifiers such as:
        attack-pattern--UUID
        malware--UUID
        intrusion-set--UUID
        tool--UUID
        course-of-action--UUID

    into ATT&CK IDs such as:
        T1566      (Technique)
        T1055.002  (Sub-technique)
        G0016      (Group)
        S0154      (Software)
        M1013      (Mitigation)

    Args:
        stix_id: Full STIX UUID identifier.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").

    Returns:
        {
          "found": bool,
          "attack_id": "<ATT&CK ID or null>",
          "message": "<status message>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        attack_id = attack_data.get_attack_id(stix_id)
    except Exception:
        attack_id = None

    if attack_id is None:
        return {
            "found": False,
            "attack_id": None,
            "message": (
                f"No ATT&CK ID found for STIX ID '{stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    return {
        "found": True,
        "attack_id": attack_id,
        "message": (
            f"Resolved STIX ID '{stix_id}' to ATT&CK ID '{attack_id}' "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_name(
    stix_id: str,
    domain: str = "enterprise",
) -> Dict[str, Any]:
    """
    Resolve the human-readable object name for a given STIX ID.

    This converts internal STIX UUIDs such as:
        attack-pattern--UUID
        intrusion-set--UUID
        malware--UUID
        tool--UUID
        course-of-action--UUID

    into ATT&CK object names such as:
        "Phishing"
        "APT29"
        "Cobalt Strike"
        "Valid Accounts"

    Args:
        stix_id: STIX UUID of the object.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").

    Returns:
        {
          "found": bool,
          "name": "<object name or null>",
          "message": "<status message>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        name = attack_data.get_name(stix_id)
    except Exception:
        name = None

    if not name:
        return {
            "found": False,
            "name": None,
            "message": (
                f"No ATT&CK object name found for STIX ID '{stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    return {
        "found": True,
        "name": name,
        "message": (
            f"Resolved STIX ID '{stix_id}' to object name '{name}' "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_technique_tactics(
    technique_id: str,
    domain: str = "enterprise",
) -> Dict[str, Any]:
    """
    Get the ATT&CK tactic names associated with a given technique.

    This tool:
      1) Looks up a technique by its external ATT&CK ID (e.g., "T1055").
      2) Extracts its kill chain phases (tactics) from the STIX object.
      3) Returns human-readable tactic names (e.g., "Initial Access"),
         along with the raw phase names and kill chain names.

    Args:
        technique_id: External ATT&CK technique ID (e.g., "T1055", "T1055.002").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").

    Returns:
        {
          "found": bool,
          "technique": {
              "id": "<ATT&CK ID>",
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--... or null>",
          } | null,
          "tactics": [
            {
              "tactic": "<Human readable, e.g., 'Initial Access'>",
              "phase_name": "<raw phase name, e.g., 'initial-access'>",
              "kill_chain_name": "<kill chain name, e.g., 'mitre-attack'>"
            },
            ...
          ],
          "message": "<status message>"
        }
    """
    attack_data = get_attack_data(domain)

    # 1) Look up the technique by ATT&CK ID
    try:
        tech = attack_data.get_object_by_attack_id(technique_id, "attack-pattern")
    except Exception:
        tech = None

    if tech is None:
        return {
            "found": False,
            "technique": None,
            "tactics": [],
            "message": (
                f"Technique '{technique_id}' not found in domain '{domain}'."
            ),
        }

    # 2) Extract basic technique fields
    if isinstance(tech, dict):
        tech_name = tech.get("name")
        tech_stix_id = tech.get("id")
        phases = tech.get("kill_chain_phases", []) or []
    else:
        tech_name = getattr(tech, "name", None)
        tech_stix_id = getattr(tech, "id", None)
        phases = getattr(tech, "kill_chain_phases", []) or []

    # 3) Normalize phases into tactic objects
    tactics: List[Dict[str, Any]] = []

    for phase in phases:
        # Handle dict-like vs object-like phase entries
        if isinstance(phase, dict):
            phase_name = phase.get("phase_name", "")
            kill_chain_name = phase.get("kill_chain_name", "")
        else:
            phase_name = getattr(phase, "phase_name", "") or ""
            kill_chain_name = getattr(phase, "kill_chain_name", "") or ""

        # Human-readable tactic label, e.g. "initial-access" -> "Initial Access"
        tactic_label = phase_name.replace("-", " ").title() if phase_name else None

        tactics.append(
            {
                "tactic": tactic_label,
                "phase_name": phase_name,
                "kill_chain_name": kill_chain_name,
            }
        )

    # 4) Return structured result
    return {
        "found": True,
        "technique": {
            "id": technique_id,
            "name": tech_name,
            "stix_id": tech_stix_id,
        },
        "tactics": tactics,
        "message": (
            f"Found {len(tactics)} tactic phase(s) for technique '{technique_id}' "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_stats(
    domain: str = "enterprise",
) -> Dict[str, Any]:
    """
    Get basic statistics about the loaded ATT&CK data for a given domain.

    This returns counts of key object types (techniques, groups, software,
    tactics, mitigations), excluding revoked/deprecated entries.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").

    Returns:
        {
          "domain": "<domain>",
          "stats": {
              "techniques": <int>,
              "groups": <int>,
              "software": <int>,
              "tactics": <int>,
              "mitigations": <int>
          },
          "message": "<status message>"
        }
    """
    attack_data = get_attack_data(domain)

    def safe_count(getter) -> int:
        try:
            return len(getter(remove_revoked_deprecated=True))
        except Exception:
            return 0

    stats = {
        "techniques": safe_count(attack_data.get_techniques),
        "groups": safe_count(attack_data.get_groups),
        "software": safe_count(attack_data.get_software),
        "tactics": safe_count(attack_data.get_tactics),
        "mitigations": safe_count(attack_data.get_mitigations),
    }

    return {
        "domain": domain,
        "stats": stats,
        "message": (
            f"ATT&CK object statistics for domain '{domain}': "
            f"{stats['techniques']} techniques, "
            f"{stats['groups']} groups, "
            f"{stats['software']} software, "
            f"{stats['tactics']} tactics, "
            f"{stats['mitigations']} mitigations."
        ),
    }
#####################################################################
    # Threat Actor Group functions
#####################################################################

@mcp.tool()
async def get_groups_by_alias(
    alias: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get APT groups (intrusion sets) matching a given alias.

    Many groups have multiple aliases—e.g., APT29 is also known as:
    "Cozy Bear", "NOBELIUM", "Midnight Blizzard", etc.
    
    This tool returns all groups whose alias list contains the given alias
    (case-insensitive exact match, per MITRE's own alias indexing).

    Args:
        alias: Alias to search for (e.g., "Cozy Bear", "NOBELIUM").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include group descriptions.

    Returns:
        {
          "count": <number>,
          "groups": [
            {
              "attack_id": "GXXXX",
              "name": "<group name>",
              "aliases": [...],
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<formatted list>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        raw_groups = attack_data.get_groups_by_alias(alias)
    except Exception:
        raw_groups = []

    if not raw_groups:
        return {
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": (
                f"No groups found with alias '{alias}' in domain '{domain}'."
            ),
        }

    groups_structured = []
    for grp in raw_groups:
        if isinstance(grp, dict):
            name = grp.get("name")
            stix_id = grp.get("id")
            aliases = grp.get("aliases", [])
            description = grp.get("description") if include_description else None
        else:
            name = getattr(grp, "name", None)
            stix_id = getattr(grp, "id", None)
            aliases = getattr(grp, "aliases", [])
            description = getattr(grp, "description", None) if include_description else None

        # Resolve ATT&CK external ID (GXXXX)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        groups_structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "description": description,
            }
        )

    # Use your global formatting helper
    formatted = format_objects(
        raw_groups,
        include_description=include_description,
        domain=domain,
    )

    return {
        "count": len(groups_structured),
        "groups": groups_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(groups_structured)} group(s) with alias '{alias}' "
            f"in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_techniques_used_by_group(
    group_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques used by a specific APT group, identified by its STIX ID.

    This is similar to `get_group_techniques`, but instead of a group name or
    alias it takes the group's STIX UUID (e.g. "intrusion-set--..."), which is
    useful when you already have the STIX ID from another query or relationship.

    Args:
        group_stix_id: STIX ID of the group (intrusion-set--UUID).
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "group": {
              "attack_id": "GXXXX" | null,
              "name": "<group name or null>",
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>"
          } | null,
          "count": <number of techniques>,
          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>"
                },
                ...
              ]
            },
            ...
          ],
          "formatted": "<human-readable technique list>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Try to resolve basic group info from its STIX ID (optional but useful)
    try:
        grp_obj = attack_data.get_object_by_stix_id(group_stix_id)
    except Exception:
        grp_obj = None

    group_info: Optional[Dict[str, Any]] = None
    if grp_obj is not None:
        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_desc = getattr(grp_obj, "description", None) if include_description else None

        try:
            g_attack_id = attack_data.get_attack_id(group_stix_id)
        except Exception:
            g_attack_id = None

        group_info = {
            "attack_id": g_attack_id,
            "name": g_name,
            "stix_id": group_stix_id,
            "description": g_desc,
        }

    # Fetch techniques used by this group
    try:
        rel_entries = attack_data.get_techniques_used_by_group(group_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "group": group_info,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found for group STIX ID '{group_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for entry in rel_entries:
        if isinstance(entry, dict):
            tech_obj = entry.get("object")
            rels = entry.get("relationships", [])
        else:
            tech_obj = getattr(entry, "object", None)
            rels = getattr(entry, "relationships", [])

        if tech_obj is None:
            continue

        technique_objects_for_format.append(tech_obj)

        # Technique fields
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_stix_id = tech_obj.get("id")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_stix_id = getattr(tech_obj, "id", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id)
        except Exception:
            t_attack_id = None

        # Relationship info
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        techniques_structured.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix_id,
                "description": t_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "group": group_info,
        "count": len(techniques_structured),
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(techniques_structured)} technique(s) for group STIX ID "
            f"'{group_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_software_used_by_group(
    group_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all software (malware and tools) used by a specific APT group,
    identified by its STIX ID.

    This uses MITRE's `get_software_used_by_group` to follow 'uses'
    relationships from an intrusion set (group) to software objects.

    Args:
        group_stix_id: STIX ID of the group (e.g., "intrusion-set--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include software descriptions.

    Returns:
        {
          "group": {
              "attack_id": "GXXXX" | null,
              "name": "<group name or null>",
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>"
          } | null,
          "count": <number of software objects>,
          "software": [
            {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name>",
              "stix_id": "<STIX ID>",
              "type": "<malware|tool|...>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],
          "formatted": "<human-readable list of software>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Optional: resolve group info from its STIX ID
    try:
        grp_obj = attack_data.get_object_by_stix_id(group_stix_id)
    except Exception:
        grp_obj = None

    group_info: Optional[Dict[str, Any]] = None
    if grp_obj is not None:
        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_desc = getattr(grp_obj, "description", None) if include_description else None

        try:
            g_attack_id = attack_data.get_attack_id(group_stix_id)
        except Exception:
            g_attack_id = None

        group_info = {
            "attack_id": g_attack_id,
            "name": g_name,
            "stix_id": group_stix_id,
            "description": g_desc,
        }

    # Get software used by this group
    try:
        rel_entries = attack_data.get_software_used_by_group(group_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "group": group_info,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found for group STIX ID '{group_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    software_structured: List[Dict[str, Any]] = []
    software_objects_for_format: List[Any] = []

    for entry in rel_entries:
        if isinstance(entry, dict):
            sw_obj = entry.get("object")
            rels = entry.get("relationships", [])
        else:
            sw_obj = getattr(entry, "object", None)
            rels = getattr(entry, "relationships", [])

        if sw_obj is None:
            continue

        software_objects_for_format.append(sw_obj)

        # Extract software fields
        if isinstance(sw_obj, dict):
            s_name = sw_obj.get("name")
            s_stix_id = sw_obj.get("id")
            s_type = sw_obj.get("type")
            s_desc = sw_obj.get("description") if include_description else None
        else:
            s_name = getattr(sw_obj, "name", None)
            s_stix_id = getattr(sw_obj, "id", None)
            s_type = getattr(sw_obj, "type", None)
            s_desc = getattr(sw_obj, "description", None) if include_description else None

        # ATT&CK external ID (SXXXX, or sometimes none)
        try:
            s_attack_id = attack_data.get_attack_id(s_stix_id)
        except Exception:
            s_attack_id = None

        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        software_structured.append(
            {
                "attack_id": s_attack_id,
                "name": s_name,
                "stix_id": s_stix_id,
                "type": s_type,
                "description": s_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if software_objects_for_format:
        formatted = format_objects(
            software_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "group": group_info,
        "count": len(software_structured),
        "software": software_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(software_structured)} software object(s) used by group "
            f"STIX ID '{group_stix_id}' in domain '{domain}'."
        ),
    }


# ---------------------------------------------------------------------------
# Campaign lookup
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_campaigns_attributed_to_group(
    group_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all campaigns attributed to a specific intrusion set (APT group),
    identified by its STIX ID.

    Campaigns represent specific operations or intrusion events attributed
    to a threat group.

    Args:
        group_stix_id: STIX UUID of the group (e.g., "intrusion-set--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include campaign descriptions.

    Returns:
        {
          "group": {
              "attack_id": "GXXXX" | null,
              "name": "<group name or null>",
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>"
          } | null,

          "count": <number of campaigns>,

          "campaigns": [
            {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name>",
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>"
            },
            ...
          ],

          "formatted": "<formatted human-readable block>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Optional: resolve group details
    try:
        grp_obj = attack_data.get_object_by_stix_id(group_stix_id)
    except Exception:
        grp_obj = None

    group_info = None
    if grp_obj is not None:
        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_desc = getattr(grp_obj, "description", None) if include_description else None

        try:
            g_attack_id = attack_data.get_attack_id(group_stix_id)
        except Exception:
            g_attack_id = None

        group_info = {
            "attack_id": g_attack_id,
            "name": g_name,
            "stix_id": group_stix_id,
            "description": g_desc,
        }

    # Retrieve campaigns for this group
    try:
        campaign_entries = attack_data.get_campaigns_attributed_to_group(group_stix_id)
    except Exception:
        campaign_entries = []

    if not campaign_entries:
        return {
            "group": group_info,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": (
                f"No campaigns attributed to group STIX ID '{group_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    structured_campaigns = []
    campaign_objects_for_format = []

    for c in campaign_entries:
        if isinstance(c, dict):
            name = c.get("name")
            stix_id = c.get("id")
            desc = c.get("description") if include_description else None
        else:
            name = getattr(c, "name", None)
            stix_id = getattr(c, "id", None)
            desc = getattr(c, "description", None) if include_description else None

        # Save for formatted output
        campaign_objects_for_format.append(c)

        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured_campaigns.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": desc,
            }
        )

    formatted = format_objects(
        campaign_objects_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "group": group_info,
        "count": len(structured_campaigns),
        "campaigns": structured_campaigns,
        "formatted": formatted,
        "message": (
            f"Found {len(structured_campaigns)} campaign(s) attributed to group "
            f"STIX ID '{group_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_campaigns_by_alias(
    alias: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get campaigns by their alias.

    Campaigns frequently have multiple names assigned by different vendors
    or research teams. This function resolves those aliases.

    Args:
        alias: Campaign alias or alternate name (case-insensitive)
        domain: ATT&CK domain ("enterprise", "ics", etc.)
        include_description: Include campaign descriptions in output

    Returns:
        {
          "alias": "<requested name>",
          "count": int,
          "campaigns": [
            {
              "name": "...",
              "stix_id": "<campaign--UUID>",
              "attack_id": "Cxxxx" | null,
              "description": "..." | null
            },
            ...
          ],
          "formatted": "<multi-line readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Retrieve matching campaigns
    try:
        campaigns = attack_data.get_campaigns_by_alias(alias) or []
    except Exception:
        campaigns = []

    if not campaigns:
        return {
            "alias": alias,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": f"No campaigns found with alias '{alias}' in domain '{domain}'.",
        }

    # Build structured campaign entries
    campaign_entries = []
    for c in campaigns:
        name = getattr(c, "name", None)
        stix_id = getattr(c, "id", None)

        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        description = getattr(c, "description", None) if include_description else None

        campaign_entries.append(
            {
                "name": name,
                "stix_id": stix_id,
                "attack_id": attack_id,
                "description": description,
            }
        )

    # Human-friendly formatted text
    formatted = format_objects(
        campaigns,
        include_description=include_description,
        domain=domain,
    )

    return {
        "alias": alias,
        "count": len(campaign_entries),
        "campaigns": campaign_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(campaign_entries)} campaign(s) matching alias '{alias}' "
            f"in domain '{domain}'."
        ),
    }


@mcp.tool()
async def get_techniques_used_by_group_software(
    group_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get techniques used by the software that a group uses (Group → Software → Techniques).

    This provides an indirect view of a group's capabilities by following:
        Group (intrusion set) → Software (malware/tools) → Techniques

    Args:
        group_stix_id: STIX ID of the group (e.g., "intrusion-set--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "group": {
              "attack_id": "GXXXX" | null,
              "name": "<group name or null>",
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of techniques>,

          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of techniques>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Optional: resolve group details for context
    try:
        grp_obj = attack_data.get_object_by_stix_id(group_stix_id)
    except Exception:
        grp_obj = None

    group_info: Optional[Dict[str, Any]] = None
    if grp_obj is not None:
        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_desc = getattr(grp_obj, "description", None) if include_description else None

        try:
            g_attack_id = attack_data.get_attack_id(group_stix_id)
        except Exception:
            g_attack_id = None

        group_info = {
            "attack_id": g_attack_id,
            "name": g_name,
            "stix_id": group_stix_id,
            "description": g_desc,
        }

    # Call MITRE helper: techniques reachable via group’s software
    try:
        rel_entries = attack_data.get_techniques_used_by_group_software(group_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "group": group_info,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found via software used by group STIX ID "
                f"'{group_stix_id}' in domain '{domain}'."
            ),
        }

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for entry in rel_entries:
        if isinstance(entry, dict):
            tech_obj = entry.get("object")
            rels = entry.get("relationships", [])
        else:
            tech_obj = getattr(entry, "object", None)
            rels = getattr(entry, "relationships", [])

        if tech_obj is None:
            continue

        technique_objects_for_format.append(tech_obj)

        # Extract technique info
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_stix_id = tech_obj.get("id")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_stix_id = getattr(tech_obj, "id", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

        # External ATT&CK ID (TXXXX / TXXXX.YYY)
        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id)
        except Exception:
            t_attack_id = None

        # Relationship metadata
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        techniques_structured.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix_id,
                "description": t_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "group": group_info,
        "count": len(techniques_structured),
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(techniques_structured)} technique(s) reachable via software "
            f"used by group STIX ID '{group_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_groups_using_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all APT groups (intrusion sets) that use a specific technique.

    This is a reverse lookup: Technique → Groups.
    It follows 'uses' relationships from a technique STIX ID to intrusion sets.

    Args:
        technique_stix_id: STIX ID of the technique
                           (e.g., "attack-pattern--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include group descriptions.

    Returns:
        {
          "technique": {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of groups>,

          "groups": [
            {
              "attack_id": "GXXXX" | null,
              "name": "<group name>",
              "aliases": [...],
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of groups>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Optional: resolve technique metadata
    try:
        tech_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        tech_obj = None

    technique_info: Optional[Dict[str, Any]] = None
    if tech_obj is not None:
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None

        technique_info = {
            "attack_id": t_attack_id,
            "name": t_name,
            "stix_id": technique_stix_id,
            "description": t_desc,
        }

    # Get groups that use this technique
    try:
        rel_entries = attack_data.get_groups_using_technique(technique_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "technique": technique_info,
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": (
                f"No groups found using technique STIX ID '{technique_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    groups_structured: List[Dict[str, Any]] = []
    group_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # Some APIs may return RelationshipEntry-like objects with .object/.relationships,
        # others may return plain group objects. Handle both defensively.
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            grp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            # Could be an object with attributes or a bare dict group
            grp_obj = entry
            rels = []

        if grp_obj is None:
            continue

        group_objects_for_format.append(grp_obj)

        # Extract group fields
        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_stix_id = grp_obj.get("id")
            g_aliases = grp_obj.get("aliases", [])
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_stix_id = getattr(grp_obj, "id", None)
            g_aliases = getattr(grp_obj, "aliases", [])
            g_desc = getattr(grp_obj, "description", None) if include_description else None

        # External ATT&CK ID (GXXXX)
        try:
            g_attack_id = attack_data.get_attack_id(g_stix_id)
        except Exception:
            g_attack_id = None

        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        groups_structured.append(
            {
                "attack_id": g_attack_id,
                "name": g_name,
                "aliases": g_aliases,
                "stix_id": g_stix_id,
                "description": g_desc,
                "relationships": relationships_info,
            }
        )

    # Nicely formatted human-readable block
    formatted = ""
    if group_objects_for_format:
        formatted = format_objects(
            group_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "technique": technique_info,
        "count": len(groups_structured),
        "groups": groups_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(groups_structured)} group(s) using technique STIX ID "
            f"'{technique_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_groups_using_software(
    software_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all APT groups (intrusion sets) that use a specific software/malware.

    This is a reverse lookup: Software → Groups.
    It follows 'uses' relationships from a software STIX ID (tool/malware)
    to intrusion sets.

    Args:
        software_stix_id: STIX ID of the software object
                          (e.g., "malware--UUID", "tool--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include group descriptions.

    Returns:
        {
          "software": {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name or null>",
              "stix_id": "<software STIX ID>",
              "type": "<tool|malware|...> or null",
              "description": "<text or null>",
          } | null,

          "count": <number of groups>,

          "groups": [
            {
              "attack_id": "GXXXX" | null,
              "name": "<group name>",
              "aliases": [...],
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of groups>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Optional: resolve software metadata
    try:
        sw_obj = attack_data.get_object_by_stix_id(software_stix_id)
    except Exception:
        sw_obj = None

    software_info: Optional[Dict[str, Any]] = None
    if sw_obj is not None:
        if isinstance(sw_obj, dict):
            s_name = sw_obj.get("name")
            s_type = sw_obj.get("type")
            s_desc = sw_obj.get("description") if include_description else None
        else:
            s_name = getattr(sw_obj, "name", None)
            s_type = getattr(sw_obj, "type", None)
            s_desc = getattr(sw_obj, "description", None) if include_description else None

        try:
            s_attack_id = attack_data.get_attack_id(software_stix_id)
        except Exception:
            s_attack_id = None

        software_info = {
            "attack_id": s_attack_id,
            "name": s_name,
            "stix_id": software_stix_id,
            "type": s_type,
            "description": s_desc,
        }

    # Get groups that use this software
    try:
        rel_entries = attack_data.get_groups_using_software(software_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "software": software_info,
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": (
                f"No groups found using software STIX ID '{software_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    groups_structured: List[Dict[str, Any]] = []
    group_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # RelationshipEntry-like or plain group object
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            grp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            grp_obj = entry
            rels = []

        if grp_obj is None:
            continue

        group_objects_for_format.append(grp_obj)

        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_stix_id = grp_obj.get("id")
            g_aliases = grp_obj.get("aliases", [])
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_stix_id = getattr(grp_obj, "id", None)
            g_aliases = getattr(grp_obj, "aliases", [])
            g_desc = getattr(grp_obj, "description", None) if include_description else None

        try:
            g_attack_id = attack_data.get_attack_id(g_stix_id)
        except Exception:
            g_attack_id = None

        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        groups_structured.append(
            {
                "attack_id": g_attack_id,
                "name": g_name,
                "aliases": g_aliases,
                "stix_id": g_stix_id,
                "description": g_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if group_objects_for_format:
        formatted = format_objects(
            group_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "software": software_info,
        "count": len(groups_structured),
        "groups": groups_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(groups_structured)} group(s) using software STIX ID "
            f"'{software_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_groups_attributing_to_campaign(
    campaign_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all APT groups (intrusion sets) attributed to a specific campaign.

    This is a reverse lookup: Campaign → Groups.
    It follows attribution relationships from a campaign STIX ID to
    intrusion sets (groups).

    Args:
        campaign_stix_id: STIX ID of the campaign (e.g., "campaign--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include group descriptions.

    Returns:
        {
          "campaign": {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name or null>",
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>"
          } | null,

          "count": <number of groups>,

          "groups": [
            {
              "attack_id": "GXXXX" | null,
              "name": "<group name>",
              "aliases": [...],
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "<type>",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of groups>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Optional: resolve campaign metadata
    try:
        camp_obj = attack_data.get_object_by_stix_id(campaign_stix_id)
    except Exception:
        camp_obj = None

    campaign_info: Optional[Dict[str, Any]] = None
    if camp_obj is not None:
        if isinstance(camp_obj, dict):
            c_name = camp_obj.get("name")
            c_desc = camp_obj.get("description") if include_description else None
        else:
            c_name = getattr(camp_obj, "name", None)
            c_desc = getattr(camp_obj, "description", None) if include_description else None

        try:
            c_attack_id = attack_data.get_attack_id(campaign_stix_id)
        except Exception:
            c_attack_id = None

        campaign_info = {
            "attack_id": c_attack_id,
            "name": c_name,
            "stix_id": campaign_stix_id,
            "description": c_desc,
        }

    # Get groups attributed to this campaign
    try:
        rel_entries = attack_data.get_groups_attributing_to_campaign(campaign_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "campaign": campaign_info,
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": (
                f"No groups found attributing to campaign STIX ID "
                f"'{campaign_stix_id}' in domain '{domain}'."
            ),
        }

    groups_structured: List[Dict[str, Any]] = []
    group_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # RelationshipEntry-like or plain group object
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            grp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            grp_obj = entry
            rels = []

        if grp_obj is None:
            continue

        group_objects_for_format.append(grp_obj)

        # Extract group fields
        if isinstance(grp_obj, dict):
            g_name = grp_obj.get("name")
            g_stix_id = grp_obj.get("id")
            g_aliases = grp_obj.get("aliases", [])
            g_desc = grp_obj.get("description") if include_description else None
        else:
            g_name = getattr(grp_obj, "name", None)
            g_stix_id = getattr(grp_obj, "id", None)
            g_aliases = getattr(grp_obj, "aliases", [])
            g_desc = getattr(grp_obj, "description", None) if include_description else None

        # External ATT&CK ID (GXXXX)
        try:
            g_attack_id = attack_data.get_attack_id(g_stix_id)
        except Exception:
            g_attack_id = None

        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        groups_structured.append(
            {
                "attack_id": g_attack_id,
                "name": g_name,
                "aliases": g_aliases,
                "stix_id": g_stix_id,
                "description": g_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if group_objects_for_format:
        formatted = format_objects(
            group_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "campaign": campaign_info,
        "count": len(groups_structured),
        "groups": groups_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(groups_structured)} group(s) attributed to campaign "
            f"STIX ID '{campaign_stix_id}' in domain '{domain}'."
        ),
    }

#####################################################################
    # Software functions
#####################################################################
@mcp.tool()
async def get_software_by_alias(
    alias: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Find software/malware by alias (e.g., 'Beacon', 'Mimilib').

    Many malware/tools have multiple alternative names. This tool searches
    the software catalog for alias matches.

    Args:
        alias: Alias to search for.
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include description fields.

    Returns:
        {
          "alias": "<alias>",
          "count": <number of matches>,
          "software": [
            {
              "attack_id": "<SXXXX or MXXXX or None>",
              "name": "<software name>",
              "aliases": [...],
              "stix_id": "<malware--UUID or tool--UUID>",
              "type": "<malware|tool|...>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<human readable output>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Query the underlying library
    try:
        results = attack_data.get_software_by_alias(alias)
    except Exception:
        results = []

    if not results:
        return {
            "alias": alias,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found for alias '{alias}' "
                f"in domain '{domain}'."
            ),
        }

    structured = []
    software_objects_for_format = []

    for sw in results:
        # MITRE library returns STIX objects that may be dicts or objects
        if isinstance(sw, dict):
            s_name = sw.get("name")
            s_stix_id = sw.get("id")
            s_aliases = sw.get("aliases", [])
            s_type = sw.get("type")
            s_desc = sw.get("description") if include_description else None
        else:
            s_name = getattr(sw, "name", None)
            s_stix_id = getattr(sw, "id", None)
            s_aliases = getattr(sw, "aliases", [])
            s_type = getattr(sw, "type", None)
            s_desc = getattr(sw, "description", None) if include_description else None

        # External ATT&CK ID (e.g., SXXXX)
        try:
            s_attack_id = attack_data.get_attack_id(s_stix_id)
        except Exception:
            s_attack_id = None

        software_objects_for_format.append(sw)

        structured.append(
            {
                "attack_id": s_attack_id,
                "name": s_name,
                "aliases": s_aliases,
                "stix_id": s_stix_id,
                "type": s_type,
                "description": s_desc,
            }
        )

    # Optional human-readable formatting
    formatted = ""
    if software_objects_for_format:
        formatted = format_objects(
            software_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "alias": alias,
        "count": len(structured),
        "software": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} software item(s) matching alias "
            f"'{alias}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_software_using_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all software (malware/tools) that use a specific technique.

    This is a reverse lookup: Technique → Software.
    It follows 'uses' relationships from a technique STIX ID to software
    (malware and tools) that implement or leverage that technique.

    Args:
        technique_stix_id: STIX ID of the technique
                           (e.g., "attack-pattern--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include software descriptions.

    Returns:
        {
          "technique": {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of software objects>,

          "software": [
            {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name>",
              "stix_id": "<software STIX ID>",
              "type": "<malware|tool|...>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of software>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Optional: resolve technique metadata for context
    try:
        tech_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        tech_obj = None

    technique_info: Optional[Dict[str, Any]] = None
    if tech_obj is not None:
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None

        technique_info = {
            "attack_id": t_attack_id,
            "name": t_name,
            "stix_id": technique_stix_id,
            "description": t_desc,
        }

    # Call MITRE helper: software that uses this technique
    try:
        rel_entries = attack_data.get_software_using_technique(technique_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "technique": technique_info,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found using technique STIX ID "
                f"'{technique_stix_id}' in domain '{domain}'."
            ),
        }

    software_structured: List[Dict[str, Any]] = []
    software_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # Some helpers may return RelationshipEntry-like objects (with "object"/"relationships"),
        # others may return plain software STIX objects. We need to Handle both.
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            sw_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            sw_obj = entry
            rels = []

        if sw_obj is None:
            continue

        software_objects_for_format.append(sw_obj)

        # Extract software fields
        if isinstance(sw_obj, dict):
            s_name = sw_obj.get("name")
            s_stix_id = sw_obj.get("id")
            s_type = sw_obj.get("type")
            s_desc = sw_obj.get("description") if include_description else None
        else:
            s_name = getattr(sw_obj, "name", None)
            s_stix_id = getattr(sw_obj, "id", None)
            s_type = getattr(sw_obj, "type", None)
            s_desc = getattr(sw_obj, "description", None) if include_description else None

        # External ATT&CK ID (SXXXX / sometimes other prefix)
        try:
            s_attack_id = attack_data.get_attack_id(s_stix_id)
        except Exception:
            s_attack_id = None

        # Relationship metadata (if present)
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        software_structured.append(
            {
                "attack_id": s_attack_id,
                "name": s_name,
                "stix_id": s_stix_id,
                "type": s_type,
                "description": s_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if software_objects_for_format:
        formatted = format_objects(
            software_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "technique": technique_info,
        "count": len(software_structured),
        "software": software_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(software_structured)} software object(s) using "
            f"technique STIX ID '{technique_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_techniques_used_by_software(
    software_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques used by specific software/malware.

    This shows what ATT&CK techniques a given software (tool/malware) is
    capable of performing.

    Args:
        software_stix_id: STIX ID of the software object
                          (e.g., "malware--UUID", "tool--UUID").
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "software": {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name or null>",
              "stix_id": "<software STIX ID>",
              "type": "<malware|tool|...> or null",
              "description": "<text or null>",
          } | null,

          "count": <number of techniques>,

          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "uses",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of techniques>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Optional: resolve software metadata for context
    try:
        sw_obj = attack_data.get_object_by_stix_id(software_stix_id)
    except Exception:
        sw_obj = None

    software_info: Optional[Dict[str, Any]] = None
    if sw_obj is not None:
        if isinstance(sw_obj, dict):
            s_name = sw_obj.get("name")
            s_type = sw_obj.get("type")
            s_desc = sw_obj.get("description") if include_description else None
        else:
            s_name = getattr(sw_obj, "name", None)
            s_type = getattr(sw_obj, "type", None)
            s_desc = getattr(sw_obj, "description", None) if include_description else None

        try:
            s_attack_id = attack_data.get_attack_id(software_stix_id)
        except Exception:
            s_attack_id = None

        software_info = {
            "attack_id": s_attack_id,
            "name": s_name,
            "stix_id": software_stix_id,
            "type": s_type,
            "description": s_desc,
        }

    # Call MITRE helper: techniques used by this software
    try:
        rel_entries = attack_data.get_techniques_used_by_software(software_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "software": software_info,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found for software STIX ID "
                f"'{software_stix_id}' in domain '{domain}'."
            ),
        }

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # RelationshipEntry-like or plain technique object
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            tech_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            tech_obj = entry
            rels = []

        if tech_obj is None:
            continue

        technique_objects_for_format.append(tech_obj)

        # Extract technique info
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_stix_id = tech_obj.get("id")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_stix_id = getattr(tech_obj, "id", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

        # External ATT&CK ID (TXXXX / TXXXX.YYY)
        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id)
        except Exception:
            t_attack_id = None

        # Relationship metadata
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        techniques_structured.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix_id,
                "description": t_desc,
                "relationships": relationships_info,
            }
        )

    formatted = ""
    if technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "software": software_info,
        "count": len(techniques_structured),
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(techniques_structured)} technique(s) used by software "
            f"STIX ID '{software_stix_id}' in domain '{domain}'."
        ),
    }

#####################################################################
    # "Get All" functions for MITRE ATT&CK objects
#####################################################################

@mcp.tool()
async def get_all_techniques(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all ATT&CK techniques for a given domain.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated techniques.
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of techniques>,
          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY",
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "tactics": [ "<tactic 1>", "<tactic 2>", ... ]
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Fetch techniques from MITRE library
    try:
        techniques = attack_data.get_techniques(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"Unable to retrieve techniques for domain '{domain}'."
        }

    if not techniques:
        return {
            "domain": domain,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"No techniques found in domain '{domain}'."
        }

    structured = []
    technique_objects_for_format = []

    for tech in techniques:
        technique_objects_for_format.append(tech)

        # Extract fields (both dict or object)
        if isinstance(tech, dict):
            name = tech.get("name")
            stix_id = tech.get("id")
            description = tech.get("description") if include_description else None
            phases = tech.get("kill_chain_phases", [])
        else:
            name = getattr(tech, "name", None)
            stix_id = getattr(tech, "id", None)
            description = getattr(tech, "description", None) if include_description else None
            phases = getattr(tech, "kill_chain_phases", [])

        # ATT&CK external ID (TXXXX)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        # Map kill chain phases to readable tactics
        tactics = []
        for p in phases or []:
            phase_name = getattr(p, "phase_name", None) or p.get("phase_name")
            if phase_name:
                tactics.append(phase_name.replace("-", " ").title())

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "tactics": tactics,
            }
        )

    # Formatted block (optional)
    formatted = ""
    if technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "domain": domain,
        "count": len(structured),
        "techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} technique(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_subtechniques(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all subtechniques in a given ATT&CK domain.

    Subtechniques are more specific versions of parent techniques,
    e.g., T1566.001 and T1566.002 are subtechniques of T1566.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated subtechniques.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of subtechniques>,
          "subtechniques": [
            {
              "attack_id": "<TXXXX.YYY>",
              "name": "<subtechnique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "tactics": ["<Tactic 1>", "<Tactic 2>", ...],
              "parent_attack_id": "<TXXXX>",
              "parent_name": "<parent technique name>",
              "parent_stix_id": "<attack-pattern--UUID>"
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Get all techniques including subtechniques
    try:
        all_techniques = attack_data.get_techniques(
            remove_revoked_deprecated=remove_revoked_deprecated,
            include_subtechniques=True,
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "subtechniques": [],
            "formatted": "",
            "message": f"Unable to retrieve techniques for domain '{domain}'.",
        }

    subtechnique_objects: List[Any] = []
    structured: List[Dict[str, Any]] = []

    for t in all_techniques:
        # Determine the STIX ID for this technique
        if isinstance(t, dict):
            stix_id = t.get("id")
            name = t.get("name")
            description = t.get("description") if include_description else None
            phases = t.get("kill_chain_phases", []) or []
        else:
            stix_id = getattr(t, "id", None)
            name = getattr(t, "name", None)
            description = getattr(t, "description", None) if include_description else None
            phases = getattr(t, "kill_chain_phases", []) or []

        if not stix_id:
            continue

        # Check if this technique has a parent (i.e., is a subtechnique)
        try:
            parent_obj = attack_data.get_parent_technique_of_subtechnique(stix_id)
        except Exception:
            parent_obj = None

        if not parent_obj:
            # Not a subtechnique
            continue

        # At this point, t is a subtechnique
        subtechnique_objects.append(t)

        # Resolve subtechnique ATT&CK ID
        try:
            sub_attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            sub_attack_id = None

        # Resolve parent fields
        if isinstance(parent_obj, dict):
            parent_stix_id = parent_obj.get("id")
            parent_name = parent_obj.get("name")
        else:
            parent_stix_id = getattr(parent_obj, "id", None)
            parent_name = getattr(parent_obj, "name", None)

        try:
            parent_attack_id = (
                attack_data.get_attack_id(parent_stix_id) if parent_stix_id else None
            )
        except Exception:
            parent_attack_id = None

        # Extract tactics from kill_chain_phases
        tactics: List[str] = []
        for p in phases:
            if isinstance(p, dict):
                phase_name = p.get("phase_name")
            else:
                phase_name = getattr(p, "phase_name", None)

            if phase_name:
                tactics.append(phase_name.replace("-", " ").title())

        structured.append(
            {
                "attack_id": sub_attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "tactics": tactics,
                "parent_attack_id": parent_attack_id,
                "parent_name": parent_name,
                "parent_stix_id": parent_stix_id,
            }
        )

    if not structured:
        return {
            "domain": domain,
            "count": 0,
            "subtechniques": [],
            "formatted": "",
            "message": (
                f"No subtechniques found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    # Optional human-readable formatting using your existing helper
    formatted = format_objects(
        subtechnique_objects,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "subtechniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} subtechnique(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_parent_techniques(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all parent techniques (exclude subtechniques) in a given domain.

    Parent techniques are the main techniques without a dot in their ATT&CK ID,
    e.g., T1566, T1055 (not T1566.001).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated techniques.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of parent techniques>,
          "parent_techniques": [
            {
              "attack_id": "<TXXXX>",
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "tactics": ["<Tactic 1>", "<Tactic 2>", ...]
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        # This call *already* returns techniques without including subtechniques
        techniques = attack_data.get_techniques(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "parent_techniques": [],
            "formatted": "",
            "message": f"Unable to retrieve techniques for domain '{domain}'.",
        }

    parent_objects: List[Any] = []
    structured: List[Dict[str, Any]] = []

    for t in techniques:
        # Extract STIX ID, name, description, kill chain phases
        if isinstance(t, dict):
            stix_id = t.get("id")
            name = t.get("name")
            description = t.get("description") if include_description else None
            phases = t.get("kill_chain_phases", []) or []
        else:
            stix_id = getattr(t, "id", None)
            name = getattr(t, "name", None)
            description = getattr(t, "description", None) if include_description else None
            phases = getattr(t, "kill_chain_phases", []) or []

        if not stix_id:
            continue

        # Resolve ATT&CK ID
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        if not attack_id:
            # If we can't resolve an ATT&CK ID, skip parent-check
            continue

        # Parent techniques: no dot in ATT&CK ID
        if "." in attack_id:
            continue

        parent_objects.append(t)

        # Extract tactics from kill_chain_phases
        tactics: List[str] = []
        for p in phases:
            if isinstance(p, dict):
                phase_name = p.get("phase_name")
            else:
                phase_name = getattr(p, "phase_name", None)

            if phase_name:
                tactics.append(phase_name.replace("-", " ").title())

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "tactics": tactics,
            }
        )

    if not structured:
        return {
            "domain": domain,
            "count": 0,
            "parent_techniques": [],
            "formatted": "",
            "message": (
                f"No parent techniques found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    formatted = format_objects(
        parent_objects,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "parent_techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} parent technique(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_groups(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all APT groups (intrusion sets) in a domain.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated groups.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of groups>,
          "groups": [
            {
              "attack_id": "GXXXX",
              "name": "<group name>",
              "aliases": [...],
              "stix_id": "<intrusion-set--UUID>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<optional human-readable listing>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Fetch groups
    try:
        groups = attack_data.get_groups(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": f"Unable to retrieve groups for domain '{domain}'."
        }

    if not groups:
        return {
            "domain": domain,
            "count": 0,
            "groups": [],
            "formatted": "",
            "message": (
                f"No APT groups found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            )
        }

    structured = []
    groups_for_format = []

    for g in groups:
        groups_for_format.append(g)

        if isinstance(g, dict):
            name = g.get("name")
            stix_id = g.get("id")
            aliases = g.get("aliases", [])
            description = g.get("description") if include_description else None
        else:
            name = getattr(g, "name", None)
            stix_id = getattr(g, "id", None)
            aliases = getattr(g, "aliases", [])
            description = getattr(g, "description", None) if include_description else None

        # External ATT&CK ID (GXXXX)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "description": description,
            }
        )

    # Optional formatted human-readable block
    formatted = format_objects(
        groups_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "groups": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} APT group(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_software(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all software (malware and tools) in a domain.

    This is effectively an alias for the MITRE helper get_software(), but it
    returns structured results suitable for LLMs and clients.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated software.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of software objects>,
          "software": [
            {
              "attack_id": "<SXXXX or similar> | null",
              "name": "<software name>",
              "aliases": [...],
              "stix_id": "<malware--UUID or tool--UUID>",
              "type": "<malware|tool|...>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<optional human-readable listing>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Fetch software objects from the MITRE library
    try:
        software_items = attack_data.get_software(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": f"Unable to retrieve software for domain '{domain}'.",
        }

    if not software_items:
        return {
            "domain": domain,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    software_for_format: List[Any] = []

    for sw in software_items:
        software_for_format.append(sw)

        if isinstance(sw, dict):
            name = sw.get("name")
            stix_id = sw.get("id")
            aliases = sw.get("aliases", [])
            sw_type = sw.get("type")
            description = sw.get("description") if include_description else None
        else:
            name = getattr(sw, "name", None)
            stix_id = getattr(sw, "id", None)
            aliases = getattr(sw, "aliases", [])
            sw_type = getattr(sw, "type", None)
            description = getattr(sw, "description", None) if include_description else None

        # External ATT&CK ID (often SXXXX)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "aliases": aliases,
                "stix_id": stix_id,
                "type": sw_type,
                "description": description,
            }
        )

    # Optional human-readable formatted view
    formatted = format_objects(
        software_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "software": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} software object(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_mitigations(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all mitigations (defensive countermeasures) in a domain.

    Mitigations are security controls or practices that can reduce the
    effectiveness of adversary techniques (e.g., M1013, M1017).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated mitigations.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of mitigations>,
          "mitigations": [
            {
              "attack_id": "MXXXX" | null,
              "name": "<mitigation name>",
              "stix_id": "<course-of-action--UUID>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Fetch mitigations from MITRE library
    try:
        mitigations = attack_data.get_mitigations(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "mitigations": [],
            "formatted": "",
            "message": f"Unable to retrieve mitigations for domain '{domain}'.",
        }

    if not mitigations:
        return {
            "domain": domain,
            "count": 0,
            "mitigations": [],
            "formatted": "",
            "message": (
                f"No mitigations found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    mitigations_for_format: List[Any] = []

    for m in mitigations:
        mitigations_for_format.append(m)

        if isinstance(m, dict):
            name = m.get("name")
            stix_id = m.get("id")
            description = m.get("description") if include_description else None
        else:
            name = getattr(m, "name", None)
            stix_id = getattr(m, "id", None)
            description = getattr(m, "description", None) if include_description else None

        # External ATT&CK ID (MXXXX)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
            }
        )

    # Optional human-readable formatting
    formatted = format_objects(
        mitigations_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "mitigations": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} mitigation(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_tactics(
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK tactics for a domain.

    Tactics represent the adversary's tactical goals (e.g., Initial Access,
    Defense Evasion, Persistence).

    Args:
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics')
        include_description: Whether to include tactic descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number>,
          "tactics": [
             {
               "attack_id": "<TAxxxx>" | null,
               "name": "...",
               "stix_id": "x-mitre-tactic--UUID",
               "description": "...",
             }
          ],
          "formatted": "<optional human-readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Retrieve tactic objects
    try:
        tactics = attack_data.get_tactics(remove_revoked_deprecated=True)
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "tactics": [],
            "formatted": "",
            "message": f"Unable to retrieve tactics for domain '{domain}'.",
        }

    if not tactics:
        return {
            "domain": domain,
            "count": 0,
            "tactics": [],
            "formatted": "",
            "message": f"No tactics found in domain '{domain}'.",
        }

    structured = []
    tactics_for_format = []

    for t in tactics:
        tactics_for_format.append(t)

        name = getattr(t, "name", None)
        stix_id = getattr(t, "id", None)
        description = getattr(t, "description", None) if include_description else None

        # ATT&CK external ID (TAxxxx)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
            }
        )

    # Human readable formatting (optional)
    formatted = format_objects(
        tactics_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "tactics": structured,
        "formatted": formatted,
        "message": f"Found {len(structured)} tactic(s) in domain '{domain}'.",
    }


@mcp.tool()
async def get_all_matrices(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK matrices in a domain.

    Matrices are the top-level organizational structures in ATT&CK.
    Each domain typically has one or more matrices
    (e.g., Enterprise ATT&CK matrix).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated matrices.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of matrices>,
          "matrices": [
            {
              "attack_id": "<matrix ID or None>",
              "name": "<matrix name>",
              "stix_id": "<x-mitre-matrix--UUID>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Fetch matrices from MITRE library
    try:
        matrices = attack_data.get_matrices(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "matrices": [],
            "formatted": "",
            "message": f"Unable to retrieve matrices for domain '{domain}'.",
        }

    if not matrices:
        return {
            "domain": domain,
            "count": 0,
            "matrices": [],
            "formatted": "",
            "message": (
                f"No matrices found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    matrices_for_format: List[Any] = []

    for m in matrices:
        matrices_for_format.append(m)

        if isinstance(m, dict):
            name = m.get("name")
            stix_id = m.get("id")
            description = m.get("description") if include_description else None
        else:
            name = getattr(m, "name", None)
            stix_id = getattr(m, "id", None)
            description = getattr(m, "description", None) if include_description else None

        # External ID if available (sometimes matrix IDs exist, sometimes not)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
            }
        )

    # Optional human-readable formatting
    formatted = format_objects(
        matrices_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "matrices": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} matrix/matrices in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_campaigns(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK campaigns in a domain.

    Campaigns represent specific intrusion events or long-running operations 
    attributed to threat actors (e.g., SolarWinds, Operation Ghost).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics")
        remove_revoked_deprecated: Whether to exclude revoked/deprecated entries
        include_description: Include campaign descriptions in the output

    Returns:
        {
          "domain": "<domain>",
          "count": <int>,
          "campaigns": [
             {
                "attack_id": "<Cxxxx or None>",
                "name": "<campaign name>",
                "stix_id": "campaign--UUID",
                "description": "<text or null>"
             },
             ...
          ],
          "formatted": "<nicely formatted output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Fetch from MITRE data
    try:
        campaigns = attack_data.get_campaigns(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": f"Unable to retrieve campaigns for domain '{domain}'.",
        }

    if not campaigns:
        return {
            "domain": domain,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": (
                f"No campaigns found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    campaigns_for_format: List[Any] = []

    for c in campaigns:
        campaigns_for_format.append(c)

        # Extract fields safely
        if isinstance(c, dict):
            name = c.get("name")
            stix_id = c.get("id")
            description = c.get("description") if include_description else None
        else:
            name = getattr(c, "name", None)
            stix_id = getattr(c, "id", None)
            description = getattr(c, "description", None) if include_description else None

        # Lookup ATT&CK ID (sometimes campaigns do have Cxxxx IDs)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": description,
            }
        )

    # Human-readable formatted block
    formatted = format_objects(
        campaigns_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "campaigns": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} campaign(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_datasources(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK data sources in a domain.

    Data sources represent *what* kind of telemetry you collect
    (e.g., Process Monitoring, Network Traffic, File Monitoring).

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated data sources.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of data sources>,
          "datasources": [
            {
              "name": "<data source name>",
              "stix_id": "<x-mitre-data-source--UUID>",
              "description": "<text or null>",
              "platforms": ["<Windows>", "<Linux>", ...]  # if available
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Fetch data sources from MITRE library
    try:
        datasources = attack_data.get_datasources(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "datasources": [],
            "formatted": "",
            "message": f"Unable to retrieve data sources for domain '{domain}'.",
        }

    if not datasources:
        return {
            "domain": domain,
            "count": 0,
            "datasources": [],
            "formatted": "",
            "message": (
                f"No data sources found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    ds_for_format: List[Any] = []

    for ds in datasources:
        ds_for_format.append(ds)

        if isinstance(ds, dict):
            name = ds.get("name")
            stix_id = ds.get("id")
            description = ds.get("description") if include_description else None
            platforms = ds.get("x_mitre_platforms") or ds.get("x-mitre-platforms") or []
        else:
            name = getattr(ds, "name", None)
            stix_id = getattr(ds, "id", None)
            description = getattr(ds, "description", None) if include_description else None
            platforms = getattr(ds, "x_mitre_platforms", []) or []

        structured.append(
            {
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "platforms": platforms,
            }
        )

    # Optional human-readable formatting
    formatted = format_objects(
        ds_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "datasources": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} data source(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_all_datacomponents(
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK data components in a domain.

    Data components are specific aspects of a data source that can be monitored.
    For example, the "Process" data source has components like
    "Process Creation", "Process Termination", etc.

    Args:
        domain: ATT&CK domain ("enterprise", "mobile", "ics").
        remove_revoked_deprecated: Whether to exclude revoked/deprecated entries.
        include_description: Whether to include descriptions.

    Returns:
        {
          "domain": "<domain>",
          "count": <number of data components>,
          "datacomponents": [
            {
              "name": "<data component name>",
              "stix_id": "<x-mitre-data-component--UUID>",
              "description": "<text or null>",
              "data_source_stix_id": "<x-mitre-data-source--UUID or null>",
              "data_source_name": "<parent data source name or null>",
              "data_source_attack_id": "<data source ATT&CK ID or null>"
            },
            ...
          ],
          "formatted": "<optional human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Fetch data components
    try:
        datacomponents = attack_data.get_datacomponents(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "datacomponents": [],
            "formatted": "",
            "message": f"Unable to retrieve data components for domain '{domain}'.",
        }

    if not datacomponents:
        return {
            "domain": domain,
            "count": 0,
            "datacomponents": [],
            "formatted": "",
            "message": (
                f"No data components found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    dc_for_format: List[Any] = []

    for dc in datacomponents:
        dc_for_format.append(dc)

        if isinstance(dc, dict):
            name = dc.get("name")
            stix_id = dc.get("id")
            description = dc.get("description") if include_description else None
            ds_ref = dc.get("x_mitre_data_source_ref") or dc.get("x-mitre-data-source-ref")
        else:
            name = getattr(dc, "name", None)
            stix_id = getattr(dc, "id", None)
            description = getattr(dc, "description", None) if include_description else None
            ds_ref = getattr(dc, "x_mitre_data_source_ref", None)

        # Resolve parent data source (if present)
        data_source_name = None
        data_source_attack_id = None
        data_source_stix_id = ds_ref

        if ds_ref:
            try:
                ds_obj = attack_data.get_object_by_stix_id(ds_ref)
            except Exception:
                ds_obj = None

            if ds_obj is not None:
                if isinstance(ds_obj, dict):
                    data_source_name = ds_obj.get("name")
                    ds_id_for_attack = ds_obj.get("id")
                else:
                    data_source_name = getattr(ds_obj, "name", None)
                    ds_id_for_attack = getattr(ds_obj, "id", None)

                try:
                    data_source_attack_id = attack_data.get_attack_id(ds_id_for_attack)
                except Exception:
                    data_source_attack_id = None

        structured.append(
            {
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "data_source_stix_id": data_source_stix_id,
                "data_source_name": data_source_name,
                "data_source_attack_id": data_source_attack_id,
            }
        )

    # Optional human-readable formatting
    formatted = format_objects(
        dc_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "datacomponents": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} data component(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }


# ---------------------------------------------------------------------------
# Technique → ICS Assets targeted (ICS domain only)
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_all_assets(
    domain: str = "ics",
    remove_revoked_deprecated: bool = True,
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK assets in a domain (primarily ICS).

    Assets represent industrial control system components 
    (PLC, HMI, Engineering Workstation, Control Server, etc.)

    Args:
        domain: ATT&CK domain ("ics" recommended)
        remove_revoked_deprecated: Exclude revoked/deprecated entries
        include_description: Include asset descriptions

    Returns:
        {
          "domain": "<domain>",
          "count": <number>,
          "assets": [
            {
              "name": "...",
              "stix_id": "x-mitre-asset--UUID",
              "description": "...",
              "attack_id": "<Axxxx or None>"
            }
          ],
          "formatted": "<human-readable output>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Retrieve assets
    try:
        assets = attack_data.get_assets(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
    except Exception:
        return {
            "domain": domain,
            "count": 0,
            "assets": [],
            "formatted": "",
            "message": f"Unable to retrieve assets for domain '{domain}'.",
        }

    if not assets:
        return {
            "domain": domain,
            "count": 0,
            "assets": [],
            "formatted": "",
            "message": (
                f"No assets found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    structured: List[Dict[str, Any]] = []
    assets_for_format: List[Any] = []

    for asset in assets:
        assets_for_format.append(asset)

        # Extract metadata
        if isinstance(asset, dict):
            name = asset.get("name")
            stix_id = asset.get("id")
            description = asset.get("description") if include_description else None
        else:
            name = getattr(asset, "name", None)
            stix_id = getattr(asset, "id", None)
            description = getattr(asset, "description", None) if include_description else None

        # ATT&CK ID lookup (ICS assets sometimes have Ax000 identifiers)
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        structured.append(
            {
                "name": name,
                "stix_id": stix_id,
                "description": description,
                "attack_id": attack_id,
            }
        )

    # Human-readable formatting (not required for apps, useful for ChatGPT)
    formatted = format_objects(
        assets_for_format,
        include_description=include_description,
        domain=domain,
    )

    return {
        "domain": domain,
        "count": len(structured),
        "assets": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} asset(s) in domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_assets_targeted_by_technique(
    technique_stix_id: str,
    domain: str = "ics",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ICS assets targeted by a specific technique.

    Assets represent industrial control system components such as
    PLCs, RTUs, Engineering Workstations, HMIs, Control Servers, etc.

    Args:
        technique_stix_id: Technique STIX UUID identifier
        domain: ATT&CK domain ('ics' strongly recommended)
        include_description: Include asset descriptions, if available

    Returns:
        {
          "technique": {
              "attack_id": "Txxxx",
              "name": "...",
              "stix_id": "<attack-pattern--UUID>"
          },
          "count": int,
          "assets": [
            {
              "name": "...",
              "stix_id": "<x-mitre-asset--UUID>",
              "description": "<optional text>",
              "asset_type": "<ICS component type>",
            },
            ...
          ],
          "formatted": "<multi-line readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # --- Resolve technique metadata ---
    try:
        tech_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        tech_obj = None

    if tech_obj is not None:
        t_name = getattr(tech_obj, "name", None)
        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None
    else:
        t_name = None
        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None

    technique_info = {
        "attack_id": t_attack_id,
        "name": t_name,
        "stix_id": technique_stix_id,
    }

    # --- Fetch assets targeted by this technique ---
    try:
        assets = attack_data.get_assets_targeted_by_technique(
            technique_stix_id
        ) or []
    except Exception:
        assets = []

    if not assets:
        return {
            "technique": technique_info,
            "count": 0,
            "assets": [],
            "formatted": "",
            "message": (
                f"No ICS assets found that are targeted by technique '{t_attack_id}' "
                f"in domain '{domain}'."
            ),
        }

    # --- Build the structured list of assets ---
    asset_entries = []
    for a in assets:
        if isinstance(a, dict):
            name = a.get("name")
            stix_id = a.get("id")
            desc = a.get("description") if include_description else None
            asset_type = a.get("x_mitre_asset_type")
        else:
            name = getattr(a, "name", None)
            stix_id = getattr(a, "id", None)
            desc = getattr(a, "description", None) if include_description else None
            asset_type = getattr(a, "x_mitre_asset_type", None)

        asset_entries.append(
            {
                "name": name,
                "stix_id": stix_id,
                "description": desc,
                "asset_type": asset_type,
            }
        )

    # --- Human-readable formatting ---
    formatted = format_objects(
        assets,
        include_description=include_description,
        domain=domain,
    )

    return {
        "technique": technique_info,
        "count": len(asset_entries),
        "assets": asset_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(asset_entries)} ICS asset(s) targeted by technique "
            f"'{t_attack_id}' ({t_name}) in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_techniques_targeting_asset(
    asset_stix_id: str,
    domain: str = "ics",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques that target a specific ICS asset.

    Shows which adversary techniques can affect a given industrial
    control system component.

    Args:
        asset_stix_id: STIX ID of the ICS asset
        domain: Domain (default: 'ics')
        include_description: Whether to include descriptions in formatted output

    Returns:
        {
            "found": bool,
            "count": int,
            "techniques": [
                {
                    "id": "<ATT&CK ID>",
                    "name": "...",
                    "stix_id": "...",
                    "description": "..." | None
                },
                ...
            ],
            "formatted": "<optional pretty text>",
            "message": "..."
        }
    """
    attack_data = get_attack_data(domain)

    try:
        techniques = attack_data.get_techniques_targeting_asset(asset_stix_id) or []
    except Exception as e:
        return {
            "found": False,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"Error retrieving techniques: {e}",
        }

    if not techniques:
        return {
            "found": False,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"No techniques found targeting asset '{asset_stix_id}' in domain '{domain}'.",
        }

    # Build machine-readable list
    out = []
    for tech in techniques:
        attack_id = attack_data.get_attack_id(tech.id)
        out.append(
            {
                "id": attack_id,
                "name": getattr(tech, "name", None),
                "stix_id": tech.id,
                "description": getattr(tech, "description", None) if include_description else None,
            }
        )

    # Human-readable formatted block
    formatted = format_objects(techniques, include_description=include_description, domain=domain)

    return {
        "found": True,
        "count": len(out),
        "techniques": out,
        "formatted": formatted,
        "message": f"Found {len(out)} techniques targeting asset '{asset_stix_id}'.",
    }

 #####################################################################
    # Campaign functions
#####################################################################

@mcp.tool()
async def get_campaigns_using_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all campaigns that use a specific technique.

    This is a reverse lookup: Technique → Campaigns.

    Args:
        technique_stix_id: Technique STIX UUID identifier
                           (e.g., 'attack-pattern--UUID').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include campaign descriptions.

    Returns:
        {
          "technique": {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of campaigns>,

          "campaigns": [
            {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name>",
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "<type>",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of campaigns>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Optional: resolve technique metadata for context
    try:
        tech_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        tech_obj = None

    technique_info: Optional[Dict[str, Any]] = None
    if tech_obj is not None:
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None

        technique_info = {
            "attack_id": t_attack_id,
            "name": t_name,
            "stix_id": technique_stix_id,
            "description": t_desc,
        }

    # Call MITRE library helper: campaigns using this technique
    try:
        rel_entries = attack_data.get_campaigns_using_technique(technique_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "technique": technique_info,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": (
                f"No campaigns found using technique STIX ID "
                f"'{technique_stix_id}' in domain '{domain}'."
            ),
        }

    campaigns_structured: List[Dict[str, Any]] = []
    campaign_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # Many mitreattack helpers return RelationshipEntry-like dicts:
        # { "object": <campaign>, "relationships": [<relationship>, ...] }
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            camp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            camp_obj = entry
            rels = []

        if camp_obj is None:
            continue

        campaign_objects_for_format.append(camp_obj)

        # Extract campaign fields
        if isinstance(camp_obj, dict):
            c_name = camp_obj.get("name")
            c_stix_id = camp_obj.get("id")
            c_desc = camp_obj.get("description") if include_description else None
        else:
            c_name = getattr(camp_obj, "name", None)
            c_stix_id = getattr(camp_obj, "id", None)
            c_desc = getattr(camp_obj, "description", None) if include_description else None

        # External ATT&CK campaign ID (CXXXX)
        try:
            c_attack_id = attack_data.get_attack_id(c_stix_id)
        except Exception:
            c_attack_id = None

        # Relationship metadata (if available)
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        campaigns_structured.append(
            {
                "attack_id": c_attack_id,
                "name": c_name,
                "stix_id": c_stix_id,
                "description": c_desc,
                "relationships": relationships_info,
            }
        )

    # Optional human-readable formatted output
    formatted = ""
    if campaign_objects_for_format:
        formatted = format_objects(
            campaign_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "technique": technique_info,
        "count": len(campaigns_structured),
        "campaigns": campaigns_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(campaigns_structured)} campaign(s) using technique "
            f"STIX ID '{technique_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_techniques_used_by_campaign(
    campaign_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques used in a specific campaign.

    Args:
        campaign_stix_id: Campaign STIX UUID identifier
                          (e.g., 'campaign--UUID').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "campaign": {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name or null>",
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of techniques>,

          "techniques": [
            {
              "attack_id": "TXXXX or TXXXX.YYY" | null,
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
              "tactics": ["<Tactic 1>", "<Tactic 2>", ...],
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "<type>",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of techniques>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Optional: resolve campaign metadata
    try:
        camp_obj = attack_data.get_object_by_stix_id(campaign_stix_id)
    except Exception:
        camp_obj = None

    campaign_info: Optional[Dict[str, Any]] = None
    if camp_obj is not None:
        if isinstance(camp_obj, dict):
            c_name = camp_obj.get("name")
            c_desc = camp_obj.get("description") if include_description else None
        else:
            c_name = getattr(camp_obj, "name", None)
            c_desc = getattr(camp_obj, "description", None) if include_description else None

        try:
            c_attack_id = attack_data.get_attack_id(campaign_stix_id)
        except Exception:
            c_attack_id = None

        campaign_info = {
            "attack_id": c_attack_id,
            "name": c_name,
            "stix_id": campaign_stix_id,
            "description": c_desc,
        }

    # Call MITRE helper: techniques used by this campaign
    try:
        rel_entries = attack_data.get_techniques_used_by_campaign(campaign_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "campaign": campaign_info,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found for campaign STIX ID "
                f"'{campaign_stix_id}' in domain '{domain}'."
            ),
        }

    techniques_structured: List[Dict[str, Any]] = []
    technique_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # RelationshipEntry-style: {"object": <technique>, "relationships": [...]}
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            tech_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            tech_obj = entry
            rels = []

        if tech_obj is None:
            continue

        technique_objects_for_format.append(tech_obj)

        # Extract technique fields
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_stix_id = tech_obj.get("id")
            t_desc = tech_obj.get("description") if include_description else None
            phases = tech_obj.get("kill_chain_phases", []) or []
        else:
            t_name = getattr(tech_obj, "name", None)
            t_stix_id = getattr(tech_obj, "id", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None
            phases = getattr(tech_obj, "kill_chain_phases", []) or []

        # ATT&CK technique ID
        try:
            t_attack_id = attack_data.get_attack_id(t_stix_id)
        except Exception:
            t_attack_id = None

        # Tactics from kill_chain_phases
        tactics: List[str] = []
        for p in phases:
            if isinstance(p, dict):
                phase_name = p.get("phase_name")
            else:
                phase_name = getattr(p, "phase_name", None)
            if phase_name:
                tactics.append(phase_name.replace("-", " ").title())

        # Relationship metadata
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        techniques_structured.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix_id,
                "description": t_desc,
                "tactics": tactics,
                "relationships": relationships_info,
            }
        )

    # Optional human-readable formatted block
    formatted = ""
    if technique_objects_for_format:
        formatted = format_objects(
            technique_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "campaign": campaign_info,
        "count": len(techniques_structured),
        "techniques": techniques_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(techniques_structured)} technique(s) used by campaign "
            f"STIX ID '{campaign_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_campaigns_using_software(
    software_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all campaigns that use specific software/malware.

    This is a reverse lookup: Software → Campaigns.

    Args:
        software_stix_id: Software STIX UUID identifier (e.g., 'malware--UUID', 'tool--UUID').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include campaign descriptions.

    Returns:
        {
          "software": {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name or null>",
              "stix_id": "<software STIX ID>",
              "type": "<malware|tool|...> or null",
              "description": "<text or null>",
          } | null,

          "count": <number of campaigns>,

          "campaigns": [
            {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name>",
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "<type>",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of campaigns>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Optional: resolve software metadata for context
    try:
        sw_obj = attack_data.get_object_by_stix_id(software_stix_id)
    except Exception:
        sw_obj = None

    software_info = None
    if sw_obj is not None:
        if isinstance(sw_obj, dict):
            s_name = sw_obj.get("name")
            s_type = sw_obj.get("type")
            s_desc = sw_obj.get("description") if include_description else None
        else:
            s_name = getattr(sw_obj, "name", None)
            s_type = getattr(sw_obj, "type", None)
            s_desc = getattr(sw_obj, "description", None) if include_description else None

        try:
            s_attack_id = attack_data.get_attack_id(software_stix_id)
        except Exception:
            s_attack_id = None

        software_info = {
            "attack_id": s_attack_id,
            "name": s_name,
            "stix_id": software_stix_id,
            "type": s_type,
            "description": s_desc,
        }

    # Call MITRE helper: campaigns using this software
    try:
        rel_entries = attack_data.get_campaigns_using_software(software_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "software": software_info,
            "count": 0,
            "campaigns": [],
            "formatted": "",
            "message": (
                f"No campaigns found using software STIX ID "
                f"'{software_stix_id}' in domain '{domain}'."
            ),
        }

    campaigns_structured: List[Dict[str, Any]] = []
    campaign_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # RelationshipEntry-style: {"object": <campaign>, "relationships": [...]}
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            camp_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            camp_obj = entry
            rels = []

        if camp_obj is None:
            continue

        campaign_objects_for_format.append(camp_obj)

        # Extract campaign fields
        if isinstance(camp_obj, dict):
            c_name = camp_obj.get("name")
            c_stix_id = camp_obj.get("id")
            c_desc = camp_obj.get("description") if include_description else None
        else:
            c_name = getattr(camp_obj, "name", None)
            c_stix_id = getattr(camp_obj, "id", None)
            c_desc = getattr(camp_obj, "description", None) if include_description else None

        # External ATT&CK campaign ID (CXXXX)
        try:
            c_attack_id = attack_data.get_attack_id(c_stix_id)
        except Exception:
            c_attack_id = None

        # Relationship metadata
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        campaigns_structured.append(
            {
                "attack_id": c_attack_id,
                "name": c_name,
                "stix_id": c_stix_id,
                "description": c_desc,
                "relationships": relationships_info,
            }
        )

    # Optional human-readable formatted output
    formatted = ""
    if campaign_objects_for_format:
        formatted = format_objects(
            campaign_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "software": software_info,
        "count": len(campaigns_structured),
        "campaigns": campaigns_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(campaigns_structured)} campaign(s) using software "
            f"STIX ID '{software_stix_id}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_software_used_by_campaign(
    campaign_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all software/malware used in a specific campaign.

    Args:
        campaign_stix_id: Campaign STIX UUID identifier (e.g., 'campaign--UUID').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include software descriptions.

    Returns:
        {
          "campaign": {
              "attack_id": "CXXXX" | null,
              "name": "<campaign name or null>",
              "stix_id": "<campaign--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of software objects>,

          "software": [
            {
              "attack_id": "SXXXX or similar" | null,
              "name": "<software name>",
              "stix_id": "<malware--UUID or tool--UUID>",
              "type": "<malware|tool|...> or null",
              "aliases": ["...", "..."],
              "description": "<text or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "<type>",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ]
            },
            ...
          ],

          "formatted": "<human-readable list of software>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Resolve campaign metadata for context
    try:
        camp_obj = attack_data.get_object_by_stix_id(campaign_stix_id)
    except Exception:
        camp_obj = None

    campaign_info = None
    if camp_obj is not None:
        if isinstance(camp_obj, dict):
            c_name = camp_obj.get("name")
            c_desc = camp_obj.get("description") if include_description else None
        else:
            c_name = getattr(camp_obj, "name", None)
            c_desc = getattr(camp_obj, "description", None) if include_description else None

        try:
            c_attack_id = attack_data.get_attack_id(campaign_stix_id)
        except Exception:
            c_attack_id = None

        campaign_info = {
            "attack_id": c_attack_id,
            "name": c_name,
            "stix_id": campaign_stix_id,
            "description": c_desc,
        }

    # Call MITRE helper: software used by this campaign
    try:
        rel_entries = attack_data.get_software_used_by_campaign(campaign_stix_id)
    except Exception:
        rel_entries = []

    if not rel_entries:
        return {
            "campaign": campaign_info,
            "count": 0,
            "software": [],
            "formatted": "",
            "message": (
                f"No software found for campaign STIX ID "
                f"'{campaign_stix_id}' in domain '{domain}'."
            ),
        }

    software_structured: List[Dict[str, Any]] = []
    software_objects_for_format: List[Any] = []

    for entry in rel_entries:
        # Expected: {"object": <software>, "relationships": [...]}
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            sw_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            sw_obj = entry
            rels = []

        if sw_obj is None:
            continue

        software_objects_for_format.append(sw_obj)

        # Extract software fields
        if isinstance(sw_obj, dict):
            s_name = sw_obj.get("name")
            s_stix_id = sw_obj.get("id")
            s_type = sw_obj.get("type")
            s_aliases = sw_obj.get("aliases", [])
            s_desc = sw_obj.get("description") if include_description else None
        else:
            s_name = getattr(sw_obj, "name", None)
            s_stix_id = getattr(sw_obj, "id", None)
            s_type = getattr(sw_obj, "type", None)
            s_aliases = getattr(sw_obj, "aliases", [])
            s_desc = getattr(sw_obj, "description", None) if include_description else None

        # External ATT&CK software ID (often SXXXX)
        try:
            s_attack_id = attack_data.get_attack_id(s_stix_id)
        except Exception:
            s_attack_id = None

        # Relationship metadata
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        software_structured.append(
            {
                "attack_id": s_attack_id,
                "name": s_name,
                "stix_id": s_stix_id,
                "type": s_type,
                "aliases": s_aliases,
                "description": s_desc,
                "relationships": relationships_info,
            }
        )

    # Optional human-readable formatted output
    formatted = ""
    if software_objects_for_format:
        formatted = format_objects(
            software_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "campaign": campaign_info,
        "count": len(software_structured),
        "software": software_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(software_structured)} software object(s) used by campaign "
            f"STIX ID '{campaign_stix_id}' in domain '{domain}'."
        ),
    }

#####################################################################
    # Technique functions
#####################################################################

@mcp.tool()
async def get_techniques_by_platform(
    platform: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK techniques that apply to a specific platform.

    Args:
        platform: Platform name (e.g., 'Windows', 'Linux', 'macOS', 
                  'Cloud', 'Azure AD', 'Network', etc.)
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "platform": "<platform>",
          "count": <number>,
          "techniques": [
            {
              "attack_id": "Txxxx" or "Txxxx.xxx" or null,
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>"
            },
            ...
          ],
          "formatted": "<optional formatted string>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        techniques = attack_data.get_techniques_by_platform(platform)
    except Exception:
        techniques = []

    if not techniques:
        return {
            "platform": platform,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found for platform '{platform}' "
                f"in domain '{domain}'."
            ),
        }

    structured = []
    for tech in techniques:
        if isinstance(tech, dict):
            t_name = tech.get("name")
            t_stix = tech.get("id")
            t_desc = tech.get("description") if include_description else None
        else:
            t_name = getattr(tech, "name", None)
            t_stix = getattr(tech, "id", None)
            t_desc = getattr(tech, "description", None) if include_description else None

        # external ATT&CK ID (Txxxx)
        try:
            t_attack = attack_data.get_attack_id(t_stix)
        except Exception:
            t_attack = None

        structured.append(
            {
                "attack_id": t_attack,
                "name": t_name,
                "stix_id": t_stix,
                "description": t_desc,
            }
        )

    # optional human-readable formatting
    formatted = format_objects(
        techniques,
        include_description=include_description,
        domain=domain,
    )

    return {
        "platform": platform,
        "count": len(structured),
        "techniques": structured,
        "formatted": formatted,
        "message": (
            f"Found {len(structured)} technique(s) applicable to platform "
            f"'{platform}' in domain '{domain}'."
        ),
    }

@mcp.tool()
async def get_parent_technique_of_subtechnique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get the parent technique of a subtechnique.

    Args:
        technique_stix_id: STIX UUID of the subtechnique.
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include the parent's description.

    Returns:
        {
          "subtechnique_stix_id": "...",
          "subtechnique_attack_id": "Txxxx.xxx" or null,
          "parent": {
              "attack_id": "Txxxx",
              "name": "...",
              "stix_id": "attack-pattern--UUID",
              "description": "..." | null
          } or null,
          "formatted": "<human readable description>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # First: resolve ATT&CK ID of the subtechnique
    try:
        sub_attack_id = attack_data.get_attack_id(technique_stix_id)
    except Exception:
        sub_attack_id = None

    # Try retrieving the parent STIX ID
    try:
        parent_stix_id = attack_data.get_parent_technique_of_subtechnique(technique_stix_id)
    except Exception:
        parent_stix_id = None

    if not parent_stix_id:
        return {
            "subtechnique_stix_id": technique_stix_id,
            "subtechnique_attack_id": sub_attack_id,
            "parent": None,
            "formatted": "",
            "message": (
                f"No parent technique found — '{technique_stix_id}' "
                f"is not a subtechnique in domain '{domain}'."
            ),
        }

    # Load the parent technique object
    parent_obj = attack_data.get_object_by_stix_id(parent_stix_id)
    if parent_obj is None:
        return {
            "subtechnique_stix_id": technique_stix_id,
            "subtechnique_attack_id": sub_attack_id,
            "parent": None,
            "formatted": "",
            "message": (
                f"Parent STIX ID '{parent_stix_id}' not found in domain '{domain}'."
            ),
        }

    # Extract parent attributes
    parent_name = getattr(parent_obj, "name", None)
    parent_desc = getattr(parent_obj, "description", None) if include_description else None

    try:
        parent_attack_id = attack_data.get_attack_id(parent_stix_id)
    except Exception:
        parent_attack_id = None

    # Human-readable formatting
    formatted = format_objects(
        [parent_obj],
        include_description=include_description,
        domain=domain,
    )

    return {
        "subtechnique_stix_id": technique_stix_id,
        "subtechnique_attack_id": sub_attack_id,
        "parent": {
            "attack_id": parent_attack_id,
            "name": parent_name,
            "stix_id": parent_stix_id,
            "description": parent_desc,
        },
        "formatted": formatted,
        "message": (
            f"Parent technique for subtechnique '{sub_attack_id}' is "
            f"'{parent_attack_id}' ({parent_name})."
        ),
    }

@mcp.tool()
async def get_subtechniques_of_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all subtechniques of a parent technique.

    Args:
        technique_stix_id: STIX UUID of the parent technique.
        domain: ATT&CK domain.
        include_description: Whether to include subtechnique descriptions.

    Returns:
        {
          "parent": {
              "stix_id": "...",
              "attack_id": "...",
              "name": "..."
          },
          "count": int,
          "subtechniques": [
              {
                  "attack_id": "...",
                  "name": "...",
                  "stix_id": "...",
                  "description": "..." | null
              },
              ...
          ],
          "formatted": "<multi-line string>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # Resolve parent attributes
    try:
        parent_attack_id = attack_data.get_attack_id(technique_stix_id)
    except Exception:
        parent_attack_id = None

    parent_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    parent_name = getattr(parent_obj, "name", None) if parent_obj else None

    # Retrieve subtechniques
    try:
        subs = attack_data.get_subtechniques_of_technique(technique_stix_id) or []
    except Exception:
        subs = []

    if not subs:
        return {
            "parent": {
                "stix_id": technique_stix_id,
                "attack_id": parent_attack_id,
                "name": parent_name,
            },
            "count": 0,
            "subtechniques": [],
            "formatted": "",
            "message": (
                f"No subtechniques found for technique "
                f"'{parent_attack_id}' in domain '{domain}'."
            ),
        }

    # Convert subtechniques to structured form
    sub_list = []
    for obj in subs:
        stix_id = obj.id
        name = getattr(obj, "name", None)
        attack_id = attack_data.get_attack_id(stix_id)
        desc = getattr(obj, "description", None) if include_description else None

        sub_list.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": desc,
            }
        )

    # Human-readable formatting
    formatted = format_objects(
        subs,
        include_description=include_description,
        domain=domain,
    )

    return {
        "parent": {
            "stix_id": technique_stix_id,
            "attack_id": parent_attack_id,
            "name": parent_name,
        },
        "count": len(sub_list),
        "subtechniques": sub_list,
        "formatted": formatted,
        "message": (
            f"Found {len(sub_list)} subtechniques for "
            f"'{parent_attack_id}' ({parent_name})."
        ),
    }

# ---------------------------------------------------------------------------
# Mitigation → Technique mapping
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_techniques_mitigated_by_mitigation(
    mitigation_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all techniques mitigated by a specific mitigation (by STIX ID).

    Args:
        mitigation_stix_id: STIX UUID of the mitigation (e.g., course-of-action--UUID).
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Include technique descriptions in the output.

    Returns:
        {
          "found": bool,
          "mitigation": {
              "attack_id": "...",
              "name": "...",
              "stix_id": "course-of-action--..."
          } | null,
          "count": int,
          "techniques": [
              {
                  "attack_id": "Txxxx",
                  "name": "...",
                  "stix_id": "...",
                  "description": "...",
              },
              ...
          ],
          "formatted": "<multi-line text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # --- Resolve the mitigation object ---
    mitigation_obj = attack_data.get_object_by_stix_id(mitigation_stix_id)
    if mitigation_obj is None:
        return {
            "found": False,
            "mitigation": None,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"Mitigation STIX ID '{mitigation_stix_id}' not found in "
                f"domain '{domain}'."
            ),
        }

    mitigation_name = getattr(mitigation_obj, "name", None)
    try:
        mitigation_attack_id = attack_data.get_attack_id(mitigation_stix_id)
    except Exception:
        mitigation_attack_id = None

    # --- Fetch techniques mitigated by this mitigation ---
    try:
        techniques = attack_data.get_techniques_mitigated_by_mitigation(
            mitigation_stix_id
        ) or []
    except Exception:
        techniques = []

    if not techniques:
        return {
            "found": True,
            "mitigation": {
                "attack_id": mitigation_attack_id,
                "name": mitigation_name,
                "stix_id": mitigation_stix_id,
            },
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques are mitigated by '{mitigation_attack_id}' "
                f"({mitigation_name}) in domain '{domain}'."
            ),
        }

    # --- Build list of technique entries ---
    technique_entries = []
    for t in techniques:
        stix_id = getattr(t, "id", None)
        name = getattr(t, "name", None)
        desc = getattr(t, "description", None) if include_description else None

        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        technique_entries.append(
            {
                "attack_id": attack_id,
                "name": name,
                "stix_id": stix_id,
                "description": desc,
            }
        )

    formatted = format_objects(
        techniques,
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "mitigation": {
            "attack_id": mitigation_attack_id,
            "name": mitigation_name,
            "stix_id": mitigation_stix_id,
        },
        "count": len(technique_entries),
        "techniques": technique_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(technique_entries)} techniques mitigated by "
            f"'{mitigation_attack_id}' ({mitigation_name})."
        ),
    }

@mcp.tool()
async def get_mitigations_mitigating_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all mitigations that address a specific technique.

    Shows which defensive controls reduce the effectiveness
    of this technique.

    Args:
        technique_stix_id: Technique STIX UUID identifier
                           (e.g., 'attack-pattern--UUID').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Include mitigation descriptions.

    Returns:
        {
          "found": bool,
          "technique": {
              "attack_id": "Txxxx or Txxxx.xxx" | null,
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--UUID>"
          } | null,
          "count": int,
          "mitigations": [
              {
                  "attack_id": "Mxxxx" | null,
                  "name": "<mitigation name>",
                  "stix_id": "<course-of-action--UUID>",
                  "description": "<text or null>",
              },
              ...
          ],
          "formatted": "<multi-line summary>",
          "message": "<status message>"
        }
    """
    attack_data = get_attack_data(domain)

    # Resolve technique context
    try:
        technique_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        technique_obj = None

    technique_info = None
    if technique_obj is not None:
        if isinstance(technique_obj, dict):
            t_name = technique_obj.get("name")
        else:
            t_name = getattr(technique_obj, "name", None)

        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None

        technique_info = {
            "attack_id": t_attack_id,
            "name": t_name,
            "stix_id": technique_stix_id,
        }
    else:
        t_name = None
        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None
        technique_info = {
            "attack_id": t_attack_id,
            "name": t_name,
            "stix_id": technique_stix_id,
        }

    # Fetch mitigations from MITRE helper
    try:
        mitigations = attack_data.get_mitigations_mitigating_technique(
            technique_stix_id
        ) or []
    except Exception:
        mitigations = []

    if not mitigations:
        return {
            "found": False,
            "technique": technique_info,
            "count": 0,
            "mitigations": [],
            "formatted": "",
            "message": (
                f"No mitigations found for technique STIX ID "
                f"'{technique_stix_id}' in domain '{domain}'."
            ),
        }

    mitigation_entries: List[Dict[str, Any]] = []
    for m in mitigations:
        if isinstance(m, dict):
            m_name = m.get("name")
            m_stix = m.get("id")
            m_desc = m.get("description") if include_description else None
        else:
            m_name = getattr(m, "name", None)
            m_stix = getattr(m, "id", None)
            m_desc = getattr(m, "description", None) if include_description else None

        try:
            m_attack_id = attack_data.get_attack_id(m_stix)
        except Exception:
            m_attack_id = None

        mitigation_entries.append(
            {
                "attack_id": m_attack_id,
                "name": m_name,
                "stix_id": m_stix,
                "description": m_desc,
            }
        )

    formatted = format_objects(
        mitigations,
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "technique": technique_info,
        "count": len(mitigation_entries),
        "mitigations": mitigation_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(mitigation_entries)} mitigation(s) that address "
            f"technique '{technique_info.get('attack_id')}' "
            f"({technique_info.get('name')})."
        ),
    }

# ---------------------------------------------------------------------------
# Technique → Data components (detection)
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_datacomponents_detecting_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all data components that can detect a specific technique.

    Data components are specific aspects of telemetry that can be used
    to detect adversary behavior (e.g., Process Creation, OS API Execution).

    Args:
        technique_stix_id: Technique STIX UUID identifier
                           (e.g., 'attack-pattern--UUID').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include data component descriptions.

    Returns:
        {
          "technique": {
              "attack_id": "Txxxx or Txxxx.xxx" | null,
              "name": "<technique name or null>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
          } | null,

          "count": <number of data components>,

          "datacomponents": [
            {
              "name": "<data component name>",
              "stix_id": "<x-mitre-data-component--UUID>",
              "description": "<text or null>",
              "data_source_stix_id": "<x-mitre-data-source--UUID or null>",
              "data_source_name": "<data source name or null>",
              "data_source_attack_id": "<data source ATT&CK ID or null>",
              "relationships": [
                {
                  "stix_id": "<relationship--UUID>",
                  "relationship_type": "<type>",
                  "description": "<relationship description or null>",
                  "source_ref": "<source STIX ID>",
                  "target_ref": "<target STIX ID>",
                },
                ...
              ],
            },
            ...
          ],

          "formatted": "<human-readable list of data components>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # --- Resolve technique context (optional, but useful for UX) ---
    try:
        tech_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        tech_obj = None

    technique_info: Optional[Dict[str, Any]] = None
    if tech_obj is not None:
        if isinstance(tech_obj, dict):
            t_name = tech_obj.get("name")
            t_desc = tech_obj.get("description") if include_description else None
        else:
            t_name = getattr(tech_obj, "name", None)
            t_desc = getattr(tech_obj, "description", None) if include_description else None

        try:
            t_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            t_attack_id = None

        technique_info = {
            "attack_id": t_attack_id,
            "name": t_name,
            "stix_id": technique_stix_id,
            "description": t_desc,
        }

    # --- Fetch data components from MITRE helper ---
    try:
        entries = attack_data.get_datacomponents_detecting_technique(
            technique_stix_id
        ) or []
    except Exception:
        entries = []

    if not entries:
        return {
            "technique": technique_info,
            "count": 0,
            "datacomponents": [],
            "formatted": "",
            "message": (
                f"No data components found that detect technique STIX ID "
                f"'{technique_stix_id}' in domain '{domain}'."
            ),
        }

    datacomponents_structured: List[Dict[str, Any]] = []
    dc_objects_for_format: List[Any] = []

    for entry in entries:
        # Expected from mitreattack: {"object": <data_component>, "relationships": [...]}
        if isinstance(entry, dict) and ("object" in entry or "relationships" in entry):
            dc_obj = entry.get("object", entry)
            rels = entry.get("relationships", [])
        else:
            dc_obj = entry
            rels = []

        if dc_obj is None:
            continue

        dc_objects_for_format.append(dc_obj)

        # Extract data component fields
        if isinstance(dc_obj, dict):
            name = dc_obj.get("name")
            stix_id = dc_obj.get("id")
            desc = dc_obj.get("description") if include_description else None
            ds_ref = (
                dc_obj.get("x_mitre_data_source_ref")
                or dc_obj.get("x-mitre-data-source-ref")
            )
        else:
            name = getattr(dc_obj, "name", None)
            stix_id = getattr(dc_obj, "id", None)
            desc = getattr(dc_obj, "description", None) if include_description else None
            ds_ref = getattr(dc_obj, "x_mitre_data_source_ref", None)

        # Resolve parent data source (if any)
        data_source_stix_id = ds_ref
        data_source_name = None
        data_source_attack_id = None

        if ds_ref:
            try:
                ds_obj = attack_data.get_object_by_stix_id(ds_ref)
            except Exception:
                ds_obj = None

            if ds_obj is not None:
                if isinstance(ds_obj, dict):
                    ds_name = ds_obj.get("name")
                    ds_internal_id = ds_obj.get("id")
                else:
                    ds_name = getattr(ds_obj, "name", None)
                    ds_internal_id = getattr(ds_obj, "id", None)

                data_source_name = ds_name
                try:
                    data_source_attack_id = attack_data.get_attack_id(ds_internal_id)
                except Exception:
                    data_source_attack_id = None

        # Relationship metadata (data-component↔technique relationships)
        relationships_info = []
        for r in rels:
            if isinstance(r, dict):
                r_id = r.get("id")
                r_type = r.get("relationship_type")
                r_desc = r.get("description")
                r_source = r.get("source_ref")
                r_target = r.get("target_ref")
            else:
                r_id = getattr(r, "id", None)
                r_type = getattr(r, "relationship_type", None)
                r_desc = getattr(r, "description", None)
                r_source = getattr(r, "source_ref", None)
                r_target = getattr(r, "target_ref", None)

            relationships_info.append(
                {
                    "stix_id": r_id,
                    "relationship_type": r_type,
                    "description": r_desc,
                    "source_ref": r_source,
                    "target_ref": r_target,
                }
            )

        datacomponents_structured.append(
            {
                "name": name,
                "stix_id": stix_id,
                "description": desc,
                "data_source_stix_id": data_source_stix_id,
                "data_source_name": data_source_name,
                "data_source_attack_id": data_source_attack_id,
                "relationships": relationships_info,
            }
        )

    # Optional human-readable formatted output
    formatted = ""
    if dc_objects_for_format:
        formatted = format_objects(
            dc_objects_for_format,
            include_description=include_description,
            domain=domain,
        )

    return {
        "technique": technique_info,
        "count": len(datacomponents_structured),
        "datacomponents": datacomponents_structured,
        "formatted": formatted,
        "message": (
            f"Found {len(datacomponents_structured)} data component(s) that can detect "
            f"technique STIX ID '{technique_stix_id}' in domain '{domain}'."
        ),
    }


@mcp.tool()
async def get_techniques_detected_by_datacomponent(
    datacomponent_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all techniques that can be detected by a specific data component.

    Shows which adversary techniques can be identified by monitoring
    this specific aspect of telemetry.

    Args:
        datacomponent_stix_id: Data component STIX UUID identifier
                               (e.g., 'x-mitre-data-component--UUID').
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Whether to include technique descriptions.

    Returns:
        {
          "datacomponent": {
              "name": "<data component name or null>",
              "stix_id": "<x-mitre-data-component--UUID>",
              "description": "<text or null>",
              "data_source_stix_id": "<x-mitre-data-source--UUID or null>",
              "data_source_name": "<data source name or null>",
              "data_source_attack_id": "<data source ATT&CK ID or null>",
          } | null,

          "count": <number of techniques>,

          "techniques": [
            {
              "attack_id": "Txxxx or Txxxx.xxx" | null,
              "name": "<technique name>",
              "stix_id": "<attack-pattern--UUID>",
              "description": "<text or null>",
            },
            ...
          ],

          "formatted": "<human-readable list of techniques>",
          "message": "<status summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # --- Resolve data component metadata ---
    try:
        dc_obj = attack_data.get_object_by_stix_id(datacomponent_stix_id)
    except Exception:
        dc_obj = None

    datacomponent_info: Optional[Dict[str, Any]] = None
    dc_for_format: Optional[Any] = None

    if dc_obj is not None:
        dc_for_format = dc_obj

        if isinstance(dc_obj, dict):
            dc_name = dc_obj.get("name")
            dc_desc = dc_obj.get("description") if include_description else None
            ds_ref = (
                dc_obj.get("x_mitre_data_source_ref")
                or dc_obj.get("x-mitre-data-source-ref")
            )
        else:
            dc_name = getattr(dc_obj, "name", None)
            dc_desc = getattr(dc_obj, "description", None) if include_description else None
            ds_ref = getattr(dc_obj, "x_mitre_data_source_ref", None)

        data_source_stix_id = ds_ref
        data_source_name = None
        data_source_attack_id = None

        if ds_ref:
            try:
                ds_obj = attack_data.get_object_by_stix_id(ds_ref)
            except Exception:
                ds_obj = None

            if ds_obj is not None:
                if isinstance(ds_obj, dict):
                    ds_name = ds_obj.get("name")
                    ds_internal_id = ds_obj.get("id")
                else:
                    ds_name = getattr(ds_obj, "name", None)
                    ds_internal_id = getattr(ds_obj, "id", None)

                data_source_name = ds_name
                try:
                    data_source_attack_id = attack_data.get_attack_id(ds_internal_id)
                except Exception:
                    data_source_attack_id = None

        datacomponent_info = {
            "name": dc_name,
            "stix_id": datacomponent_stix_id,
            "description": dc_desc,
            "data_source_stix_id": data_source_stix_id,
            "data_source_name": data_source_name,
            "data_source_attack_id": data_source_attack_id,
        }

    # --- Fetch techniques detected by this data component ---
    try:
        techniques = attack_data.get_techniques_detected_by_datacomponent(
            datacomponent_stix_id
        ) or []
    except Exception:
        techniques = []

    if not techniques:
        return {
            "datacomponent": datacomponent_info,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": (
                f"No techniques found that are detected by data component "
                f"STIX ID '{datacomponent_stix_id}' in domain '{domain}'."
            ),
        }

    # --- Let's build structured list of techniques ---
    technique_entries: List[Dict[str, Any]] = []
    for t in techniques:
        if isinstance(t, dict):
            t_name = t.get("name")
            t_stix = t.get("id")
            t_desc = t.get("description") if include_description else None
        else:
            t_name = getattr(t, "name", None)
            t_stix = getattr(t, "id", None)
            t_desc = getattr(t, "description", None) if include_description else None

        try:
            t_attack_id = attack_data.get_attack_id(t_stix)
        except Exception:
            t_attack_id = None

        technique_entries.append(
            {
                "attack_id": t_attack_id,
                "name": t_name,
                "stix_id": t_stix,
                "description": t_desc,
            }
        )

    # --- Optional human-readable formatted output. Can be silent if needed ---
    formatted = ""
    if techniques:
        formatted = format_objects(
            techniques,
            include_description=include_description,
            domain=domain,
        )

    return {
        "datacomponent": datacomponent_info,
        "count": len(technique_entries),
        "techniques": technique_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(technique_entries)} technique(s) that can be detected by "
            f"data component STIX ID '{datacomponent_stix_id}' in domain '{domain}'."
        ),
    }

# ---------------------------------------------------------------------------
# Technique → Tactic → Procedure Examples (real-world usage)
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_procedure_examples_by_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get procedure examples showing how threat groups used a specific technique.

    Procedure examples describe real incident behavior tied to this technique.

    Args:
        technique_stix_id: STIX UUID of the technique
        domain: ATT&CK domain
        include_description: Include descriptions of the examples if available

    Returns:
        {
          "technique": {
              "attack_id": "Txxxx",
              "name": "...",
              "stix_id": "attack-pattern--UUID"
          },
          "count": N,
          "examples": [
              {
                "relationship_id": "relationship--UUID",
                "source_group_attack_id": "Gxxxx",
                "source_group_name": "...",
                "description": "...",
                "stix_id": "relationship--UUID"
              },
              ...
          ],
          "formatted": "<multi-line readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # --- Resolve technique metadata ---
    try:
        tech_obj = attack_data.get_object_by_stix_id(technique_stix_id)
    except Exception:
        tech_obj = None

    if tech_obj:
        tech_name = getattr(tech_obj, "name", None)
        try:
            tech_attack_id = attack_data.get_attack_id(technique_stix_id)
        except Exception:
            tech_attack_id = None
    else:
        tech_name = None
        tech_attack_id = None

    technique_info = {
        "attack_id": tech_attack_id,
        "name": tech_name,
        "stix_id": technique_stix_id,
    }

    # --- Retrieve procedure examples ---
    try:
        examples = attack_data.get_procedure_examples_by_technique(
            technique_stix_id
        ) or []
    except Exception:
        examples = []

    if not examples:
        return {
            "technique": technique_info,
            "count": 0,
            "examples": [],
            "formatted": "",
            "message": (
                f"No procedure examples found for technique '{tech_attack_id}' "
                f"in domain '{domain}'."
            ),
        }

    # --- Parse examples ---
    example_entries = []
    for rel in examples:
        # Relationship STIX ID
        rel_id = getattr(rel, "id", None)

        # Description of the specific usage of this technique
        desc = getattr(rel, "description", None) if include_description else None

        # Source group that used this technique
        source_stix_id = getattr(rel, "source_ref", None)

        group_attack_id = None
        group_name = None
        try:
            group_obj = attack_data.get_object_by_stix_id(source_stix_id)
            if group_obj:
                group_name = getattr(group_obj, "name", None)
                group_attack_id = attack_data.get_attack_id(source_stix_id)
        except Exception:
            pass

        example_entries.append(
            {
                "relationship_id": rel_id,
                "source_group_attack_id": group_attack_id,
                "source_group_name": group_name,
                "description": desc,
                "stix_id": rel_id,
            }
        )

    # --- Produce human-readable version (optional) as inidcated earlier ---
    formatted = format_objects(
        examples,
        include_description=include_description,
        domain=domain,
    )

    return {
        "technique": technique_info,
        "count": len(example_entries),
        "examples": example_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(example_entries)} procedure examples showing how groups "
            f"used technique '{tech_attack_id}' ({tech_name})."
        ),
    }


@mcp.tool()
async def get_procedure_examples_by_tactic(
    tactic: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all procedure examples for techniques in a specific tactic.

    Shows real-world examples of how threat groups use techniques that fall
    under a given tactic (e.g., Initial Access, Persistence).

    Args:
        tactic: Tactic name (e.g., "Initial Access", "Persistence").
                Case-insensitive; should match ATT&CK tactic names.
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics').
        include_description: Include example descriptions when available.

    Returns:
        {
          "tactic": {
              "name": "<tactic name>",
              "attack_id": "TAxxxx" | null,
              "stix_id": "x-mitre-tactic--UUID" | null,
          },
          "count": int,
          "examples": [
            {
              "relationship_id": "relationship--UUID",
              "description": "<procedure text or null>",
              "group": {
                "attack_id": "Gxxxx" | null,
                "name": "<group name or null>",
                "stix_id": "intrusion-set--UUID" | null,
              },
              "technique": {
                "attack_id": "Txxxx or Txxxx.xxx" | null,
                "name": "<technique name or null>",
                "stix_id": "attack-pattern--UUID" | null,
              },
            },
            ...
          ],
          "formatted": "<multi-line human-readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    # --- Resolve tactic metadata by name (best-effort) ---
    tactic_name_input = tactic
    tactic_name_norm = tactic.lower()
    tactic_stix_id = None
    tactic_attack_id = None

    try:
        all_tactics = attack_data.get_tactics(remove_revoked_deprecated=True)
    except Exception:
        all_tactics = []

    for t in all_tactics:
        t_name = getattr(t, "name", "") or ""
        if t_name.lower() == tactic_name_norm:
            tactic_stix_id = getattr(t, "id", None)
            try:
                tactic_attack_id = attack_data.get_attack_id(tactic_stix_id)
            except Exception:
                tactic_attack_id = None
            # Normalize to canonical name from ATT&CK
            tactic_name_input = t_name
            break

    tactic_info = {
        "name": tactic_name_input,
        "attack_id": tactic_attack_id,
        "stix_id": tactic_stix_id,
    }

    # --- Get procedure examples from MITRE helper ---
    try:
        examples = attack_data.get_procedure_examples_by_tactic(tactic_name_input) or []
    except Exception:
        examples = []

    if not examples:
        return {
            "tactic": tactic_info,
            "count": 0,
            "examples": [],
            "formatted": "",
            "message": (
                f"No procedure examples found for tactic '{tactic_name_input}' "
                f"in domain '{domain}'."
            ),
        }

    example_entries: list[Dict[str, Any]] = []

    for rel in examples:
        # Relationship itself (procedure example)
        rel_id = getattr(rel, "id", None)
        rel_desc = getattr(rel, "description", None) if include_description else None
        source_ref = getattr(rel, "source_ref", None)
        target_ref = getattr(rel, "target_ref", None)

        # Resolve source group
        group_info = {
            "attack_id": None,
            "name": None,
            "stix_id": source_ref,
        }
        if source_ref:
            try:
                g_obj = attack_data.get_object_by_stix_id(source_ref)
            except Exception:
                g_obj = None

            if g_obj is not None:
                g_name = getattr(g_obj, "name", None)
                try:
                    g_attack_id = attack_data.get_attack_id(source_ref)
                except Exception:
                    g_attack_id = None

                group_info = {
                    "attack_id": g_attack_id,
                    "name": g_name,
                    "stix_id": source_ref,
                }

        # Resolve target technique
        technique_info = {
            "attack_id": None,
            "name": None,
            "stix_id": target_ref,
        }
        if target_ref:
            try:
                tech_obj = attack_data.get_object_by_stix_id(target_ref)
            except Exception:
                tech_obj = None

            if tech_obj is not None:
                t_name = getattr(tech_obj, "name", None)
                try:
                    t_attack_id = attack_data.get_attack_id(target_ref)
                except Exception:
                    t_attack_id = None

                technique_info = {
                    "attack_id": t_attack_id,
                    "name": t_name,
                    "stix_id": target_ref,
                }

        example_entries.append(
            {
                "relationship_id": rel_id,
                "description": rel_desc,
                "group": group_info,
                "technique": technique_info,
            }
        )

    # --- Human-readable formatted block (for LLMs / humans) ---
    formatted = format_objects(
        examples,
        include_description=include_description,
        domain=domain,
    )

    return {
        "tactic": tactic_info,
        "count": len(example_entries),
        "examples": example_entries,
        "formatted": formatted,
        "message": (
            f"Found {len(example_entries)} procedure example(s) for tactic "
            f"'{tactic_info['name']}' in domain '{domain}'."
        ),
    }


# ---------------------------------------------------------------------------
# Generic STIX object browser
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_objects_by_type(
    stix_type: str,
    domain: str = "enterprise",
    remove_revoked_deprecated: bool = True,
    include_description: bool = False,
) -> Dict[str, Any]:
    """
    Get all objects of a specific STIX type.

    This is a generic method to retrieve ATT&CK/CTI objects by STIX type.
    It complements more specific tools such as get_all_techniques(),
    get_all_groups(), etc.

    Common STIX types include:
      - 'attack-pattern'          (techniques)
      - 'malware'                 (malware)
      - 'tool'                    (tools)
      - 'intrusion-set'           (APT groups)
      - 'campaign'                (campaigns)
      - 'course-of-action'        (mitigations)
      - 'x-mitre-matrix'          (matrices)
      - 'x-mitre-tactic'          (tactics)
      - 'x-mitre-data-source'     (data sources)
      - 'x-mitre-data-component'  (data components)
      - 'x-mitre-asset'           (ICS assets)

    Args:
        stix_type: STIX object type to fetch.
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics', ...).
        remove_revoked_deprecated: Exclude revoked/deprecated objects.
        include_description: Include object descriptions in output.

    Returns:
        {
          "stix_type": "<type>",
          "domain": "<domain>",
          "count": int,
          "objects": [
            {
              "name": "...",
              "stix_id": "<stix-id>",
              "attack_id": "<T/G/S/M/C/... or null>",
              "description": "<text or null>",
            },
            ...
          ],
          "formatted": "<multi-line readable text>",
          "message": "<summary>"
        }
    """
    attack_data = get_attack_data(domain)

    try:
        objs = attack_data.get_objects_by_type(
            stix_type,
            remove_revoked_deprecated=remove_revoked_deprecated,
        ) or []
    except Exception:
        objs = []

    if not objs:
        return {
            "stix_type": stix_type,
            "domain": domain,
            "count": 0,
            "objects": [],
            "formatted": "",
            "message": (
                f"No objects of type '{stix_type}' found in domain '{domain}' "
                f"(remove_revoked_deprecated={remove_revoked_deprecated})."
            ),
        }

    entries: list[dict[str, Any]] = []
    for obj in objs:
        # Handle both STIX classes and dict-like objects
        if isinstance(obj, dict):
            stix_id = obj.get("id")
            name = obj.get("name")
            desc = obj.get("description") if include_description else None
        else:
            stix_id = getattr(obj, "id", None)
            name = getattr(obj, "name", None)
            desc = getattr(obj, "description", None) if include_description else None

        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        entries.append(
            {
                "name": name,
                "stix_id": stix_id,
                "attack_id": attack_id,
                "description": desc,
            }
        )

    formatted = format_objects(
        objs,
        include_description=include_description,
        domain=domain,
    )

    return {
        "stix_type": stix_type,
        "domain": domain,
        "count": len(entries),
        "objects": entries,
        "formatted": formatted,
        "message": (
            f"Found {len(entries)} object(s) of type '{stix_type}' in "
            f"domain '{domain}' "
            f"(remove_revoked_deprecated={remove_revoked_deprecated})."
        ),
    }

@mcp.tool()
async def get_tactics_by_matrix(
    matrix_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
):
    """
    Get all ATT&CK tactics belonging to a specific matrix.

    Args:
        matrix_stix_id: STIX ID of the matrix (e.g., x-mitre-matrix--UUID)
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics')
        include_description: Whether to include tactic descriptions

    Returns:
        {
          "found": bool,
          "count": int,
          "tactics": [
            {
              "name": "...",
              "stix_id": "...",
              "description": "...",
              "attack_id": "TAxxxx" or null
            }
          ],
          "formatted": "<multiline string>",
          "message": "..."
        }
    """
    attack_data = get_attack_data(domain)

    try:
        tactics = attack_data.get_tactics_by_matrix(matrix_stix_id) or []
    except Exception:
        tactics = []

    if not tactics:
        return {
            "found": False,
            "count": 0,
            "tactics": [],
            "formatted": "",
            "message": f"No tactics found for matrix '{matrix_stix_id}' in domain '{domain}'.",
        }

    results = []
    for tac in tactics:
        stix_id = tac.id
        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        results.append(
            {
                "name": getattr(tac, "name", None),
                "stix_id": stix_id,
                "attack_id": attack_id,
                "description": getattr(tac, "description", None) if include_description else None,
            }
        )

    formatted = format_objects(
        tactics,
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "count": len(results),
        "tactics": results,
        "formatted": formatted,
        "message": f"Found {len(results)} tactic(s) in matrix '{matrix_stix_id}'.",
    }

@mcp.tool()
async def get_tactics_by_technique(
    technique_stix_id: str,
    domain: str = "enterprise",
    include_description: bool = False,
):
    """
    Get all tactics associated with a specific ATT&CK technique.

    Techniques can belong to one or more tactics (kill chain phases).

    Args:
        technique_stix_id: Technique STIX UUID identifier (attack-pattern--UUID)
        domain: ATT&CK domain ('enterprise', 'mobile', 'ics')
        include_description: Whether to include tactic descriptions

    Returns:
        {
          "found": bool,
          "count": int,
          "tactics": [
            {
              "name": "...",
              "stix_id": "...",
              "attack_id": "TAxxxx" or null,
              "description": "...",
            }
          ],
          "formatted": "<multiline formatted output>",
          "message": "..."
        }
    """
    attack_data = get_attack_data(domain)

    try:
        tactics = attack_data.get_tactics_by_technique(technique_stix_id) or []
    except Exception:
        tactics = []

    if not tactics:
        return {
            "found": False,
            "count": 0,
            "tactics": [],
            "formatted": "",
            "message": (
                f"No tactics found for technique '{technique_stix_id}' "
                f"in domain '{domain}'."
            ),
        }

    results = []
    for tac in tactics:
        stix_id = tac.id

        try:
            attack_id = attack_data.get_attack_id(stix_id)
        except Exception:
            attack_id = None

        results.append(
            {
                "name": getattr(tac, "name", None),
                "stix_id": stix_id,
                "attack_id": attack_id,
                "description": getattr(tac, "description", None)
                if include_description
                else None,
            }
        )

    formatted = format_objects(
        tactics,
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "count": len(results),
        "tactics": results,
        "formatted": formatted,
        "message": f"Found {len(results)} tactic(s) associated with the technique.",
    }


@mcp.tool()
async def get_objects_created_after(
    timestamp: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK objects created after a specific timestamp.

    Useful for detecting new additions to the framework.
    Timestamp must be ISO8601 format, e.g., '2024-01-01T00:00:00Z'.

    Returns:
        {
            "found": bool,
            "count": int,
            "objects": [
                {
                    "id": "<ATT&CK ID or None>",
                    "name": "...",
                    "stix_id": "...",
                    "type": "<stix-type>",
                    "description": "..." | None
                },
                ...
            ],
            "formatted": "<pretty text>",
            "message": "..."
        }
    """
    attack_data = get_attack_data(domain)

    # Try to fetch objects
    try:
        objects = attack_data.get_objects_created_after(timestamp) or []
    except Exception as e:
        return {
            "found": False,
            "count": 0,
            "objects": [],
            "formatted": "",
            "message": f"Error retrieving objects created after {timestamp}: {e}",
        }

    if not objects:
        return {
            "found": False,
            "count": 0,
            "objects": [],
            "formatted": "",
            "message": f"No objects created after '{timestamp}' in domain '{domain}'.",
        }

    # Build structured response
    results = []
    for obj in objects:
        attack_id = None
        try:
            attack_id = attack_data.get_attack_id(obj.id)
        except Exception:
            pass

        results.append(
            {
                "id": attack_id,
                "name": getattr(obj, "name", None),
                "stix_id": obj.id,
                "type": getattr(obj, "type", None),
                "description": getattr(obj, "description", None)
                if include_description
                else None,
            }
        )

    # Pretty printed human-friendly block
    formatted = format_objects(objects, include_description=include_description, domain=domain)

    return {
        "found": True,
        "count": len(results),
        "objects": results,
        "formatted": formatted,
        "message": f"Found {len(results)} objects created after {timestamp}.",
    }

@mcp.tool()
async def get_objects_modified_after(
    timestamp: str,
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all ATT&CK objects modified after a specific timestamp.

    Useful for tracking updates and changes to the ATT&CK framework.
    Timestamp must be ISO8601 format, e.g., '2024-01-01T00:00:00Z'.

    Returns:
        {
            "found": bool,
            "count": int,
            "objects": [
                {
                    "id": "<ATT&CK ID or None>",
                    "name": "...",
                    "stix_id": "...",
                    "type": "<stix-type>",
                    "description": "..." | None
                },
                ...
            ],
            "formatted": "<pretty text>",
            "message": "..."
        }
    """
    attack_data = get_attack_data(domain)

    # Try to fetch objects
    try:
        objects = attack_data.get_objects_modified_after(timestamp) or []
    except Exception as e:
        return {
            "found": False,
            "count": 0,
            "objects": [],
            "formatted": "",
            "message": f"Error retrieving objects modified after {timestamp}: {e}",
        }

    if not objects:
        return {
            "found": False,
            "count": 0,
            "objects": [],
            "formatted": "",
            "message": f"No objects modified after '{timestamp}' in domain '{domain}'.",
        }

    # Build structured response
    results: list[Dict[str, Any]] = []
    for obj in objects:
        try:
            attack_id = attack_data.get_attack_id(obj.id)
        except Exception:
            attack_id = None

        results.append(
            {
                "id": attack_id,
                "name": getattr(obj, "name", None),
                "stix_id": getattr(obj, "id", None),
                "type": getattr(obj, "type", None),
                "description": getattr(obj, "description", None)
                if include_description
                else None,
            }
        )

    # Human-readable formatted output
    formatted = format_objects(
        objects,
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "count": len(results),
        "objects": results,
        "formatted": formatted,
        "message": f"Found {len(results)} objects modified after {timestamp}.",
    }

@mcp.tool()
async def get_revoked_techniques(
    domain: str = "enterprise",
    include_description: bool = True,
) -> Dict[str, Any]:
    """
    Get all revoked techniques for a domain.

    Revoked techniques are no longer valid in the framework, often because
    they were merged or replaced.

    Returns:
        {
            "found": bool,
            "count": int,
            "techniques": [...],
            "formatted": "<pretty output>",
            "message": "..."
        }
    """
    attack_data = get_attack_data(domain)

    # Retrieve ALL techniques, including revoked ones
    try:
        all_techniques = attack_data.get_techniques(remove_revoked_deprecated=False)
    except Exception as e:
        return {
            "found": False,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"Error retrieving techniques: {e}",
        }

    # Filter revoked only
    revoked = [t for t in all_techniques if getattr(t, "revoked", False)]

    if not revoked:
        return {
            "found": False,
            "count": 0,
            "techniques": [],
            "formatted": "",
            "message": f"No revoked techniques found in domain '{domain}'.",
        }

    # Build structured output
    output_items = []
    for tech in revoked:
        try:
            attack_id = attack_data.get_attack_id(tech.id)
        except Exception:
            attack_id = None

        output_items.append(
            {
                "id": attack_id,
                "name": getattr(tech, "name", None),
                "stix_id": getattr(tech, "id", None),
                "revoked": True,
                "description": getattr(tech, "description", None)
                if include_description
                else None,
            }
        )

    # Human-readable formatted block
    formatted = format_objects(
        revoked,
        include_description=include_description,
        domain=domain,
    )

    return {
        "found": True,
        "count": len(output_items),
        "techniques": output_items,
        "formatted": formatted,
        "message": f"Found {len(output_items)} revoked techniques in '{domain}'.",
    }

@mcp.tool()
async def generate_layer(
    attack_id: str,
    score: int = 1,
    domain: str = "enterprise",
) -> Dict[str, Any]:
    """
    Generate an ATT&CK Navigator layer for visualization.

    This wraps mitreattack.navlayers.UsageLayerGenerator and produces a
    JSON layer highlighting techniques associated with a given ATT&CK ID.

    Only the following ATT&CK ID prefixes are supported:
      - Gxxxx : groups (intrusion sets)
      - Mxxxx : mitigations (course-of-action)
      - Sxxxx : software (tool/malware)
      - Dxxxx : data components

    Technique IDs (Txxxx / Txxxx.xxx) are NOT supported here.

    Args:
        attack_id: ATT&CK ID (Gxxxx, Mxxxx, Sxxxx, or Dxxxx)
        score: Score to assign to all matched techniques in the layer
        domain: ATT&CK domain (e.g., "enterprise", "mobile", "ics")

    Returns:
        {
          "success": bool,
          "attack_id": "<G/M/S/D ID>",
          "domain": "<domain>",
          "count": int,              # number of techniques in layer
          "layer": { ... } | null,   # ATT&CK Navigator layer JSON
          "message": "<summary or error>"
        }
    """
    import re
    from mitreattack.navlayers import UsageLayerGenerator

    # Validate ATT&CK ID format: must be Gxxx/Mxxx/Sxxx/Dxxx
    if not re.match(r"^[GMSD]\d+$", attack_id):
        return {
            "success": False,
            "attack_id": attack_id,
            "domain": domain,
            "count": 0,
            "layer": None,
            "message": (
                f"Invalid ATT&CK ID format: '{attack_id}'. Must be "
                "GXXX (group), MXXX (mitigation), SXXX (software), or DXXX (data component). "
                "Technique IDs (TXXX) are not supported."
            ),
        }

    # Use the shared path helpers so behavior matches downloads + other tools
    stix_path = get_stix_path(domain)

    if not stix_path.exists():
        return {
            "success": False,
            "attack_id": attack_id,
            "domain": domain,
            "count": 0,
            "layer": None,
            "message": (
                f"STIX data file not found at '{stix_path}'. "
                "Make sure data has been downloaded for this domain."
            ),
        }

    # Generate Navigator layer
    try:
        generator = UsageLayerGenerator(
            source="local",
            domain=domain,
            resource=str(stix_path),
        )

        layer_obj = generator.generate_layer(match=attack_id)

        # Basic sanity checks
        if not layer_obj or not layer_obj.layer or not layer_obj.layer.techniques:
            return {
                "success": False,
                "attack_id": attack_id,
                "domain": domain,
                "count": 0,
                "layer": None,
                "message": (
                    f"No techniques found for '{attack_id}' in domain '{domain}'."
                ),
            }

        # Keep only techniques with score > 0, then override score
        layer_obj.layer.techniques = [
            t for t in layer_obj.layer.techniques if getattr(t, "score", 0) > 0
        ]
        for t in layer_obj.layer.techniques:
            t.score = score

        layer_dict = layer_obj.to_dict()
        count = len(layer_obj.layer.techniques)

        return {
            "success": True,
            "attack_id": attack_id,
            "domain": domain,
            "count": count,
            "layer": layer_dict,
            "message": (
                f"Generated Navigator layer for '{attack_id}' in domain "
                f"'{domain}' with {count} technique(s)."
            ),
        }

    except Exception as e:
        return {
            "success": False,
            "attack_id": attack_id,
            "domain": domain,
            "count": 0,
            "layer": None,
            "message": f"Failed to generate layer: {e}",
        }

@mcp.tool()
async def get_layer_metadata(domain: str = "enterprise") -> Dict[str, Any]:
    """
    Return a standard ATT&CK Navigator layer metadata template.

    This provides default layer properties (version info, gradient settings,
    layout, filters, etc.) adapted to a specific ATT&CK domain.

    Useful for clients that want to build custom layers programmatically
    without starting from scratch.

    Args:
        domain: One of "enterprise", "mobile", "ics". Defaults to "enterprise".

    Returns:
        {
          "success": bool,
          "domain": "<domain>",
          "metadata": { ... },  # Navigator layer metadata
          "message": "<summary>"
        }
    """
    # Base Navigator layer template
    base_metadata = {
        "name": "layer",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "description": "",
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "expandedSubtechniques": "none",
        },
        "techniques": [],
        "gradient": {
            "colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [],
        "metadata": [],
        "links": [],
        "tacticRowBackground": "#dddddd",
    }

    # Domain → platform filter mappings
    domain_configs = {
        "enterprise": {
            "domain": "enterprise-attack",
            "filters": {
                "platforms": [
                    "Windows", "Linux", "macOS", "Network", "PRE",
                    "Containers", "IaaS", "SaaS", "Office Suite",
                    "Identity Provider"
                ]
            },
        },
        "mobile": {
            "domain": "mobile-attack",
            "filters": {"platforms": ["Android", "iOS"]},
        },
        "ics": {
            "domain": "ics-attack",
            "filters": {"platforms": ["None"]},
        },
    }

    # Normalize domain
    domain = domain.lower()
    if domain not in domain_configs:
        return {
            "success": False,
            "domain": domain,
            "metadata": None,
            "message": (
                "Invalid domain. Must be one of: enterprise, mobile, ics."
            ),
        }

    # Merge templates
    metadata = base_metadata.copy()
    metadata.update(domain_configs[domain])

    return {
        "success": True,
        "domain": domain,
        "metadata": metadata,
        "message": f"Returned Navigator layer metadata for {domain} domain.",
    }



# ---------------------------------------------------------------------------
# Entrypoint for MCP (used by pyproject.toml [project.scripts])
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Entrypoint for the mitre-mcp-server executable.

    - Ensures STIX data is downloaded for all domains (if not already).
    - Starts the FastMCP server so tools (like get_data_stats) can be used.
    """
    # Download all domains if needed (no force by default)
    download_all_domains(force=False)

    # Start the MCP server (FastMCP handles stdio / CLI integration)
    mcp.run()
