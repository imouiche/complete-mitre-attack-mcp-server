"""
STIX data parser for MITRE ATT&CK framework using mitreattack-python library.

This module provides a unified interface to query MITRE ATT&CK data across
all three domains (Enterprise, Mobile, ICS).
"""
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Any


from mitreattack.navlayers import UsageLayerGenerator
from mitreattack.stix20 import MitreAttackData
from mitreattack import release_info


# Base data directory (same as download.py)
BASE_DATA_DIR = Path(
    os.getenv(
        "MITRE_MCP_DATA_DIR",
        Path.home() / ".mitre-mcp-server" / "data",
    )
)

DOMAINS = ["enterprise", "mobile", "ics"]


class MITREDataManager:
    """
    Manager for MITRE ATT&CK data across all domains.
    
    This class handles loading and querying MITRE ATT&CK STIX data
    using the mitreattack-python library.
    """
    
    def __init__(self, data_dir: Optional[Path] = None):
        """
        Initialize the MITRE data manager.
        
        Args:
            data_dir: Optional custom data directory path. If None, uses default.
        """
        self.data_dir = data_dir or BASE_DATA_DIR
        self.attack_data: Dict[str, MitreAttackData] = {}
        self._loaded_domains: List[str] = []
    
    def load_domain(self, domain: str) -> bool:
        """
        Load STIX data for a specific domain.
        
        Args:
            domain: Domain name ('enterprise', 'mobile', or 'ics')
            
        Returns:
            True if loaded successfully, False otherwise
        """
        if domain not in DOMAINS:
            raise ValueError(f"Invalid domain '{domain}'. Must be one of: {DOMAINS}")
        
        domain_key = f"{domain}-attack"
        
        # Check if already loaded
        if domain_key in self.attack_data:
            return True
        
        # Build path to STIX file
        version_dir = self.data_dir / f"v{release_info.LATEST_VERSION}"
        stix_path = version_dir / f"{domain_key}.json"
        
        if not stix_path.exists():
            raise FileNotFoundError(
                f"STIX data file not found at {stix_path}. "
                f"Run 'python -m mitre_mcp_server.data.download' to download it."
            )
        
        # Load the data
        try:
            self.attack_data[domain_key] = MitreAttackData(str(stix_path))
            self._loaded_domains.append(domain)
            return True
        except Exception as e:
            raise RuntimeError(f"Failed to load {domain} domain data: {e}")
    
    def load_all_domains(self) -> List[str]:
        """
        Load STIX data for all available domains.
        
        Returns:
            List of successfully loaded domain names
        """
        loaded = []
        for domain in DOMAINS:
            try:
                if self.load_domain(domain):
                    loaded.append(domain)
            except Exception as e:
                print(f"Warning: Could not load {domain} domain: {e}")
        
        return loaded
    
    def get_attack_data(self, domain: str = "enterprise") -> MitreAttackData:
        """
        Get the MitreAttackData object for a specific domain.
        
        Args:
            domain: Domain name (default: 'enterprise')
            
        Returns:
            MitreAttackData object for the specified domain
        """
        domain_key = f"{domain}-attack"
        
        # Load domain if not already loaded
        if domain_key not in self.attack_data:
            self.load_domain(domain)
        
        return self.attack_data[domain_key]
    
    @property
    def loaded_domains(self) -> List[str]:
        """Get list of currently loaded domains."""
        return self._loaded_domains.copy()
    
    def get_technique_by_id(self, technique_id: str, domain: str = "enterprise") -> Optional[Any]:
        """
        Get a technique by its ATT&CK ID (e.g., T1566, T1053.005).
        
        Args:
            technique_id: ATT&CK technique ID
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            Technique object or None if not found
        """
        attack_data = self.get_attack_data(domain)
        techniques = attack_data.get_techniques(remove_revoked_deprecated=True)
        
        for tech in techniques:
            if attack_data.get_attack_id(tech.id) == technique_id:
                return tech
        
        return None
    
    def get_object_by_attack_id(
        self,
        attack_id: str,
        stix_type: str,
        domain: str = "enterprise"
        ) -> Optional[Any]:
        """
        Get any MITRE object by its ATT&CK ID and STIX type.
        
        This is a generic method that can retrieve any type of MITRE object.
        
        Args:
            attack_id: ATT&CK ID (e.g., 'T1566', 'G0016', 'S0154', 'M1013')
            stix_type: STIX object type - must be one of:
                - 'attack-pattern' (techniques)
                - 'malware' (malware)
                - 'tool' (tools)
                - 'intrusion-set' (APT groups)
                - 'campaign' (campaigns)
                - 'course-of-action' (mitigations)
                - 'x-mitre-matrix' (matrices)
                - 'x-mitre-tactic' (tactics)
                - 'x-mitre-data-source' (data sources)
                - 'x-mitre-data-component' (data components)
                - 'x-mitre-asset' (assets)
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            STIX object or None if not found
            
        Examples:
            >>> manager.get_object_by_attack_id("T1566", "attack-pattern")  # Phishing
            >>> manager.get_object_by_attack_id("G0016", "intrusion-set")   # APT29
            >>> manager.get_object_by_attack_id("M1013", "course-of-action") # Mitigation
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            obj = attack_data.get_object_by_attack_id(attack_id, stix_type)
            return obj
        except Exception:
            # Object not found or invalid type
            return None
        
    def get_object_by_stix_id(
        self,
        stix_id: str,
        domain: str = "enterprise"
        ) -> Optional[Any]:
        """
        Get any MITRE object by its STIX ID (UUID).
        
        STIX IDs are internal UUIDs like:
        'attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b'
        
        Args:
            stix_id: STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            STIX object or None if not found
            
        Examples:
            >>> manager.get_object_by_stix_id(
            ...     "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
            ... )  # Returns Phishing technique
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            obj = attack_data.get_object_by_stix_id(stix_id)
            return obj
        except Exception:
            # Object not found
            return None
        
    def get_objects_by_name(
        self,
        name: str,
        stix_type: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get objects by exact name match (case-sensitive).
        
        This searches for objects with an exact name match, unlike search methods
        which do partial/keyword matching.
        
        Args:
            name: Exact name to search for (case-sensitive)
            stix_type: STIX object type (same types as get_object_by_attack_id)
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of matching STIX objects (may be empty)
            
        Examples:
            >>> manager.get_objects_by_name("Phishing", "attack-pattern")
            >>> manager.get_objects_by_name("APT29", "intrusion-set")
            >>> manager.get_objects_by_name("Cobalt Strike", "malware")
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            objects = attack_data.get_objects_by_name(name, stix_type)
            return objects if objects else []
        except Exception:
            return []
    
    def get_objects_by_content(
        self,
        content: str,
        object_type: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Search for objects by content in their description (full-text search).
        
        This searches within the description field of objects, useful for finding
        objects that mention specific tools, techniques, or concepts.
        
        Args:
            content: Text to search for in descriptions
            object_type: STIX object type (same types as get_object_by_attack_id)
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of matching STIX objects (may be empty)
            
        Examples:
            >>> # Find techniques mentioning PowerShell
            >>> manager.get_objects_by_content("PowerShell", "attack-pattern")
            >>> 
            >>> # Find groups mentioning specific countries
            >>> manager.get_objects_by_content("Russia", "intrusion-set")
            >>>
            >>> # Find mitigations mentioning MFA
            >>> manager.get_objects_by_content("multi-factor", "course-of-action")
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            objects = attack_data.get_objects_by_content(content, object_type)
            return objects if objects else []
        except Exception:
            return []


    def get_techniques_by_tactic(self, tactic: str, domain: str = "enterprise") -> List[Any]:
            """
            Get all techniques for a specific tactic.
            
            Args:
                tactic: Tactic name (e.g., 'Initial Access', 'Persistence')
                domain: Domain to search in (default: 'enterprise')
                
            Returns:
                List of technique objects
            """
            attack_data = self.get_attack_data(domain)
            techniques = attack_data.get_techniques_by_tactic(
                tactic,
                f"{domain}-attack",
                remove_revoked_deprecated=True
            )
            return techniques
    
    def search_techniques(self, query: str, domain: str = "enterprise") -> List[Any]:
        """
        Search techniques by name or description keyword.
        
        Args:
            query: Search query string
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of matching technique objects
        """
        attack_data = self.get_attack_data(domain)
        techniques = attack_data.get_techniques(remove_revoked_deprecated=True)
        
        query_lower = query.lower()
        results = []
        
        for tech in techniques:
            name = tech.name.lower() if hasattr(tech, 'name') else ""
            description = tech.description.lower() if hasattr(tech, 'description') else ""
            
            if query_lower in name or query_lower in description:
                results.append(tech)
        
        return results
    
    def get_group_by_name(self, group_name: str, domain: str = "enterprise") -> Optional[Any]:
        """
        Get an APT group by name.
        
        Args:
            group_name: Group name (e.g., 'APT29', 'Lazarus Group')
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            Group object or None if not found
        """
        attack_data = self.get_attack_data(domain)
        groups = attack_data.get_groups(remove_revoked_deprecated=True)
        
        query_lower = group_name.lower()
        
        for group in groups:
            name = group.name.lower() if hasattr(group, 'name') else ""
            aliases = [alias.lower() for alias in getattr(group, 'aliases', [])]
            
            if query_lower in name or query_lower in ' '.join(aliases):
                return group
        
        return None
    
    def get_stix_type(
        self,
        stix_id: str,
        domain: str = "enterprise"
        ) -> Optional[str]:
        """
        Get the STIX type of an object by its STIX ID.
        
        Useful when you have a STIX ID but need to know what type of object it is.
        
        Args:
            stix_id: STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            STIX type string (e.g., 'attack-pattern', 'intrusion-set', 'malware')
            or None if not found
            
        Examples:
            >>> manager.get_stix_type(
            ...     "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
            ... )
            'attack-pattern'
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            stix_type = attack_data.get_stix_type(stix_id)
            return stix_type
        except Exception:
            return None
    
    def search_groups(self, query: str = "", domain: str = "enterprise") -> List[Any]:
        """
        Search APT groups by name, alias, or description.
        
        Args:
            query: Search query (empty string returns all groups)
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of matching group objects
        """
        attack_data = self.get_attack_data(domain)
        groups = attack_data.get_groups(remove_revoked_deprecated=True)
        
        if not query:
            return groups
        
        query_lower = query.lower()
        results = []
        
        for group in groups:
            name = group.name.lower() if hasattr(group, 'name') else ""
            description = group.description.lower() if hasattr(group, 'description') else ""
            aliases = [alias.lower() for alias in getattr(group, 'aliases', [])]
            
            if (query_lower in name or 
                query_lower in description or
                query_lower in ' '.join(aliases)):
                results.append(group)
        
        return results
    
    def get_group_techniques(self, group_name: str, domain: str = "enterprise") -> List[Any]:
        """
        Get all techniques used by a specific APT group.
        
        Args:
            group_name: Group name or alias
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of technique objects used by the group
        """
        # First find the group
        group = self.get_group_by_name(group_name, domain)
        
        if not group:
            return []
        
        # Get techniques used by this group
        attack_data = self.get_attack_data(domain)
        techniques = attack_data.get_techniques_used_by_group(group.id)
        
        return techniques
    
    def get_software(self, domain: str = "enterprise") -> List[Any]:
        """
        Get all software/malware objects.
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of software objects
        """
        attack_data = self.get_attack_data(domain)
        software = attack_data.get_software(remove_revoked_deprecated=True)
        return software
    
    def search_software(self, query: str, domain: str = "enterprise") -> List[Any]:
        """
        Search software/malware by name or description.
        
        Args:
            query: Search query string
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of matching software objects
        """
        attack_data = self.get_attack_data(domain)
        software = attack_data.get_software(remove_revoked_deprecated=True)
        
        query_lower = query.lower()
        results = []
        
        for sw in software:
            name = sw.name.lower() if hasattr(sw, 'name') else ""
            description = sw.description.lower() if hasattr(sw, 'description') else ""
            
            if query_lower in name or query_lower in description:
                results.append(sw)
        
        return results
    

    def get_attack_id(
        self,
        stix_id: str,
        domain: str = "enterprise"
        ) -> Optional[str]:
        """
        Get the ATT&CK ID for a given STIX ID.
        
        Converts internal STIX UUID to human-readable ATT&CK ID.
        
        Args:
            stix_id: STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            ATT&CK ID (e.g., 'T1566', 'G0016', 'S0154') or None if not found
            
        Examples:
            >>> manager.get_attack_id(
            ...     "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
            ... )
            'T1566'
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            attack_id = attack_data.get_attack_id(stix_id)
            return attack_id
        except Exception:
            return None
    
    # def get_attack_id(self, stix_object, domain: str = "enterprise") -> str:
    #     """Extract ATT&CK ID (T1566, G0016, etc.) from STIX object"""
    #     attack_data = self.get_attack_data(domain)
    #     return attack_data.get_attack_id(stix_object.id)
    
    # Helper to get description
    def get_description(self, stix_object) -> Optional[str]:
        """Get description from any STIX object"""
        return getattr(stix_object, 'description', None)
    

    def get_name(
        self,
        stix_id: str,
        domain: str = "enterprise"
        ) -> Optional[str]:
        """
        Get the name of an object by its STIX ID.
        
        Args:
            stix_id: STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            Object name (e.g., 'Phishing', 'APT29', 'Cobalt Strike') 
            or None if not found
            
        Examples:
            >>> manager.get_name(
            ...     "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
            ... )
            'Phishing'
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            name = attack_data.get_name(stix_id)
            return name
        except Exception:
            return None
    
    # Helper to get tactic names from technique
    def get_technique_tactics(self, technique_object) -> List[str]:
        """
        Extract tactic names from a technique object.
        
        Args:
            technique_object: A STIX technique object
            
        Returns:
            List of tactic names (e.g., ['Initial Access', 'Persistence'])
        """
        phases = getattr(technique_object, 'kill_chain_phases', [])
        return [phase.phase_name.replace('-', ' ').title() for phase in phases]

    def get_stats(self, domain: str = "enterprise") -> Dict[str, int]:
        """
        Get statistics about the loaded data.
        
        Args:
            domain: Domain to get stats for (default: 'enterprise')
            
        Returns:
            Dictionary with counts of different object types
        """
        attack_data = self.get_attack_data(domain)
        
        return {
            "techniques": len(attack_data.get_techniques(remove_revoked_deprecated=True)),
            "groups": len(attack_data.get_groups(remove_revoked_deprecated=True)),
            "software": len(attack_data.get_software(remove_revoked_deprecated=True)),
            "tactics": len(attack_data.get_tactics(remove_revoked_deprecated=True)),
            "mitigations": len(attack_data.get_mitigations(remove_revoked_deprecated=True)),
        }


    #####################################################################
    # Threat Actor Group functions
    #####################################################################
    
    def get_groups_by_alias(
        self,
        alias: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get groups by their alias.
        
        Many APT groups have multiple aliases. This method searches specifically
        in the aliases field.
        
        Args:
            alias: Group alias to search for (e.g., 'Cozy Bear', 'NOBELIUM')
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of matching group objects (may be empty)
            
        Examples:
            >>> # All find the same group (APT29)
            >>> manager.get_groups_by_alias("Cozy Bear")
            >>> manager.get_groups_by_alias("NOBELIUM")
            >>> manager.get_groups_by_alias("Midnight Blizzard")
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            groups = attack_data.get_groups_by_alias(alias)
            return groups if groups else []
        except Exception:
            return []

    def get_techniques_used_by_group(
        self,
        group_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all techniques used by a group (by STIX ID).
        
        Similar to get_group_techniques() but takes STIX ID instead of name.
        Useful when you already have the group's STIX ID from another query.
        
        Args:
            group_stix_id: Group STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of technique objects used by the group
            
        Examples:
            >>> group = manager.get_group_by_name("APT29")
            >>> techniques = manager.get_techniques_used_by_group(group.id)
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            techniques = attack_data.get_techniques_used_by_group(group_stix_id)
            return techniques if techniques else []
        except Exception:
            return []

    def get_software_used_by_group(
        self,
        group_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all software (malware/tools) used by a group.
        
        Returns both malware and tools that the group is known to use.
        
        Args:
            group_stix_id: Group STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of software objects (malware and tools) used by the group
            
        Examples:
            >>> group = manager.get_group_by_name("APT29")
            >>> software = manager.get_software_used_by_group(group.id)
            >>> # Returns: Cobalt Strike, Mimikatz, etc.
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            software = attack_data.get_software_used_by_group(group_stix_id)
            return software if software else []
        except Exception:
            return []

    def get_campaigns_attributed_to_group(
        self,
        group_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all campaigns attributed to a specific group.
        
        Campaigns are specific operations or intrusion sets carried out by a group.
        
        Args:
            group_stix_id: Group STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of campaign objects attributed to the group
            
        Examples:
            >>> group = manager.get_group_by_name("APT29")
            >>> campaigns = manager.get_campaigns_attributed_to_group(group.id)
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            campaigns = attack_data.get_campaigns_attributed_to_group(group_stix_id)
            return campaigns if campaigns else []
        except Exception:
            return []

    def get_techniques_used_by_group_software(
        self,
        group_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get techniques used by the software that a group uses.
        
        This provides an indirect view of group capabilities through their tools:
        Group → Software → Techniques
        
        Args:
            group_stix_id: Group STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of technique objects used by the group's software
            
        Examples:
            >>> group = manager.get_group_by_name("APT29")
            >>> # Get techniques from APT29's tools (Cobalt Strike, etc.)
            >>> techniques = manager.get_techniques_used_by_group_software(group.id)
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            techniques = attack_data.get_techniques_used_by_group_software(group_stix_id)
            return techniques if techniques else []
        except Exception:
            return []

    def get_groups_using_technique(
        self,
        technique_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all groups that use a specific technique.
        
        This is a reverse lookup: Technique → Groups
        
        Args:
            technique_stix_id: Technique STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of group objects that use this technique
            
        Examples:
            >>> tech = manager.get_technique_by_id("T1566")  # Phishing
            >>> groups = manager.get_groups_using_technique(tech.id)
            >>> # Returns: APT29, APT28, Lazarus Group, etc.
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            groups = attack_data.get_groups_using_technique(technique_stix_id)
            return groups if groups else []
        except Exception:
            return []

    def get_groups_using_software(
        self,
        software_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all groups that use specific software/malware.
        
        This is a reverse lookup: Software → Groups
        
        Args:
            software_stix_id: Software STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of group objects that use this software
            
        Examples:
            >>> # Find Cobalt Strike
            >>> software = manager.search_software("Cobalt Strike")[0]
            >>> # Find which groups use it
            >>> groups = manager.get_groups_using_software(software.id)
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            groups = attack_data.get_groups_using_software(software_stix_id)
            return groups if groups else []
        except Exception:
            return []

    def get_groups_attributing_to_campaign(
        self,
        campaign_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all groups attributed to a specific campaign.
        
        This is a reverse lookup: Campaign → Groups
        
        Args:
            campaign_stix_id: Campaign STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of group objects attributed to this campaign
            
        Examples:
            >>> # Find a campaign first
            >>> campaigns = manager.get_object_by_attack_id("C0024", "campaign")
            >>> # Find which groups are attributed to it
            >>> groups = manager.get_groups_attributing_to_campaign(campaigns.id)
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            groups = attack_data.get_groups_attributing_to_campaign(campaign_stix_id)
            return groups if groups else []
        except Exception:
            return []
        

    #####################################################################
    # Software functions
    #####################################################################

    def get_software_by_alias(
        self,
        alias: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get software/malware by their alias.
        
        Many software/malware have multiple aliases or names.
        
        Args:
            alias: Software alias to search for
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of matching software objects (may be empty)
            
        Examples:
            >>> manager.get_software_by_alias("Beacon")  # Finds Cobalt Strike
            >>> manager.get_software_by_alias("Mimilib")  # Finds Mimikatz
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            software = attack_data.get_software_by_alias(alias)
            return software if software else []
        except Exception:
            return []


    def get_software_using_technique(
        self,
        technique_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all software that use a specific technique.
        
        This is a reverse lookup: Technique → Software
        
        Args:
            technique_stix_id: Technique STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of software objects that use this technique
            
        Examples:
            >>> tech = manager.get_technique_by_id("T1055")  # Process Injection
            >>> software = manager.get_software_using_technique(tech.id)
            >>> # Returns: Cobalt Strike, Mimikatz, etc.
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            software = attack_data.get_software_using_technique(technique_stix_id)
            return software if software else []
        except Exception:
            return []
        
    def get_techniques_used_by_software(
        self,
        software_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all techniques used by specific software/malware.
        
        Shows what techniques the software is capable of performing.
        
        Args:
            software_stix_id: Software STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of technique objects used by this software
            
        Examples:
            >>> software = manager.search_software("Cobalt Strike")[0]
            >>> techniques = manager.get_techniques_used_by_software(software.id)
            >>> # Returns: Process Injection, Command and Control, etc.
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            techniques = attack_data.get_techniques_used_by_software(software_stix_id)
            return techniques if techniques else []
        except Exception:
            return []

    #####################################################################
    # "Get All" functions for MITRE ATT&CK objects
    #####################################################################
    def get_all_techniques(
        self,
        domain: str = "enterprise",
        remove_revoked_deprecated: bool = True
        ) -> List[Any]:
        """
        Get all techniques in a domain.
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            remove_revoked_deprecated: Exclude revoked/deprecated techniques (default: True)
            
        Returns:
            List of all technique objects in the domain
            
        Examples:
            >>> techniques = manager.get_all_techniques()
            >>> print(f"Total techniques: {len(techniques)}")
        """
        attack_data = self.get_attack_data(domain)
        techniques = attack_data.get_techniques(remove_revoked_deprecated=remove_revoked_deprecated)
        return techniques

    def get_all_subtechniques(
        self,
        domain: str = "enterprise",
        remove_revoked_deprecated: bool = True
        ) -> List[Any]:
        """
        Get all subtechniques in a domain.
        
        Subtechniques are more specific versions of parent techniques.
        For example: T1566.001, T1566.002 are subtechniques of T1566.
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            remove_revoked_deprecated: Exclude revoked/deprecated (default: True)
            
        Returns:
            List of subtechnique objects (only those with parent techniques)
            
        Examples:
            >>> subtechniques = manager.get_all_subtechniques()
            >>> # Returns: T1566.001, T1566.002, T1053.005, etc.
        """
        attack_data = self.get_attack_data(domain)
        
        # Get all techniques including subtechniques
        all_techniques = attack_data.get_techniques(
            remove_revoked_deprecated=remove_revoked_deprecated,
            include_subtechniques=True
        )
        
        # Filter to only subtechniques (those with a parent)
        subtechniques = [
            t for t in all_techniques
            if attack_data.get_parent_technique_of_subtechnique(t.id)
        ]
        
        return subtechniques

    def get_all_parent_techniques(
        self,
        domain: str = "enterprise",
        remove_revoked_deprecated: bool = True
        ) -> List[Any]:
        """
        Get all parent techniques (exclude subtechniques).
        
        Parent techniques are the main techniques without a dot in their ID.
        For example: T1566 (not T1566.001)
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            remove_revoked_deprecated: Exclude revoked/deprecated (default: True)
            
        Returns:
            List of parent technique objects only
            
        Examples:
            >>> parents = manager.get_all_parent_techniques()
            >>> # Returns: T1566, T1055, T1053, etc. (no T1566.001)
        """
        attack_data = self.get_attack_data(domain)
        
        # Get all techniques (excluding subtechniques by default)
        techniques = attack_data.get_techniques(
            remove_revoked_deprecated=remove_revoked_deprecated
        )
        
        # Filter to only parent techniques (no dot in ATT&CK ID)
        parent_techniques = [
            t for t in techniques 
            if "." not in attack_data.get_attack_id(t.id)
        ]
        
        return parent_techniques
    
    def get_all_groups(
        self,
        domain: str = "enterprise",
        remove_revoked_deprecated: bool = True
        ) -> List[Any]:
        """
        Get all APT groups/threat actors in a domain.
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            remove_revoked_deprecated: Exclude revoked/deprecated (default: True)
            
        Returns:
            List of all group objects
            
        Examples:
            >>> groups = manager.get_all_groups()
            >>> print(f"Total APT groups: {len(groups)}")
        """
        attack_data = self.get_attack_data(domain)
        groups = attack_data.get_groups(remove_revoked_deprecated=remove_revoked_deprecated)
        return groups

    def get_all_software(
        self,
        domain: str = "enterprise",
        remove_revoked_deprecated: bool = True
        ) -> List[Any]:
        """
        Get all software/malware/tools in a domain.
        
        Alias for get_software() for naming consistency.
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            remove_revoked_deprecated: Exclude revoked/deprecated (default: True)
            
        Returns:
            List of all software objects (malware and tools)
        """
        return self.get_software(domain)

    def get_all_mitigations(
        self,
        domain: str = "enterprise",
        remove_revoked_deprecated: bool = True
        ) -> List[Any]:
        """
        Get all mitigations (defensive countermeasures) in a domain.
        
        Mitigations are security controls or practices that can reduce
        the effectiveness of adversary techniques.
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            remove_revoked_deprecated: Exclude revoked/deprecated (default: True)
            
        Returns:
            List of all mitigation objects
            
        Examples:
            >>> mitigations = manager.get_all_mitigations()
            >>> # Returns: M1013 (Application Developer Guidance), M1017 (User Training), etc.
        """
        attack_data = self.get_attack_data(domain)
        mitigations = attack_data.get_mitigations(remove_revoked_deprecated=remove_revoked_deprecated)
        return mitigations

    def get_all_tactics(self, domain: str = "enterprise") -> List[Any]:
        """
        Get all tactics for a domain.
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of tactic objects
        """
        attack_data = self.get_attack_data(domain)
        tactics = attack_data.get_tactics(remove_revoked_deprecated=True)
        return tactics
    
    def get_all_matrices(
        self,
        domain: str = "enterprise",
        remove_revoked_deprecated: bool = True
        ) -> List[Any]:
        """
        Get all matrices in a domain.
        
        Matrices are the top-level organizational structures in ATT&CK.
        Each domain typically has one or more matrices (e.g., Enterprise ATT&CK matrix).
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            remove_revoked_deprecated: Exclude revoked/deprecated (default: True)
            
        Returns:
            List of matrix objects
            
        Examples:
            >>> matrices = manager.get_all_matrices("enterprise")
            >>> # Returns: Enterprise ATT&CK matrix
        """
        attack_data = self.get_attack_data(domain)
        matrices = attack_data.get_matrices(remove_revoked_deprecated=remove_revoked_deprecated)
        return matrices

    def get_all_campaigns(
        self,
        domain: str = "enterprise",
        remove_revoked_deprecated: bool = True
        ) -> List[Any]:
        """
        Get all campaigns in a domain.
        
        Campaigns are specific operations or intrusion sets carried out by threat actors.
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            remove_revoked_deprecated: Exclude revoked/deprecated (default: True)
            
        Returns:
            List of campaign objects
            
        Examples:
            >>> campaigns = manager.get_all_campaigns()
            >>> # Returns: SolarWinds compromise, etc.
        """
        attack_data = self.get_attack_data(domain)
        campaigns = attack_data.get_campaigns(remove_revoked_deprecated=remove_revoked_deprecated)
        return campaigns

    def get_all_datasources(
        self,
        domain: str = "enterprise",
        remove_revoked_deprecated: bool = True
        ) -> List[Any]:
        """
        Get all data sources in a domain.
        
        Data sources represent sources of information that can be used to detect
        adversary behavior (e.g., Process Monitoring, Network Traffic, File Monitoring).
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            remove_revoked_deprecated: Exclude revoked/deprecated (default: True)
            
        Returns:
            List of data source objects
            
        Examples:
            >>> datasources = manager.get_all_datasources()
            >>> # Returns: Process Monitoring, Network Traffic, etc.
        """
        attack_data = self.get_attack_data(domain)
        datasources = attack_data.get_datasources(remove_revoked_deprecated=remove_revoked_deprecated)
        return datasources

    def get_all_datacomponents(
        self,
        domain: str = "enterprise",
        remove_revoked_deprecated: bool = True
        ) -> List[Any]:
        """
        Get all data components in a domain.
        
        Data components are specific aspects of a data source that can be monitored.
        For example, the "Process" data source has components like "Process Creation",
        "Process Termination", etc.
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            remove_revoked_deprecated: Exclude revoked/deprecated (default: True)
            
        Returns:
            List of data component objects
            
        Note:
            Data components reference their parent data source via x_mitre_data_source_ref
            
        Examples:
            >>> components = manager.get_all_datacomponents()
            >>> # Returns: Process Creation, File Modification, Network Connection, etc.
        """
        attack_data = self.get_attack_data(domain)
        datacomponents = attack_data.get_datacomponents(remove_revoked_deprecated=remove_revoked_deprecated)
        return datacomponents

    def get_all_assets(
        self,
        domain: str = "ics",
        remove_revoked_deprecated: bool = True
        ) -> List[Any]:
        """
        Get all assets (ICS domain only).
        
        Assets represent industrial control system components such as PLCs,
        SCADA systems, HMIs, Safety Instrumented Systems, etc.
        
        Args:
            domain: Domain to search in (typically 'ics')
            remove_revoked_deprecated: Exclude revoked/deprecated (default: True)
            
        Returns:
            List of asset objects
            
        Note:
            Assets are primarily found in the ICS (Industrial Control Systems) domain.
            
        Examples:
            >>> assets = manager.get_all_assets("ics")
            >>> # Returns: Control Server, Engineering Workstation, HMI, PLC, etc.
        """
        attack_data = self.get_attack_data(domain)
        assets = attack_data.get_assets(remove_revoked_deprecated=remove_revoked_deprecated)
        return assets

    #####################################################################
    # Campaign functions
    #####################################################################

    def get_campaigns_using_technique(
        self,
        technique_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all campaigns that use a specific technique.
        
        This is a reverse lookup: Technique → Campaigns
        
        Args:
            technique_stix_id: Technique STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of campaign objects that use this technique
            
        Examples:
            >>> tech = manager.get_technique_by_id("T1566")  # Phishing
            >>> campaigns = manager.get_campaigns_using_technique(tech.id)
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            campaigns = attack_data.get_campaigns_using_technique(technique_stix_id)
            return campaigns if campaigns else []
        except Exception:
            return []

    def get_techniques_used_by_campaign(
        self,
        campaign_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all techniques used in a specific campaign.
        
        Args:
            campaign_stix_id: Campaign STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of technique objects used in this campaign
            
        Examples:
            >>> # Find a campaign first
            >>> campaigns = manager.get_all_campaigns()
            >>> campaign = campaigns[0]
            >>> # Get techniques used in it
            >>> techniques = manager.get_techniques_used_by_campaign(campaign.id)
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            techniques = attack_data.get_techniques_used_by_campaign(campaign_stix_id)
            return techniques if techniques else []
        except Exception:
            return []

    def get_campaigns_using_software(
        self,
        software_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all campaigns that use specific software/malware.
        
        This is a reverse lookup: Software → Campaigns
        
        Args:
            software_stix_id: Software STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of campaign objects that use this software
            
        Examples:
            >>> software = manager.search_software("Cobalt Strike")[0]
            >>> campaigns = manager.get_campaigns_using_software(software.id)
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            campaigns = attack_data.get_campaigns_using_software(software_stix_id)
            return campaigns if campaigns else []
        except Exception:
            return []

    def get_software_used_by_campaign(
        self,
        campaign_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all software/malware used in a specific campaign.
        
        Args:
            campaign_stix_id: Campaign STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of software objects used in this campaign
            
        Examples:
            >>> campaigns = manager.get_all_campaigns()
            >>> campaign = campaigns[0]
            >>> software = manager.get_software_used_by_campaign(campaign.id)
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            software = attack_data.get_software_used_by_campaign(campaign_stix_id)
            return software if software else []
        except Exception:
            return []

    #####################################################################
    # Technique functions
    #####################################################################

    def get_techniques_by_platform(
        self,
        platform: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all techniques that apply to a specific platform.
        
        Args:
            platform: Platform name (e.g., 'Windows', 'Linux', 'macOS', 'Cloud', 
                    'Network', 'Containers', 'IaaS', 'SaaS', etc.)
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of technique objects applicable to this platform
            
        Examples:
            >>> windows_techniques = manager.get_techniques_by_platform("Windows")
            >>> linux_techniques = manager.get_techniques_by_platform("Linux")
            >>> cloud_techniques = manager.get_techniques_by_platform("Azure AD")
        """
        attack_data = self.get_attack_data(domain)
        techniques = attack_data.get_techniques_by_platform(platform)
        return techniques

    def get_parent_technique_of_subtechnique(
        self,
        technique_stix_id: str,
        domain: str = "enterprise"
        ) -> Optional[Any]:
        """
        Get the parent technique of a subtechnique.
        
        Navigates the technique hierarchy to find the parent.
        
        Args:
            technique_stix_id: Subtechnique STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            Parent technique object, or None if not a subtechnique
            
        Examples:
            >>> # T1566.001 is Spearphishing Attachment
            >>> subtech = manager.get_technique_by_id("T1566.001")
            >>> parent = manager.get_parent_technique_of_subtechnique(subtech.id)
            >>> # Returns T1566 (Phishing)
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            parent_stix_id = attack_data.get_parent_technique_of_subtechnique(technique_stix_id)
            if parent_stix_id:
                parent = attack_data.get_object_by_stix_id(parent_stix_id)
                return parent
            return None
        except Exception:
            return None

    def get_subtechniques_of_technique(
        self,
        technique_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all subtechniques of a parent technique.
        
        Args:
            technique_stix_id: Parent technique STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of subtechnique objects for this parent technique
            
        Examples:
            >>> # T1566 is Phishing
            >>> tech = manager.get_technique_by_id("T1566")
            >>> subtechs = manager.get_subtechniques_of_technique(tech.id)
            >>> # Returns: T1566.001, T1566.002, T1566.003, T1566.004
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            subtechniques = attack_data.get_subtechniques_of_technique(technique_stix_id)
            return subtechniques if subtechniques else []
        except Exception:
            return []

    #####################################################################
    # Mitigation functions
    #####################################################################

    def get_techniques_mitigated_by_mitigation(
        self,
        mitigation_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all techniques that are mitigated by a specific mitigation.
        
        Shows which adversary techniques this defensive control addresses.
        
        Args:
            mitigation_stix_id: Mitigation STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of technique objects mitigated by this control
            
        Examples:
            >>> # M1017 is User Training
            >>> mitigations = manager.get_all_mitigations()
            >>> user_training = [m for m in mitigations if "User Training" in m.name][0]
            >>> techniques = manager.get_techniques_mitigated_by_mitigation(user_training.id)
            >>> # Returns: Phishing, User Execution, etc.
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            techniques = attack_data.get_techniques_mitigated_by_mitigation(mitigation_stix_id)
            return techniques if techniques else []
        except Exception:
            return []

    def get_mitigations_mitigating_technique(
        self,
        technique_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all mitigations that address a specific technique.
        
        Shows which defensive controls can reduce the effectiveness of this technique.
        
        Args:
            technique_stix_id: Technique STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of mitigation objects that address this technique
            
        Examples:
            >>> tech = manager.get_technique_by_id("T1566")  # Phishing
            >>> mitigations = manager.get_mitigations_mitigating_technique(tech.id)
            >>> # Returns: User Training, Software Configuration, etc.
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            mitigations = attack_data.get_mitigations_mitigating_technique(technique_stix_id)
            return mitigations if mitigations else []
        except Exception:
            return []

    #####################################################################
    # Data component and detection functions
    #####################################################################

    def get_datacomponents_detecting_technique(
        self,
        technique_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all data components that can detect a specific technique.
        
        Data components represent specific aspects of telemetry that can be used
        to detect adversary behavior.
        
        Args:
            technique_stix_id: Technique STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of data component objects (as dicts with 'object' and 'relationships' keys)
            that can detect this technique
            
        Examples:
            >>> tech = manager.get_technique_by_id("T1055")  # Process Injection
            >>> components = manager.get_datacomponents_detecting_technique(tech.id)
            >>> # Returns: Process Access, OS API Execution, etc.
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            datacomponents = attack_data.get_datacomponents_detecting_technique(technique_stix_id)
            return datacomponents if datacomponents else []
        except Exception:
            return []

    def get_techniques_detected_by_datacomponent(
        self,
        datacomponent_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all techniques that can be detected by a specific data component.
        
        Shows which adversary techniques can be identified by monitoring
        this specific aspect of telemetry.
        
        Args:
            datacomponent_stix_id: Data component STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of technique objects that can be detected by this data component
            
        Examples:
            >>> # Find "Process Creation" data component
            >>> components = manager.get_all_datacomponents()
            >>> proc_creation = [c for c in components if "Process Creation" in c.name][0]
            >>> techniques = manager.get_techniques_detected_by_datacomponent(proc_creation.id)
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            techniques = attack_data.get_techniques_detected_by_datacomponent(datacomponent_stix_id)
            return techniques if techniques else []
        except Exception:
            return []

    def get_procedure_examples_by_technique(
        self,
        technique_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get procedure examples showing how groups use a specific technique.
        
        Procedure examples are real-world instances of how threat actors
        have applied a technique in their operations.
        
        Args:
            technique_stix_id: Technique STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of procedure example objects (relationships showing usage)
            
        Examples:
            >>> tech = manager.get_technique_by_id("T1566")  # Phishing
            >>> examples = manager.get_procedure_examples_by_technique(tech.id)
            >>> # Returns: How APT29, APT28, etc. used phishing
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            procedure_examples = attack_data.get_procedure_examples_by_technique(technique_stix_id)
            return procedure_examples if procedure_examples else []
        except Exception:
            return []

    def get_assets_targeted_by_technique(
        self,
        technique_stix_id: str,
        domain: str = "ics"
        ) -> List[Any]:
        """
        Get all assets targeted by a specific technique (ICS domain only).
        
        Shows which industrial control system components are vulnerable to
        this technique.
        
        Args:
            technique_stix_id: Technique STIX UUID identifier
            domain: Domain to search in (typically 'ics')
            
        Returns:
            List of asset objects targeted by this technique
            
        Examples:
            >>> # Load ICS domain first
            >>> manager.load_domain("ics")
            >>> tech = manager.get_technique_by_id("T0883", "ics")
            >>> assets = manager.get_assets_targeted_by_technique(tech.id, "ics")
            >>> # Returns: Control Server, HMI, etc.
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            assets = attack_data.get_assets_targeted_by_technique(technique_stix_id)
            return assets if assets else []
        except Exception:
            return []
        
    def get_campaigns_by_alias(
        self,
        alias: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get campaigns by their alias.
        
        Campaigns often have multiple names or aliases from different
        threat intelligence sources.
        
        Args:
            alias: Campaign alias to search for
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of matching campaign objects (may be empty)
            
        Examples:
            >>> campaigns = manager.get_campaigns_by_alias("SolarWinds")
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            campaigns = attack_data.get_campaigns_by_alias(alias)
            return campaigns if campaigns else []
        except Exception:
            return []

    def get_objects_by_type(
        self,
        stix_type: str,
        domain: str = "enterprise",
        remove_revoked_deprecated: bool = True
        ) -> List[Any]:
        """
        Get all objects of a specific STIX type.
        
        Generic method to retrieve objects by their type. Alternative to
        specific methods like get_all_techniques(), get_all_groups(), etc.
        
        Args:
            stix_type: STIX object type, must be one of:
                'attack-pattern', 'malware', 'tool', 'intrusion-set',
                'campaign', 'course-of-action', 'x-mitre-matrix', 
                'x-mitre-tactic', 'x-mitre-data-source', 
                'x-mitre-data-component', 'x-mitre-asset'
            domain: Domain to search in (default: 'enterprise')
            remove_revoked_deprecated: Exclude revoked/deprecated (default: True)
            
        Returns:
            List of objects of the specified type
            
        Examples:
            >>> techniques = manager.get_objects_by_type("attack-pattern")
            >>> groups = manager.get_objects_by_type("intrusion-set")
            >>> malware = manager.get_objects_by_type("malware")
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            objects = attack_data.get_objects_by_type(
                stix_type,
                remove_revoked_deprecated=remove_revoked_deprecated
            )
            return objects if objects else []
        except Exception:
            return []

    def get_tactics_by_matrix(
        self,
        matrix_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all tactics that belong to a specific matrix.
        
        Shows the tactical categories within a matrix.
        
        Args:
            matrix_stix_id: Matrix STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of tactic objects in this matrix
            
        Examples:
            >>> matrices = manager.get_all_matrices()
            >>> matrix = matrices[0]  # Enterprise ATT&CK matrix
            >>> tactics = manager.get_tactics_by_matrix(matrix.id)
            >>> # Returns: Initial Access, Execution, Persistence, etc.
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            tactics = attack_data.get_tactics_by_matrix(matrix_stix_id)
            return tactics if tactics else []
        except Exception:
            return []

    def get_tactics_by_technique(
        self,
        technique_stix_id: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all tactics associated with a specific technique.
        
        Techniques can belong to one or more tactics (kill chain phases).
        
        Args:
            technique_stix_id: Technique STIX UUID identifier
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of tactic objects associated with this technique
            
        Examples:
            >>> tech = manager.get_technique_by_id("T1566")  # Phishing
            >>> tactics = manager.get_tactics_by_technique(tech.id)
            >>> # Returns: Initial Access
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            tactics = attack_data.get_tactics_by_technique(technique_stix_id)
            return tactics if tactics else []
        except Exception:
            return []

    def get_procedure_examples_by_tactic(
        self,
        tactic: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all procedure examples for techniques in a specific tactic.
        
        Shows real-world examples of how groups use techniques within
        this tactical category.
        
        Args:
            tactic: Tactic name (e.g., 'Initial Access', 'Persistence')
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of procedure example objects (relationships)
            
        Examples:
            >>> examples = manager.get_procedure_examples_by_tactic("Initial Access")
            >>> # Returns: How groups use phishing, exploits, etc.
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            procedure_examples = attack_data.get_procedure_examples_by_tactic(tactic)
            return procedure_examples if procedure_examples else []
        except Exception:
            return []

    def get_techniques_targeting_asset(
        self,
        asset_stix_id: str,
        domain: str = "ics"
        ) -> List[Any]:
        """
        Get all techniques that target a specific asset (ICS domain only).
        
        Shows which adversary techniques can affect this industrial
        control system component.
        
        Args:
            asset_stix_id: Asset STIX UUID identifier
            domain: Domain to search in (typically 'ics')
            
        Returns:
            List of technique objects that target this asset
            
        Examples:
            >>> manager.load_domain("ics")
            >>> assets = manager.get_all_assets("ics")
            >>> control_server = assets[0]
            >>> techniques = manager.get_techniques_targeting_asset(control_server.id, "ics")
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            techniques = attack_data.get_techniques_targeting_asset(asset_stix_id)
            return techniques if techniques else []
        except Exception:
            return []

    def get_objects_created_after(
        self,
        timestamp: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all objects created after a specific timestamp.
        
        Useful for tracking new additions to the ATT&CK framework.
        
        Args:
            timestamp: ISO format timestamp string (e.g., '2024-01-01T00:00:00Z')
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of objects created after the specified time
            
        Examples:
            >>> # Get everything added since Jan 2024
            >>> new_objects = manager.get_objects_created_after("2024-01-01T00:00:00Z")
            >>> 
            >>> # Get everything from the last 6 months
            >>> from datetime import datetime, timedelta
            >>> six_months_ago = (datetime.now() - timedelta(days=180)).isoformat() + "Z"
            >>> recent = manager.get_objects_created_after(six_months_ago)
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            objects = attack_data.get_objects_created_after(timestamp)
            return objects if objects else []
        except Exception:
            return []

    def get_objects_modified_after(
        self,
        timestamp: str,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all objects modified after a specific timestamp.
        
        Useful for tracking updates and changes to the ATT&CK framework.
        
        Args:
            timestamp: ISO format timestamp string (e.g., '2024-01-01T00:00:00Z')
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of objects modified after the specified time
            
        Examples:
            >>> # Get everything updated since Jan 2024
            >>> updated = manager.get_objects_modified_after("2024-01-01T00:00:00Z")
            >>> 
            >>> # Track what changed recently
            >>> recent = manager.get_objects_modified_after("2024-06-01T00:00:00Z")
        """
        attack_data = self.get_attack_data(domain)
        
        try:
            objects = attack_data.get_objects_modified_after(timestamp)
            return objects if objects else []
        except Exception:
            return []

    def get_revoked_techniques(
        self,
        domain: str = "enterprise"
        ) -> List[Any]:
        """
        Get all revoked techniques.
        
        Revoked techniques have been removed from the framework, often
        because they were merged with others or are no longer valid.
        
        Args:
            domain: Domain to search in (default: 'enterprise')
            
        Returns:
            List of revoked technique objects
        """
        attack_data = self.get_attack_data(domain)
        
        # Get ALL techniques (including revoked)
        all_techniques = attack_data.get_techniques(remove_revoked_deprecated=False)
        
        # Filter to only revoked ones
        revoked = [
            tech for tech in all_techniques
            if hasattr(tech, 'revoked') and tech.revoked
        ]
        
        return revoked

    #####################################################################
    # Layer generation functions
    #####################################################################

    def generate_layer(
        self,
        attack_id: str,
        score: int = 1,
        domain: str = "enterprise"
    ) -> dict:
        """Generate an ATT&CK Navigator layer for visualization."""
        import re
        from mitreattack.navlayers import UsageLayerGenerator
        from mitreattack import release_info
        from pathlib import Path
        
        # Validate attack_id format
        if not re.match(r"^[GMSD]\d+$", attack_id):
            raise ValueError(
                f"Invalid ATT&CK ID format: '{attack_id}'. "
                "Must be GXXX (group), MXXX (mitigation), SXXX (software), or DXXX (data component). "
                "Technique IDs (TXXX) are not supported."
            )
        
        # Use the actual data directory path from download.py
        import os
        data_dir = Path(os.getenv(
            "MITRE_MCP_DATA_DIR",
            Path.home() / ".mitre-mcp-server" / "data"
        ))
        
        domain_key = f"{domain}-attack"
        stix_path = data_dir / f"v{release_info.LATEST_VERSION}" / f"{domain_key}.json"
        
        if not stix_path.exists():
            raise FileNotFoundError(
                f"STIX data file not found: {stix_path}. "
                "Run download script first."
            )
        
        # Generate layer
        try:
            generator = UsageLayerGenerator(
                source="local",
                domain=domain,
                resource=str(stix_path)
            )
            
            layer = generator.generate_layer(match=attack_id)
            
            if not layer or not layer.layer or not layer.layer.techniques:
                raise ValueError(f"No techniques found for '{attack_id}' in '{domain}' domain")
            
            # Filter techniques with score > 0 and apply new score
            layer.layer.techniques = [t for t in layer.layer.techniques if t.score > 0]
            for technique in layer.layer.techniques:
                technique.score = score
            
            return layer.to_dict()
            
        except Exception as e:
            raise RuntimeError(f"Failed to generate layer: {str(e)}")

    def get_layer_metadata(self, domain: str = "enterprise") -> dict:
        """
        Get ATT&CK Navigator layer metadata template.
        
        Provides the base structure and configuration for a layer,
        including domain-specific settings, colors, and filters.
        
        Args:
            domain: Domain name ('enterprise', 'mobile', or 'ics')
            
        Returns:
            Dictionary containing layer metadata template
            
        Examples:
            >>> metadata = manager.get_layer_metadata("enterprise")
            >>> # Use this as template when creating custom layers
        """
        # Base metadata template
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
        
        # Domain-specific configurations
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
        
        # Validate domain and default to enterprise if invalid
        domain = domain.lower()
        if domain not in domain_configs:
            domain = "enterprise"
        
        # Merge base metadata with domain config
        metadata = base_metadata.copy()
        metadata.update(domain_configs[domain])
        
        return metadata


# Global singleton instance
_manager: Optional[MITREDataManager] = None


def get_manager() -> MITREDataManager:
    """
    Get the global MITREDataManager singleton instance.
    
    Returns:
        MITREDataManager instance
    """
    global _manager
    if _manager is None:
        _manager = MITREDataManager()
    return _manager