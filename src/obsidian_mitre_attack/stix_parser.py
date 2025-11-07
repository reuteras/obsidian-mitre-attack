"""StixParser class to get and parse STIX data."""

from __future__ import annotations

import sys
import time as time_module
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from stix2 import Filter, MemoryStore

from .models import (
    MITREAsset,
    MITRECampaign,
    MITREDataSource,
    MITREGroup,
    MITREMitigation,
    MITRESoftware,
    MITRETactic,
    MITRETechnique,
)


class StixParser:
    """Get and parse STIX data creating Tactics and Techniques objects.

    Get the ATT&CK STIX data from MITRE/CTI GitHub repository.
    Domain should be 'enterprise-attack', 'mobile-attack', or 'ics-attack'.
    """

    def __init__(self, repo_url: str, version="15.1", verbose: bool = False) -> None:
        """Initialize the StixParser object."""
        self.url: str = repo_url
        self.version: str = version
        self.verbose: bool = verbose

        self.techniques = list()
        self.tactics = list()
        self.mitigations = list()

        self.verbose_log(
            message=f"Getting STIX data from {self.url} for version {self.version}"
        )

        # Parallelize STIX data downloads for all three domains
        domains = ["enterprise-attack", "mobile-attack", "ics-attack"]

        def download_domain(domain: str) -> tuple[str, dict]:
            """Download STIX data for a specific domain."""
            url = f"{self.url}/{domain}/{domain}-{version}.json"
            response = requests.get(url=url, timeout=30)
            return domain, response.json()

        # Download all domains in parallel using thread pool
        domain_data = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(download_domain, domain): domain for domain in domains
            }
            for future in as_completed(futures):
                domain, stix_json = future.result()
                domain_data[domain] = stix_json

        # Create MemoryStore instances for each domain
        self.enterprise_attack = MemoryStore(
            stix_data=domain_data["enterprise-attack"]["objects"]
        )
        self.mobile_attack = MemoryStore(
            stix_data=domain_data["mobile-attack"]["objects"]
        )
        self.ics_attack = MemoryStore(stix_data=domain_data["ics-attack"]["objects"])

        self.verbose_log(message="STIX data loaded successfully")

    def verbose_log(self, message) -> None:
        """Print a message if verbose mode is enabled."""
        if self.verbose:
            print(message, flush=True)

    @staticmethod
    def is_valid_stix_object(obj: dict) -> bool:
        """Check if STIX object is not deprecated or revoked.

        Args:
            obj: STIX object dictionary

        Returns:
            True if object is valid (not deprecated and not revoked), False otherwise
        """
        is_not_deprecated = (
            "x_mitre_deprecated" not in obj or not obj["x_mitre_deprecated"]
        )
        is_not_revoked = "revoked" not in obj or not obj["revoked"]
        return is_not_deprecated and is_not_revoked

    def get_domain_data(self, domain) -> None:
        """Get and parse tactics, techniques, and mitigations from STIX data."""
        if domain == "enterprise-attack":
            self.src: MemoryStore = self.enterprise_attack
        elif domain == "mobile-attack":
            self.src = self.mobile_attack
        elif domain == "ics-attack":
            self.src = self.ics_attack

        self.verbose_log(message=f"Getting tactics data for {domain} domain")
        self._get_tactics(domain=domain)
        self.verbose_log(message=f"Getting techniques data for {domain} domain")
        self._get_techniques(domain=domain)
        self.verbose_log(message=f"Getting mitigations data for {domain} domain")
        self._get_mitigations(domain=domain)

    def get_cti_data(self) -> None:
        """Get and parse from STIX data.

        Get and parse the following data from STIX data:
        - Groups
        - Campaigns
        - Software
        - Data sources
        - Assets
        """
        self.verbose_log(message="Getting data sources data")
        self._get_data_sources()
        self.verbose_log(message="Getting assets data")
        self._get_assets()
        self.verbose_log(message="Getting groups data")
        self._get_groups()
        self.verbose_log(message="Getting campaigns data")
        self._get_campaigns()
        self.verbose_log(message="Getting software data")
        self._get_software()
        self.verbose_log(message="CTI data loaded successfully")

    def _get_tactics(self, domain) -> None:  # noqa: PLR0912
        """Get and parse tactics from STIX data."""
        # Set the appropriate data source for the domain
        if domain == "enterprise-attack":
            self.src = self.enterprise_attack
        elif domain == "mobile-attack":
            self.src = self.mobile_attack
        elif domain == "ics-attack":
            self.src = self.ics_attack

        # Extract tactics
        tactics_stix = self.src.query(
            [Filter(prop="type", op="=", value="x-mitre-tactic")]
        )

        for tactic in tactics_stix:
            if self.is_valid_stix_object(tactic):
                tactic_obj = MITRETactic(name=tactic["name"])
                external_references_added = set()

                # Add attributes to the tactic object
                tactic_obj.description = tactic["description"]
                tactic_obj.created = tactic.get("created", "")
                tactic_obj.modified = tactic.get("modified", "")
                tactic_obj.version = tactic.get("x_mitre_version", [])
                tactic_obj.shortname = tactic.get("x_mitre_shortname", "")
                tactic_obj.domain = domain

                # Get external references for the description as well as the URL and external ID
                ext_refs = tactic.get("external_references", [])
                for ext_ref in ext_refs:
                    if ext_ref["source_name"] == "mitre-attack":
                        tactic_obj.id = ext_ref["external_id"]
                        tactic_obj.url = ext_ref["url"]
                    elif "url" in ext_ref and "description" in ext_ref:
                        item = {
                            "name": ext_ref["source_name"],
                            "url": ext_ref["url"],
                            "description": ext_ref["description"],
                        }
                        if ext_ref["source_name"] not in external_references_added:
                            tactic_obj.external_references = item
                            external_references_added.add(ext_ref["source_name"])

                # Get techniques used in this tactic
                techniques_stix = self.src.query(
                    [Filter(prop="type", op="=", value="attack-pattern")]
                )

                for technique in techniques_stix:
                    if self.is_valid_stix_object(technique):
                        kill_chain_phase = technique.get("kill_chain_phases", [])
                        for phase in kill_chain_phase:
                            if phase["phase_name"] == tactic_obj.shortname:
                                ext_refs = technique.get("external_references", [])
                                technique_id = ""
                                for ext_ref in ext_refs:
                                    if ext_ref["source_name"] == "mitre-attack":
                                        technique_id = ext_ref["external_id"]
                                        break
                                tactic_obj.techniques_used = {
                                    "id": technique_id,
                                    "name": technique["name"].replace("/", "／"),  # noqa: RUF001
                                    "description": technique["description"],
                                }

                self.tactics.append(tactic_obj)

    def _get_techniques(self, domain):  # noqa: PLR0912, PLR0915
        """Get and parse techniques from STIX data."""
        # Set the appropriate data source for the domain
        if domain == "enterprise-attack":
            self.src = self.enterprise_attack
        elif domain == "mobile-attack":
            self.src = self.mobile_attack
        elif domain == "ics-attack":
            self.src = self.ics_attack

        # Pre-cache all relationships and objects to avoid repeated queries
        print(f"Pre-caching relationships and objects for {domain} techniques...")
        cache_start = time_module.time()

        # Extract techniques
        techniques_stix = self.src.query([Filter("type", "=", "attack-pattern")])

        # Extract tactics to build relationship between techniques and tactics
        tactics_stix = self.src.query([Filter("type", "=", "x-mitre-tactic")])

        shortname_name = dict()
        shortname_id = dict()

        # Build a dictionary with shortname and name of the tactic
        for tactic in tactics_stix:
            ext_refs = tactic.get("external_references", [])
            for ext_ref in ext_refs:
                if ext_ref["source_name"] == "mitre-attack":
                    tactic_id = ext_ref["external_id"]
                    break
            shortname_name[tactic["x_mitre_shortname"]] = tactic["name"]
            shortname_id[tactic["x_mitre_shortname"]] = tactic_id

        # Cache all "uses" relationships by target_ref
        all_uses_relationships = self.src.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
            ]
        )
        uses_by_target = {}
        for rel in all_uses_relationships:
            target = rel.get("target_ref")
            if target:
                if target not in uses_by_target:
                    uses_by_target[target] = []
                uses_by_target[target].append(rel)

        # Cache all "mitigates" relationships by target_ref
        all_mitigates_relationships = self.src.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="mitigates"),
            ]
        )
        mitigates_by_target = {}
        for rel in all_mitigates_relationships:
            target = rel.get("target_ref")
            if target:
                if target not in mitigates_by_target:
                    mitigates_by_target[target] = []
                mitigates_by_target[target].append(rel)

        # Cache all "detects" relationships by target_ref
        all_detects_relationships = self.src.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="detects"),
            ]
        )
        detects_by_target = {}
        for rel in all_detects_relationships:
            target = rel.get("target_ref")
            if target:
                if target not in detects_by_target:
                    detects_by_target[target] = []
                detects_by_target[target].append(rel)

        # Cache all software (malware + tools) by ID
        all_malware = self.src.query([Filter(prop="type", op="=", value="malware")])
        all_tools = self.src.query([Filter(prop="type", op="=", value="tool")])
        software_cache = {}
        for soft in all_malware + all_tools:
            software_cache[soft["id"]] = soft

        # Cache all groups by ID
        all_groups = self.src.query(
            [Filter(prop="type", op="=", value="intrusion-set")]
        )
        group_cache = {}
        for group in all_groups:
            group_cache[group["id"]] = group

        # Cache all campaigns by ID
        all_campaigns = self.src.query([Filter(prop="type", op="=", value="campaign")])
        campaign_cache = {}
        for camp in all_campaigns:
            campaign_cache[camp["id"]] = camp

        # Cache all mitigations by ID
        all_mitigations = self.src.query(
            [Filter(prop="type", op="=", value="course-of-action")]
        )
        mitigation_cache = {}
        for mit in all_mitigations:
            mitigation_cache[mit["id"]] = mit

        # Cache all data components by ID
        all_data_components = self.src.query(
            [Filter(prop="type", op="=", value="x-mitre-data-component")]
        )
        data_component_cache = {}
        for dc in all_data_components:
            data_component_cache[dc["id"]] = dc

        # Cache all data sources by ID
        all_data_sources = self.src.query(
            [Filter(prop="type", op="=", value="x-mitre-data-source")]
        )
        data_source_cache = {}
        for ds in all_data_sources:
            data_source_cache[ds["id"]] = ds

        # Build subtechniques cache by main_id
        subtechniques_by_main_id = {}
        for tech in techniques_stix:
            if tech.get("x_mitre_is_subtechnique"):
                ext_refs = tech.get("external_references", [])
                for ext_ref in ext_refs:
                    if ext_ref["source_name"] == "mitre-attack":
                        sub_id = ext_ref["external_id"]
                        main_id = sub_id.split(".")[0]
                        if main_id not in subtechniques_by_main_id:
                            subtechniques_by_main_id[main_id] = []
                        subtechniques_by_main_id[main_id].append(tech)
                        break

        print(f"  Cache built in {time_module.time() - cache_start:.2f}s")

        # Extract techniques
        for tech in techniques_stix:
            if (
                "x_mitre_deprecated" not in tech or not tech["x_mitre_deprecated"]
            ) and ("revoked" not in tech or not tech["revoked"]):
                technique_obj = MITRETechnique(name=tech["name"])
                mitigations_added = set()
                detections_added = set()
                targeted_assets_added = set()
                external_references_added = set()

                # Add attributes to the technique object
                technique_obj.internal_id = tech["id"]
                technique_obj.is_subtechnique = tech["x_mitre_is_subtechnique"]
                technique_obj.platforms = tech.get("x_mitre_platforms", [])
                technique_obj.effective_permissions = tech.get(
                    "x_mitre_effective_permissions", []
                )
                technique_obj.permissions_required = tech.get(
                    "x_mitre_permissions_required", []
                )
                technique_obj.description = tech["description"]
                technique_obj.defense_bypassed = tech.get(
                    "x_mitre_defense_bypassed", []
                )
                technique_obj.data_sources = tech.get("x_mitre_data_sources", [])
                technique_obj.created = tech.get("created", "")
                technique_obj.modified = tech.get("modified", "")
                technique_obj.version = tech.get("x_mitre_version", [])
                technique_obj.detection = tech.get("x_mitre_detection", "")
                technique_obj.tactic_name = shortname_name[
                    tech["kill_chain_phases"][0]["phase_name"]
                ]
                technique_obj.tactic_id = shortname_id[
                    tech["kill_chain_phases"][0]["phase_name"]
                ]
                technique_obj.supports_remote = tech.get(
                    "x_mitre_remote_support", False
                )
                technique_obj.domain = domain

                # Get external references
                ext_refs = tech.get("external_references", [])
                for ext_ref in ext_refs:
                    if ext_ref["source_name"] == "mitre-attack":
                        technique_obj.id = ext_ref["external_id"]
                        technique_obj.url = ext_ref["url"]
                    elif "url" in ext_ref and "description" in ext_ref:
                        item = {
                            "name": ext_ref["source_name"],
                            "url": ext_ref["url"],
                            "description": ext_ref["description"],
                        }
                        if ext_ref["source_name"] not in external_references_added:
                            technique_obj.external_references = item
                            external_references_added.add(ext_ref["source_name"])

                # Get technique main id
                if technique_obj.is_subtechnique:
                    technique_obj.main_id = technique_obj.id.split(".")[0]
                else:
                    technique_obj.main_id = technique_obj.id

                # Procedure examples (using cache)
                procedure_examples_stix = uses_by_target.get(
                    technique_obj.internal_id, []
                )
                for relation in procedure_examples_stix:
                    if (
                        "x_mitre_deprecated" not in relation
                        or not relation["x_mitre_deprecated"]
                    ) and ("revoked" not in relation or not relation["revoked"]):
                        if "external_references" in relation:
                            ext_refs = relation.get("external_references", [])
                            for ext_ref in ext_refs:
                                if "url" in ext_ref and "description" in ext_ref:
                                    item = {
                                        "name": ext_ref["source_name"],
                                        "url": ext_ref["url"],
                                        "description": ext_ref["description"],
                                    }
                                    if (
                                        ext_ref["source_name"]
                                        not in external_references_added
                                    ):
                                        technique_obj.external_references = item
                                        external_references_added.add(
                                            ext_ref["source_name"]
                                        )

                        # Use cache instead of queries
                        source = None
                        source_ref = relation["source_ref"]
                        if "malware" in source_ref or "tool" in source_ref:
                            source = software_cache.get(source_ref)
                        elif "intrusion-set" in source_ref:
                            source = group_cache.get(source_ref)
                        elif "campaign" in source_ref:
                            source = campaign_cache.get(source_ref)
                        else:
                            sys.exit(f"Unknown source type: {source_ref}")

                        if source:
                            if (
                                "x_mitre_deprecated" not in source
                                or not source["x_mitre_deprecated"]
                            ) and ("revoked" not in source or not source["revoked"]):
                                source_id: str = ""
                                ext_refs = source.get("external_references", [])
                                for ext_ref in ext_refs:
                                    if ext_ref["source_name"] == "mitre-attack":
                                        source_id = ext_ref["external_id"]
                                    elif "url" in ext_ref and "description" in ext_ref:
                                        item = {
                                            "name": ext_ref["source_name"],
                                            "url": ext_ref["url"],
                                            "description": ext_ref["description"],
                                        }
                                        if (
                                            ext_ref["source_name"]
                                            not in external_references_added
                                        ):
                                            technique_obj.external_references = item
                                            external_references_added.add(
                                                ext_ref["source_name"]
                                            )

                                technique_obj.procedure_examples = {
                                    "name": source["name"],
                                    "id": source_id,
                                    "description": relation.get("description", ""),
                                }

                # Mitigations (using cache)
                mitigations_relationships = mitigates_by_target.get(
                    technique_obj.internal_id, []
                )
                for relation in mitigations_relationships:
                    ext_refs = relation.get("external_references", [])
                    for ext_ref in ext_refs:
                        if "url" in ext_ref and "description" in ext_ref:
                            item = {
                                "name": ext_ref["source_name"],
                                "url": ext_ref["url"],
                                "description": ext_ref["description"],
                            }
                            if ext_ref["source_name"] not in external_references_added:
                                technique_obj.external_references = item
                                external_references_added.add(ext_ref["source_name"])
                    # Get mitigation id (using cache)
                    mitigation = mitigation_cache.get(relation["source_ref"])
                    if not mitigation:
                        continue
                    mitigation_id = ""
                    ext_refs = mitigation.get("external_references", [])
                    for ext_ref in ext_refs:
                        if ext_ref["source_name"] == "mitre-attack":
                            mitigation_id = ext_ref["external_id"]
                    description = relation.get("description", "")
                    item = {
                        "name": mitigation.get("name").replace("/", "／"),  # noqa: RUF001
                        "description": description,
                        "id": mitigation_id,
                    }
                    if (
                        mitigation_id not in mitigations_added
                        and (
                            "x_mitre_deprecated" not in mitigation
                            or not mitigation["x_mitre_deprecated"]
                        )
                        and ("revoked" not in mitigation or not mitigation["revoked"])
                    ):
                        technique_obj.mitigations = item
                        mitigations_added.add(mitigation_id)

                # Detection (using cache)
                detections_relationships = detects_by_target.get(
                    technique_obj.internal_id, []
                )
                for relation in detections_relationships:
                    data_component = data_component_cache.get(relation["source_ref"])

                    # Set defaults in case lookups fail
                    data_component_name = "Unknown"
                    data_source_name = "Unknown"
                    data_source_id = ""

                    if data_component:
                        data_component_name = data_component.get("name", "Unknown")
                        data_component_source_ref = data_component.get(
                            "x_mitre_data_source_ref", ""
                        )

                        if data_component_source_ref:
                            data_source = data_source_cache.get(
                                data_component_source_ref
                            )

                            if data_source:
                                data_source_name = data_source.get("name", "Unknown")
                                ext_refs = data_source.get("external_references", [])

                                for ext_ref in ext_refs:
                                    if ext_ref["source_name"] == "mitre-attack":
                                        data_source_id = ext_ref["external_id"]
                                    if "url" in ext_ref and "description" in ext_ref:
                                        item = {
                                            "name": ext_ref["source_name"],
                                            "url": ext_ref["url"],
                                            "description": ext_ref["description"],
                                        }
                                        if (
                                            ext_ref["source_name"]
                                            not in external_references_added
                                        ):
                                            technique_obj.external_references = item
                                            external_references_added.add(
                                                ext_ref["source_name"]
                                            )

                    # Always add the detection, even if some lookups failed
                    item = {
                        "name": data_component_name,
                        "data_source": data_source_name,
                        "id": data_source_id,
                        "description": relation.get("description", ""),
                    }
                    # Use data_source_id as unique key, or fall back to combination if id is empty
                    detection_key = (
                        data_source_id
                        if data_source_id
                        else f"{data_source_name}:{data_component_name}"
                    )
                    if detection_key not in detections_added:
                        technique_obj.detections = item
                        detections_added.add(detection_key)

                # Subtechniques (using cache)
                subtechniques = subtechniques_by_main_id.get(technique_obj.main_id, [])
                for subtechnique in subtechniques:
                    if (
                        "x_mitre_deprecated" not in subtechnique
                        or not subtechnique["x_mitre_deprecated"]
                    ) and (
                        "revoked" not in subtechnique or not subtechnique["revoked"]
                    ):
                        sub_id = ""
                        ext_refs = subtechnique.get("external_references", [])
                        for ext_ref in ext_refs:
                            if ext_ref["source_name"] == "mitre-attack":
                                sub_id = ext_ref["external_id"]
                        if sub_id.split(".")[0] == technique_obj.main_id:
                            technique_obj.subtechniques.append(
                                {
                                    "id": sub_id,
                                    "name": subtechnique["name"].replace("/", "／"),  # noqa: RUF001
                                }
                            )

                # Parent name
                if technique_obj.is_subtechnique:
                    parent_techniques = self.src.query(
                        [
                            Filter("type", "=", "attack-pattern"),
                            Filter("x_mitre_is_subtechnique", "=", False),
                            Filter(
                                "external_references.external_id",
                                "=",
                                technique_obj.main_id,
                            ),
                        ]
                    )
                    for parent_technique in parent_techniques:
                        parent_id = ""
                        ext_refs = parent_technique.get("external_references", [])
                        for ext_ref in ext_refs:
                            if ext_ref["source_name"] == "mitre-attack":
                                parent_id = ext_ref["external_id"]
                        if parent_id == technique_obj.main_id:
                            technique_obj.parent_name = parent_technique["name"]
                            break

                # Targeted assets
                targeted_assets_relationships = self.src.query(
                    [
                        Filter("type", "=", "relationship"),
                        Filter("relationship_type", "=", "targets"),
                        Filter("source_ref", "=", technique_obj.internal_id),
                    ]
                )

                for relation in targeted_assets_relationships:
                    targeted_asset = self.src.query(
                        [Filter("id", "=", relation["target_ref"])]
                    )[0]
                    targeted_assets_name = targeted_asset.get("name", "")
                    targeted_assets_description = targeted_asset.get("description", "")
                    targeted_assets_id = ""
                    ext_refs = targeted_asset.get("external_references", [])
                    for ext_ref in ext_refs:
                        if ext_ref["source_name"] == "mitre-attack":
                            targeted_assets_id = ext_ref["external_id"]
                        if "url" in ext_ref and "description" in ext_ref:
                            item = {
                                "name": ext_ref["source_name"],
                                "url": ext_ref["url"],
                                "description": ext_ref["description"],
                            }
                            if ext_ref["source_name"] not in external_references_added:
                                technique_obj.external_references = item
                                external_references_added.add(ext_ref["source_name"])
                    item = {
                        "name": targeted_assets_name.replace("/", "／"),  # noqa: RUF001
                        "id": targeted_assets_id,
                        "description": targeted_assets_description,
                    }
                    if targeted_assets_id not in targeted_assets_added:
                        technique_obj.targeted_assets = item
                        targeted_assets_added.add(targeted_assets_id)
                self.techniques.append(technique_obj)

    def _get_mitigations(self, domain) -> None:  # noqa: PLR0912
        """Get and parse techniques from STIX data."""
        # Set the appropriate data source for the domain
        if domain == "enterprise-attack":
            self.src = self.enterprise_attack
        elif domain == "mobile-attack":
            self.src = self.mobile_attack
        elif domain == "ics-attack":
            self.src = self.ics_attack

        # Extract mitigations
        mitigations_stix = self.src.query(
            [Filter(prop="type", op="=", value="course-of-action")]
        )

        for mitigation in mitigations_stix:
            if (
                (
                    "x_mitre_deprecated" not in mitigation
                    or not mitigation["x_mitre_deprecated"]
                )
                and ("revoked" not in mitigation or not mitigation["revoked"])
                and (domain in mitigation["x_mitre_domains"])
            ):
                mitigation_obj = MITREMitigation(name=mitigation["name"])
                external_references_added = set()

                # Add attributes to the mitigation object
                mitigation_obj.internal_id = mitigation["id"]
                mitigation_obj.description = mitigation["description"]
                mitigation_obj.created = mitigation.get("created", "")
                mitigation_obj.modified = mitigation.get("modified", "")
                mitigation_obj.version = mitigation.get("x_mitre_version", [])
                mitigation_obj.domain = domain

                # Get external references
                ext_refs = mitigation.get("external_references", [])
                for ext_ref in ext_refs:
                    if ext_ref["source_name"] == "mitre-attack":
                        mitigation_obj.id = ext_ref["external_id"]
                        mitigation_obj.url = ext_ref["url"]
                    elif "url" in ext_ref and "description" in ext_ref:
                        item = {
                            "name": ext_ref["source_name"],
                            "url": ext_ref["url"],
                            "description": ext_ref["description"],
                        }
                        if ext_ref["source_name"] not in external_references_added:
                            mitigation_obj.external_references = item
                            external_references_added.add(ext_ref["source_name"])

                mitigation_relationships = self.src.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="mitigates"),
                        Filter(
                            prop="source_ref", op="=", value=mitigation_obj.internal_id
                        ),
                    ]
                )

                for relationship in mitigation_relationships:
                    techniques_stix = self.src.query(
                        [
                            Filter(prop="type", op="=", value="attack-pattern"),
                            Filter(prop="x_mitre_deprecated", op="=", value=False),
                            Filter(prop="revoked", op="=", value=False),
                            Filter(prop="id", op="=", value=relationship["target_ref"]),
                        ]
                    )

                    if techniques_stix:
                        technique = techniques_stix[0]
                        external_id = ""
                        ext_refs = technique.get("external_references", [])
                        for ext_ref in ext_refs:
                            if ext_ref["source_name"] == "mitre-attack":
                                external_id = ext_ref["external_id"]
                        ext_refs = relationship.get("external_references", [])
                        for ext_ref in ext_refs:
                            if "url" in ext_ref and "description" in ext_ref:
                                item = {
                                    "name": ext_ref["source_name"],
                                    "url": ext_ref["url"],
                                    "description": ext_ref["description"],
                                }
                                if (
                                    ext_ref["source_name"]
                                    not in external_references_added
                                ):
                                    mitigation_obj.external_references = item
                                    external_references_added.add(
                                        ext_ref["source_name"]
                                    )
                        mitigation_obj.mitigates = {
                            "id": external_id,
                            "name": technique["name"].replace("/", "／"),  # noqa: RUF001
                            "description": relationship.get("description", ""),
                            "domain": relationship.get("x_mitre_domains", domain),
                        }

                self.mitigations.append(mitigation_obj)

    def _get_groups(self) -> None:  # noqa: PLR0912, PLR0915
        """Get and parse groups from STIX data."""
        # Pre-cache all relationships and techniques to avoid repeated queries
        print("Pre-caching relationships and techniques for groups...")
        cache_start = time_module.time()

        # Cache all "uses" relationships for groups->techniques
        all_tech_relationships_enterprise = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
                Filter(prop="target_ref", op="contains", value="attack-pattern"),
            ]
        )
        all_tech_relationships_mobile = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
                Filter(prop="target_ref", op="contains", value="attack-pattern"),
            ]
        )
        all_tech_relationships_ics = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
                Filter(prop="target_ref", op="contains", value="attack-pattern"),
            ]
        )

        # Build a dict mapping source_ref -> list of relationships
        tech_relationships_by_source = {}
        for rel in (
            all_tech_relationships_enterprise
            + all_tech_relationships_mobile
            + all_tech_relationships_ics
        ):
            source = rel.get("source_ref")
            if source:
                if source not in tech_relationships_by_source:
                    tech_relationships_by_source[source] = []
                tech_relationships_by_source[source].append(rel)

        # Cache all techniques by their ID for O(1) lookup
        all_techniques_enterprise = self.enterprise_attack.query(
            [Filter(prop="type", op="=", value="attack-pattern")]
        )
        all_techniques_mobile = self.mobile_attack.query(
            [Filter(prop="type", op="=", value="attack-pattern")]
        )
        all_techniques_ics = self.ics_attack.query(
            [Filter(prop="type", op="=", value="attack-pattern")]
        )

        technique_cache = {}
        for tech in all_techniques_enterprise:
            technique_cache[tech["id"]] = (tech, "enterprise-attack")
        for tech in all_techniques_mobile:
            technique_cache[tech["id"]] = (tech, "mobile-attack")
        for tech in all_techniques_ics:
            technique_cache[tech["id"]] = (tech, "ics-attack")

        # Cache all "uses" relationships for groups->software
        # Query separately for malware relationships
        all_soft_relationships_enterprise_malware = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
                Filter(prop="target_ref", op="contains", value="malware"),
            ]
        )
        # Query separately for tool relationships
        all_soft_relationships_enterprise_tool = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
                Filter(prop="target_ref", op="contains", value="tool"),
            ]
        )
        all_soft_relationships_mobile_malware = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
                Filter(prop="target_ref", op="contains", value="malware"),
            ]
        )
        all_soft_relationships_mobile_tool = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
                Filter(prop="target_ref", op="contains", value="tool"),
            ]
        )
        all_soft_relationships_ics_malware = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
                Filter(prop="target_ref", op="contains", value="malware"),
            ]
        )
        all_soft_relationships_ics_tool = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
                Filter(prop="target_ref", op="contains", value="tool"),
            ]
        )

        soft_relationships_by_source = {}
        for rel in (
            all_soft_relationships_enterprise_malware
            + all_soft_relationships_enterprise_tool
            + all_soft_relationships_mobile_malware
            + all_soft_relationships_mobile_tool
            + all_soft_relationships_ics_malware
            + all_soft_relationships_ics_tool
        ):
            source = rel.get("source_ref")
            if source:
                if source not in soft_relationships_by_source:
                    soft_relationships_by_source[source] = []
                soft_relationships_by_source[source].append(rel)

        # Cache all software by ID (combined query for malware and tool)
        all_software_enterprise = self.enterprise_attack.query(
            [Filter(prop="type", op="in", value=["malware", "tool"])]
        )
        all_software_mobile = self.mobile_attack.query(
            [Filter(prop="type", op="in", value=["malware", "tool"])]
        )
        all_software_ics = self.ics_attack.query(
            [Filter(prop="type", op="in", value=["malware", "tool"])]
        )

        software_cache = {}
        for soft in all_software_enterprise + all_software_mobile + all_software_ics:
            software_cache[soft["id"]] = soft

        print(f"  Cache built in {time_module.time() - cache_start:.2f}s")

        # Extract groups
        groups_enterprise_stix = self.enterprise_attack.query(
            [Filter(prop="type", op="=", value="intrusion-set")]
        )
        groups_mobile_stix = self.mobile_attack.query(
            [Filter(prop="type", op="=", value="intrusion-set")]
        )
        groups_ics_stix = self.ics_attack.query(
            [Filter(prop="type", op="=", value="intrusion-set")]
        )
        groups_stix = groups_enterprise_stix + groups_mobile_stix + groups_ics_stix

        self.groups = list()

        for group in groups_stix:
            if (
                "x_mitre_deprecated" not in group or not group["x_mitre_deprecated"]
            ) and ("revoked" not in group or not group["revoked"]):
                group_obj = MITREGroup(name=group["name"])
                external_references_added = set()
                software_used_added = set()

                # Add attributes to the group object
                group_obj.internal_id = group["id"]
                group_obj.aliases = group.get("aliases", [])
                group_obj.contributors = group.get("x_mitre_contributors", [])
                group_obj.description = group.get("description", "")
                group_obj.version = group.get("x_mitre_version", [])
                group_obj.created = group.get("created", "")
                group_obj.modified = group.get("modified", "")

                # Extract external references, including the link to mitre
                ext_refs = group.get("external_references", [])

                for ext_ref in ext_refs:
                    if ext_ref["source_name"] == "mitre-attack":
                        group_obj.id = ext_ref["external_id"]
                        group_obj.url = ext_ref["url"]
                    elif "url" in ext_ref:
                        item = {
                            "name": ext_ref["source_name"],
                            "url": ext_ref["url"],
                            "description": ext_ref["description"],
                        }
                        if ext_ref["source_name"] not in external_references_added:
                            group_obj.external_references = item
                            external_references_added.add(ext_ref["source_name"])
                    elif ext_ref["source_name"] != group_obj.name:
                        group_obj.aliases_references = {
                            "name": ext_ref["source_name"],
                            "description": ext_ref["description"],
                        }

                # Get techniques used by group (using cache)
                tech_group_relationships = tech_relationships_by_source.get(
                    group_obj.internal_id, []
                )

                for tech_group_rel in tech_group_relationships:
                    if (
                        "x_mitre_deprecated" not in tech_group_rel
                        or not tech_group_rel["x_mitre_deprecated"]
                    ) and (
                        "revoked" not in tech_group_rel or not tech_group_rel["revoked"]
                    ):
                        # Use cache instead of repeated queries
                        target_ref = tech_group_rel["target_ref"]
                        if target_ref in technique_cache:
                            technique, domain = technique_cache[target_ref]

                            ext_refs = technique.get("external_references", [])
                            technique_id = None
                            for ext_ref in ext_refs:
                                if ext_ref["source_name"] == "mitre-attack":
                                    technique_id = ext_ref["external_id"]
                                    break

                            if technique_id:
                                ext_refs = tech_group_rel.get("external_references", [])
                                for ext_ref in ext_refs:
                                    if "url" in ext_ref and "description" in ext_ref:
                                        item = {
                                            "name": ext_ref["source_name"].replace(
                                                "/", "／"
                                            ),
                                            "url": ext_ref["url"],
                                            "description": ext_ref["description"],
                                        }
                                        if (
                                            ext_ref["source_name"]
                                            not in external_references_added
                                        ):
                                            group_obj.external_references = item
                                            external_references_added.add(
                                                ext_ref["source_name"]
                                            )

                                group_obj.techniques_used = {
                                    "technique_name": technique["name"].replace(
                                        "/", "／"
                                    ),
                                    "technique_id": technique_id,
                                    "description": tech_group_rel.get(
                                        "description", ""
                                    ),
                                    "domain": domain,
                                }

                # Get software used by group (using cache)
                software_relationships = soft_relationships_by_source.get(
                    group_obj.internal_id, []
                )

                for group_software_rel in software_relationships:
                    if (
                        "x_mitre_deprecated" not in group_software_rel
                        or not group_software_rel["x_mitre_deprecated"]
                    ) and (
                        "revoked" not in group_software_rel
                        or not group_software_rel["revoked"]
                    ):
                        # Use cache to get software details
                        target_ref = group_software_rel["target_ref"]
                        if target_ref not in software_cache:
                            continue

                        software = software_cache[target_ref]
                        software_name = software["name"]
                        software_id = ""

                        ext_refs = software.get("external_references", [])
                        for ext_ref in ext_refs:
                            if ext_ref["source_name"] == "mitre-attack":
                                software_id = ext_ref["external_id"]
                                break

                        if not software_id:
                            continue

                        # Get techniques used by this software (using cache)
                        source_relationships = tech_relationships_by_source.get(
                            target_ref, []
                        )
                        markdown_links: str = ""

                        for relationship in source_relationships:
                            # Use cache instead of repeated queries
                            technique_ref = relationship["target_ref"]
                            if technique_ref in technique_cache:
                                technique, _ = technique_cache[technique_ref]

                                # Check if deprecated/revoked
                                if technique.get("x_mitre_deprecated") or technique.get(
                                    "revoked"
                                ):
                                    continue

                                technique_name = technique["name"]
                                technique_id = ""
                                for ext_ref in technique.get("external_references", []):
                                    if ext_ref["source_name"] == "mitre-attack":
                                        technique_id = ext_ref["external_id"]
                                        break

                                if not technique_id:
                                    continue

                                if technique.get("x_mitre_is_subtechnique"):
                                    technique_parent_id: str = technique_id.split(".")[
                                        0
                                    ]
                                    technique_parent_name_enterprise = self.enterprise_attack.query(
                                        [
                                            Filter(
                                                prop="type",
                                                op="=",
                                                value="attack-pattern",
                                            ),
                                            Filter(
                                                prop="external_references.external_id",
                                                op="=",
                                                value=technique_parent_id,
                                            ),
                                        ]
                                    )
                                    technique_parent_name_mobile = self.mobile_attack.query(
                                        [
                                            Filter(
                                                prop="type",
                                                op="=",
                                                value="attack-pattern",
                                            ),
                                            Filter(
                                                prop="external_references.external_id",
                                                op="=",
                                                value=technique_parent_id,
                                            ),
                                        ]
                                    )
                                    technique_parent_name_ics = self.ics_attack.query(
                                        [
                                            Filter(
                                                prop="type",
                                                op="=",
                                                value="attack-pattern",
                                            ),
                                            Filter(
                                                prop="external_references.external_id",
                                                op="=",
                                                value=technique_parent_id,
                                            ),
                                        ]
                                    )
                                    technique_parent_name_stix = (
                                        technique_parent_name_enterprise
                                        + technique_parent_name_mobile
                                        + technique_parent_name_ics
                                    )

                                    if technique_parent_name_stix:
                                        technique_parent_name = (
                                            technique_parent_name_stix[0]["name"]
                                        )
                                    else:
                                        technique_parent_name: str = ""
                                else:
                                    technique_parent_id: str = ""
                                    technique_parent_name: str = ""
                                if technique_parent_name:
                                    markdown_link: str = f"[[{technique_parent_name.replace('/', '／')} - {technique_parent_id} \\| {technique_parent_name.replace('/', '／')}]]: [[{technique_name.replace('/', '／')} - {technique_id} \\| {technique_name.replace('/', '／')}]]"  # noqa: RUF001
                                else:
                                    markdown_link = f"[[{technique_name.replace('/', '／')} - {technique_id} \\| {technique_name.replace('/', '／')}]]"  # noqa: RUF001

                                if markdown_links:
                                    markdown_links += ", " + markdown_link
                                else:
                                    markdown_links = markdown_link
                        item = {
                            "name": software_name,
                            "id": software_id,
                            "description": relationship.get("description", ""),
                            "software_techniques": markdown_links,
                        }
                        if software_id not in software_used_added:
                            group_obj.software_used = item
                            software_used_added.add(software_id)

                self.groups.append(group_obj)

    def _get_software(self) -> None:  # noqa: PLR0912, PLR0915
        """Get and parse software from STIX data."""
        # Pre-cache all relationships and objects to avoid repeated queries
        print("Pre-caching relationships and objects for software...")
        cache_start = time_module.time()

        # Extract software
        software_enterprise_malware_stix = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="malware"),
            ]
        )
        software_enterprise_tool_stix = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="tool"),
            ]
        )
        software_mobile_malware_stix = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="malware"),
            ]
        )
        software_mobile_tool_stix = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="tool"),
            ]
        )
        software_ics_malware_stix = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="malware"),
            ]
        )
        software_ics_tool_stix = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="tool"),
            ]
        )

        software_stix = (
            software_enterprise_malware_stix
            + software_enterprise_tool_stix
            + software_mobile_malware_stix
            + software_mobile_tool_stix
            + software_ics_malware_stix
            + software_ics_tool_stix
        )

        # Cache all "uses" relationships: software->techniques and campaigns/groups->software
        all_uses_relationships_enterprise = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
            ]
        )
        all_uses_relationships_mobile = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
            ]
        )
        all_uses_relationships_ics = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="uses"),
            ]
        )

        # Build dictionaries: source_ref -> list of relationships
        uses_by_source = {}
        uses_by_target = {}
        for rel in (
            all_uses_relationships_enterprise
            + all_uses_relationships_mobile
            + all_uses_relationships_ics
        ):
            source = rel.get("source_ref")
            target = rel.get("target_ref")
            if source:
                if source not in uses_by_source:
                    uses_by_source[source] = []
                uses_by_source[source].append(rel)
            if target:
                if target not in uses_by_target:
                    uses_by_target[target] = []
                uses_by_target[target].append(rel)

        # Cache all techniques by ID
        all_techniques_enterprise = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="attack-pattern"),
            ]
        )
        all_techniques_mobile = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="attack-pattern"),
            ]
        )
        all_techniques_ics = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="attack-pattern"),
            ]
        )

        technique_cache = {}
        for tech in all_techniques_enterprise:
            technique_cache[tech["id"]] = (tech, "enterprise-attack")
        for tech in all_techniques_mobile:
            technique_cache[tech["id"]] = (tech, "mobile-attack")
        for tech in all_techniques_ics:
            technique_cache[tech["id"]] = (tech, "ics-attack")

        # Cache all campaigns by ID
        all_campaigns_enterprise = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="campaign"),
            ]
        )
        all_campaigns_mobile = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="campaign"),
            ]
        )
        all_campaigns_ics = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="campaign"),
            ]
        )

        campaign_cache = {}
        for camp in all_campaigns_enterprise:
            campaign_cache[camp["id"]] = camp
        for camp in all_campaigns_mobile:
            campaign_cache[camp["id"]] = camp
        for camp in all_campaigns_ics:
            campaign_cache[camp["id"]] = camp

        # Cache all groups by ID
        all_groups_enterprise = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="intrusion-set"),
            ]
        )
        all_groups_mobile = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="intrusion-set"),
            ]
        )
        all_groups_ics = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="intrusion-set"),
            ]
        )

        group_cache = {}
        for group in all_groups_enterprise:
            group_cache[group["id"]] = group
        for group in all_groups_mobile:
            group_cache[group["id"]] = group
        for group in all_groups_ics:
            group_cache[group["id"]] = group

        # Cache "attributed-to" relationships: campaign->group
        all_attributed_relationships_enterprise = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="attributed-to"),
            ]
        )
        all_attributed_relationships_mobile = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="attributed-to"),
            ]
        )
        all_attributed_relationships_ics = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="attributed-to"),
            ]
        )

        # Build dictionary: (campaign_id, group_id) -> relationship
        attributed_by_campaign_group = {}
        for rel in (
            all_attributed_relationships_enterprise
            + all_attributed_relationships_mobile
            + all_attributed_relationships_ics
        ):
            source = rel.get("source_ref")
            target = rel.get("target_ref")
            if source and target:
                attributed_by_campaign_group[(source, target)] = rel

        print(f"  Cache built in {time_module.time() - cache_start:.2f}s")

        self.software = list()

        for software in software_stix:
            if (
                "x_mitre_deprecated" not in software
                or not software["x_mitre_deprecated"]
            ) and ("revoked" not in software or not software["revoked"]):
                software_obj = MITRESoftware(name=software["name"])
                campaigns_using_added = set()
                external_references_added = set()

                # Add simple attributes to the software object
                software_obj.internal_id = software["id"]
                software_obj.type = software["type"]
                software_obj.platforms = software.get("x_mitre_platforms", [])
                software_obj.contributors = software.get("x_mitre_contributors", [])
                software_obj.version = software.get("x_mitre_version", [])
                software_obj.description = software.get("description", "")
                software_obj.created = software.get("created", "")
                software_obj.modified = software.get("modified", "")
                software_obj.aliases = software.get("aliases", [])

                # Extract external references, including the link to mitre used to get software id
                ext_refs = software.get("external_references", [])

                for ext_ref in ext_refs:
                    if ext_ref["source_name"] == "mitre-attack":
                        software_obj.id = ext_ref["external_id"]
                        software_obj.url = ext_ref["url"]
                    elif "url" in ext_ref:
                        item = {
                            "name": ext_ref["source_name"],
                            "url": ext_ref["url"],
                            "description": ext_ref["description"],
                        }
                        if ext_ref["source_name"] not in external_references_added:
                            software_obj.external_references = item
                            external_references_added.add(ext_ref["source_name"])

                # Techniques used by software (using cache)
                source_relationships = uses_by_source.get(software_obj.internal_id, [])

                for relationship in source_relationships:
                    # Use cache instead of repeated queries
                    target_ref = relationship["target_ref"]
                    if target_ref in technique_cache:
                        technique, domain = technique_cache[target_ref]
                        if (
                            "x_mitre_deprecated" not in technique
                            or not technique["x_mitre_deprecated"]
                        ) and ("revoked" not in technique or not technique["revoked"]):
                            software_obj.techniques_used = {
                                "technique": technique,
                                "description": relationship.get("description", ""),
                                "domain": technique.get("x_mitre_domains", []),
                            }

                            if "external_references" in relationship:
                                ext_refs = relationship.get("external_references", [])
                                for ext_ref in ext_refs:
                                    if "url" in ext_ref and "description" in ext_ref:
                                        item = {
                                            "name": ext_ref["source_name"],
                                            "url": ext_ref["url"],
                                            "description": ext_ref["description"],
                                        }
                                        if (
                                            ext_ref["source_name"]
                                            not in external_references_added
                                        ):
                                            software_obj.external_references = item
                                            external_references_added.add(
                                                ext_ref["source_name"]
                                            )

                # Software has been used in these campaigns (using cache)
                campaign_relationships = uses_by_target.get(
                    software_obj.internal_id, []
                )

                for relationship in campaign_relationships:
                    source_ref = relationship["source_ref"]
                    if (
                        source_ref.startswith("campaign")
                        and source_ref in campaign_cache
                    ):
                        campaign = campaign_cache[source_ref]
                        if (
                            "x_mitre_deprecated" not in campaign
                            or not campaign["x_mitre_deprecated"]
                        ) and ("revoked" not in campaign or not campaign["revoked"]):
                            ext_refs = campaign.get("external_references", [])
                            campaign_id = ""
                            for ext_ref in ext_refs:
                                if ext_ref["source_name"] == "mitre-attack":
                                    campaign_id = ext_ref["external_id"]
                                if "url" in ext_ref and "description" in ext_ref:
                                    item = {
                                        "name": ext_ref["source_name"],
                                        "url": ext_ref["url"],
                                        "description": ext_ref["description"],
                                    }
                                    if (
                                        ext_ref["source_name"]
                                        not in external_references_added
                                    ):
                                        software_obj.external_references = item
                                        external_references_added.add(
                                            ext_ref["source_name"]
                                        )
                            ext_refs = relationship.get("external_references", [])
                            for ext_ref in ext_refs:
                                if "url" in ext_ref and "description" in ext_ref:
                                    item = {
                                        "name": ext_ref["source_name"],
                                        "url": ext_ref["url"],
                                        "description": ext_ref["description"],
                                    }
                                    if (
                                        ext_ref["source_name"]
                                        not in external_references_added
                                    ):
                                        software_obj.external_references = item
                                        external_references_added.add(
                                            ext_ref["source_name"]
                                        )
                            item = {
                                "campaign_id": campaign_id,
                                "campaign_name": campaign.get("name", ""),
                                "description": relationship.get("description", ""),
                                "campaign_internal_id": campaign["id"],
                            }
                            if campaign["id"] not in campaigns_using_added:
                                software_obj.campaigns_using = item
                                campaigns_using_added.add(campaign["id"])

                # Groups using the software (using cache)
                group_relationships = uses_by_target.get(software_obj.internal_id, [])

                group_added = []
                for relationship in group_relationships:
                    source_ref = relationship["source_ref"]
                    if (
                        source_ref.startswith("intrusion-set")
                        and source_ref in group_cache
                        and (
                            "x_mitre_deprecated" not in relationship
                            or not relationship["x_mitre_deprecated"]
                        )
                        and (
                            "revoked" not in relationship or not relationship["revoked"]
                        )
                    ):
                        groupinfo = group_cache[source_ref]
                        group_id: str = ""
                        descriptions: str = ""
                        if "external_references" in groupinfo:
                            ext_refs = groupinfo.get("external_references", [])
                            for ext_ref in ext_refs:
                                if "mitre-attack" in ext_ref["source_name"]:
                                    group_id = ext_ref["external_id"]
                                if "url" in ext_ref and "description" in ext_ref:
                                    item = {
                                        "name": ext_ref["source_name"],
                                        "url": ext_ref["url"],
                                        "description": ext_ref["description"],
                                    }
                                    if (
                                        ext_ref["source_name"]
                                        not in external_references_added
                                    ):
                                        software_obj.external_references = item
                                        external_references_added.add(
                                            ext_ref["source_name"]
                                        )
                        if "external_references" in relationship:
                            ext_refs = relationship.get("external_references", [])
                            for ext_ref in ext_refs:
                                if "url" in ext_ref and "description" in ext_ref:
                                    item = {
                                        "name": ext_ref["source_name"],
                                        "url": ext_ref["url"],
                                        "description": ext_ref["description"],
                                    }
                                    if (
                                        ext_ref["source_name"]
                                        not in external_references_added
                                    ):
                                        software_obj.external_references = item
                                        external_references_added.add(
                                            ext_ref["source_name"]
                                        )

                        # Check campaign-to-group attribution (using cache)
                        for software_campaign in software_obj.campaigns_using:
                            campaign_id = software_campaign.get("campaign_internal_id")
                            # Use cache to check if this campaign is attributed to this group
                            if (
                                campaign_id,
                                groupinfo["id"],
                            ) in attributed_by_campaign_group:
                                campaign_rel = attributed_by_campaign_group[
                                    (campaign_id, groupinfo["id"])
                                ]
                                if campaign_id in campaign_cache:
                                    campaign = campaign_cache[campaign_id]
                                    if (
                                        "x_mitre_deprecated" not in campaign
                                        or not campaign["x_mitre_deprecated"]
                                    ) and (
                                        "revoked" not in campaign
                                        or not campaign["revoked"]
                                    ):
                                        for ext_ref in campaign.get(
                                            "external_references", []
                                        ):
                                            if (
                                                "url" in ext_ref
                                                and "description" in ext_ref
                                            ):
                                                item = {
                                                    "name": ext_ref["source_name"],
                                                    "url": ext_ref["url"],
                                                    "description": ext_ref[
                                                        "description"
                                                    ],
                                                }
                                                if (
                                                    ext_ref["source_name"]
                                                    not in external_references_added
                                                ):
                                                    software_obj.external_references = (
                                                        item
                                                    )
                                                    external_references_added.add(
                                                        ext_ref["source_name"]
                                                    )
                                        description: str = campaign.get(
                                            "description", ""
                                        )
                                        if description not in descriptions:
                                            descriptions += description

                        description = relationship.get("description", "")
                        if description not in descriptions:
                            descriptions += description

                        item = {
                            "group_id": group_id,
                            "group_name": groupinfo["name"],
                            "description": descriptions,
                        }
                        if item not in group_added:
                            software_obj.groups_using = item
                            group_added.append(item)

                self.software.append(software_obj)

    def _get_campaigns(self) -> None:  # noqa: PLR0912, PLR0915
        """Get and parse campaigns from STIX data."""
        self.campaigns = list()

        for domain in ("enterprise-attack", "mobile-attack", "ics-attack"):
            # Extract campaigns
            if domain == "enterprise-attack":
                campaigns_stix = self.enterprise_attack.query(
                    [
                        Filter(prop="type", op="=", value="campaign"),
                    ]
                )
            elif domain == "mobile-attack":
                campaigns_stix = self.mobile_attack.query(
                    [
                        Filter(prop="type", op="=", value="campaign"),
                    ]
                )
            elif domain == "ics-attack":
                campaigns_stix = self.ics_attack.query(
                    [
                        Filter(prop="type", op="=", value="campaign"),
                    ]
                )
            for campaign in campaigns_stix:
                if (
                    "x_mitre_deprecated" not in campaign
                    or not campaign["x_mitre_deprecated"]
                ) and ("revoked" not in campaign or not campaign["revoked"]):
                    campaign_obj = MITRECampaign(name=campaign["name"])
                    external_references_added = set()
                    groups_added = []

                    # Add attributes to the campaign object
                    campaign_obj.internal_id = campaign["id"]
                    campaign_obj.aliases = campaign.get("aliases", [])
                    campaign_obj.description = campaign.get("description", "")
                    campaign_obj.version = campaign.get("x_mitre_version", [])
                    campaign_obj.created = campaign.get("created", "")
                    campaign_obj.modified = campaign.get("modified", "")
                    campaign_obj.first_seen = campaign.get("first_seen", "")
                    campaign_obj.last_seen = campaign.get("last_seen", "")

                    # Get external references
                    ext_refs = campaign.get("external_references", [])

                    for ext_ref in ext_refs:
                        if ext_ref["source_name"] == "mitre-attack":
                            campaign_obj.id = ext_ref["external_id"]
                            campaign_obj.url = ext_ref["url"]
                        elif "url" in ext_ref and "description" in ext_ref:
                            item = {
                                "name": ext_ref["source_name"],
                                "url": ext_ref["url"],
                                "description": ext_ref["description"],
                            }
                            if ext_ref["source_name"] not in external_references_added:
                                campaign_obj.external_references = item
                                external_references_added.add(ext_ref["source_name"])

                    # Get group(s) associated with the campaign
                    group_relationships_enterprise = self.enterprise_attack.query(
                        [
                            Filter(prop="type", op="=", value="relationship"),
                            Filter(
                                prop="relationship_type", op="=", value="attributed-to"
                            ),
                            Filter(
                                prop="source_ref",
                                op="=",
                                value=campaign_obj.internal_id,
                            ),
                        ]
                    )
                    group_relationships_mobile = self.mobile_attack.query(
                        [
                            Filter(prop="type", op="=", value="relationship"),
                            Filter(
                                prop="relationship_type", op="=", value="attributed-to"
                            ),
                            Filter(
                                prop="source_ref",
                                op="=",
                                value=campaign_obj.internal_id,
                            ),
                        ]
                    )
                    group_relationships_ics = self.ics_attack.query(
                        [
                            Filter(prop="type", op="=", value="relationship"),
                            Filter(
                                prop="relationship_type", op="=", value="attributed-to"
                            ),
                            Filter(
                                prop="source_ref",
                                op="=",
                                value=campaign_obj.internal_id,
                            ),
                        ]
                    )

                    group_relationships = (
                        group_relationships_enterprise
                        + group_relationships_mobile
                        + group_relationships_ics
                    )

                    for relationship in group_relationships:
                        for group in self.groups:
                            if group.internal_id == relationship["target_ref"]:
                                if group.internal_id not in groups_added:
                                    campaign_obj.groups = {
                                        "group": group,
                                        "description": relationship.get(
                                            "description", ""
                                        ),
                                    }
                                    groups_added.append(group.internal_id)

                    # Get software used in the campaign
                    software_relationships_enterprise = self.enterprise_attack.query(
                        [
                            Filter(prop="type", op="=", value="relationship"),
                            Filter(prop="relationship_type", op="=", value="uses"),
                            Filter(
                                prop="source_ref",
                                op="=",
                                value=campaign_obj.internal_id,
                            ),
                        ]
                    )
                    software_relationships_mobile = self.mobile_attack.query(
                        [
                            Filter(prop="type", op="=", value="relationship"),
                            Filter(prop="relationship_type", op="=", value="uses"),
                            Filter(
                                prop="source_ref",
                                op="=",
                                value=campaign_obj.internal_id,
                            ),
                        ]
                    )
                    software_relationships_ics = self.ics_attack.query(
                        [
                            Filter(prop="type", op="=", value="relationship"),
                            Filter(prop="relationship_type", op="=", value="uses"),
                            Filter(
                                prop="source_ref",
                                op="=",
                                value=campaign_obj.internal_id,
                            ),
                        ]
                    )

                    software_relationships = (
                        software_relationships_enterprise
                        + software_relationships_mobile
                        + software_relationships_ics
                    )

                    software_malware_enterprise = self.enterprise_attack.query(
                        [
                            Filter(prop="type", op="=", value="malware"),
                        ]
                    )
                    software_malware_mobile = self.mobile_attack.query(
                        [
                            Filter(prop="type", op="=", value="malware"),
                        ]
                    )
                    software_malware_ics = self.ics_attack.query(
                        [
                            Filter(prop="type", op="=", value="malware"),
                        ]
                    )

                    software_malware = (
                        software_malware_enterprise
                        + software_malware_mobile
                        + software_malware_ics
                    )

                    software_tool_enterprise = self.enterprise_attack.query(
                        [
                            Filter(prop="type", op="=", value="tool"),
                        ]
                    )
                    software_tool_mobile = self.mobile_attack.query(
                        [
                            Filter(prop="type", op="=", value="tool"),
                        ]
                    )
                    software_tool_ics = self.ics_attack.query(
                        [
                            Filter(prop="type", op="=", value="tool"),
                        ]
                    )

                    software_tool = (
                        software_tool_enterprise
                        + software_tool_mobile
                        + software_tool_ics
                    )
                    softwares = software_malware + software_tool

                    software_added = []
                    external_references_added = set()
                    for relationship in software_relationships:
                        if campaign_obj.internal_id == relationship["source_ref"]:
                            for software in softwares:
                                if software["id"] == relationship["target_ref"]:
                                    item = {
                                        "software": software,
                                        "description": relationship.get(
                                            "description", ""
                                        ),
                                    }
                                    if item not in software_added:
                                        campaign_obj.software_used = item
                                        software_added.append(item)

                    # Get techniques used in the campaign
                    source_relationships_enterprise = self.enterprise_attack.query(
                        [
                            Filter(prop="type", op="=", value="relationship"),
                            Filter(
                                prop="source_ref",
                                op="=",
                                value=campaign_obj.internal_id,
                            ),
                        ]
                    )
                    source_relationships_mobile = self.mobile_attack.query(
                        [
                            Filter(prop="type", op="=", value="relationship"),
                            Filter(
                                prop="source_ref",
                                op="=",
                                value=campaign_obj.internal_id,
                            ),
                        ]
                    )
                    source_relationships_ics = self.ics_attack.query(
                        [
                            Filter(prop="type", op="=", value="relationship"),
                            Filter(
                                prop="source_ref",
                                op="=",
                                value=campaign_obj.internal_id,
                            ),
                        ]
                    )

                    source_relationships = (
                        source_relationships_enterprise
                        + source_relationships_mobile
                        + source_relationships_ics
                    )

                    techniques_enterprise_stix = self.enterprise_attack.query(
                        [
                            Filter(prop="type", op="=", value="attack-pattern"),
                        ]
                    )
                    techniques_mobile_stix = self.mobile_attack.query(
                        [
                            Filter(prop="type", op="=", value="attack-pattern"),
                        ]
                    )
                    techniques_ics_stix = self.ics_attack.query(
                        [
                            Filter(prop="type", op="=", value="attack-pattern"),
                        ]
                    )

                    techniques_stix = (
                        techniques_enterprise_stix
                        + techniques_mobile_stix
                        + techniques_ics_stix
                    )

                    for relationship in source_relationships:
                        for technique in techniques_stix:
                            if technique["id"] == relationship["target_ref"]:
                                ext_refs = technique.get("external_references", [])
                                for ext_ref in ext_refs:
                                    if ext_ref["source_name"] == "mitre-attack":
                                        technique_id = ext_ref["external_id"]
                                campaign_obj.techniques_used = {
                                    "technique_name": technique["name"],
                                    "technique_id": technique_id,
                                    "description": relationship.get("description", ""),
                                    "domain": domain,
                                }

                        if "external_references" in relationship:
                            ext_refs = relationship.get("external_references", [])
                            for ext_ref in ext_refs:
                                if "url" in ext_ref and "description" in ext_ref:
                                    item = {
                                        "name": ext_ref["source_name"],
                                        "url": ext_ref["url"],
                                        "description": ext_ref["description"],
                                    }
                                    if (
                                        ext_ref["source_name"]
                                        not in external_references_added
                                    ):
                                        campaign_obj.external_references = item
                                        external_references_added.add(
                                            ext_ref["source_name"]
                                        )

                    self.campaigns.append(campaign_obj)

    def _get_assets(self):  # noqa: PLR0912, PLR0915
        """Get and parse assets from STIX data."""
        # Extract assets
        assets_stix_enterprise = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="x-mitre-asset"),
            ]
        )
        assets_stix_mobile = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="x-mitre-asset"),
            ]
        )
        assets_stix_ics = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="x-mitre-asset"),
            ]
        )

        assets_stix = assets_stix_enterprise + assets_stix_mobile + assets_stix_ics

        self.assets = list()

        for asset in assets_stix:
            if (
                "x_mitre_deprecated" not in asset or not asset["x_mitre_deprecated"]
            ) and ("revoked" not in asset or not asset["revoked"]):
                asset_obj = MITREAsset(name=asset["name"])

                external_references_added = set()

                # Add attributes to the asset object
                asset_obj.internal_id = asset["id"]
                asset_obj.description = asset.get("description", "")
                asset_obj.created = asset.get("created", "")
                asset_obj.modified = asset.get("modified", "")
                asset_obj.version = asset.get("x_mitre_version", "")
                asset_obj.platforms = asset.get("x_mitre_platforms", [])
                asset_obj.sectors = asset.get("x_mitre_sectors", [])

                # Get external references
                ext_refs = asset.get("external_references", [])

                for ext_ref in ext_refs:
                    if ext_ref["source_name"] == "mitre-attack":
                        asset_obj.id = ext_ref["external_id"]
                        asset_obj.url = ext_ref["url"]
                    elif "url" in ext_ref:
                        item = {
                            "name": ext_ref["source_name"],
                            "url": ext_ref["url"],
                            "description": ext_ref["description"],
                        }
                        if ext_ref["source_name"] not in external_references_added:
                            asset_obj.external_references = item
                            external_references_added.add(ext_ref["source_name"])

                related_assets = asset.get("x_mitre_related_assets", [])

                if related_assets:
                    for related_asset in related_assets:
                        related_asset_name = related_asset["name"]
                        related_asset_sectors = related_asset.get(
                            "related_asset_sectors", []
                        )
                        related_asset_description = related_asset["description"]
                        asset_obj.related_assets = {
                            "name": related_asset_name,
                            "sectors": related_asset_sectors,
                            "description": related_asset_description,
                        }

                # Get techniques used by asset
                asset_relationships_enterprise = self.enterprise_attack.query(
                    [
                        Filter("type", "=", "relationship"),
                        Filter("relationship_type", "=", "targets"),
                        Filter("target_ref", "=", asset_obj.internal_id),
                    ]
                )
                asset_relationships_mobile = self.mobile_attack.query(
                    [
                        Filter("type", "=", "relationship"),
                        Filter("relationship_type", "=", "targets"),
                        Filter("target_ref", "=", asset_obj.internal_id),
                    ]
                )
                asset_relationships_ics = self.ics_attack.query(
                    [
                        Filter("type", "=", "relationship"),
                        Filter("relationship_type", "=", "targets"),
                        Filter("target_ref", "=", asset_obj.internal_id),
                    ]
                )

                asset_relationships = (
                    asset_relationships_enterprise
                    + asset_relationships_mobile
                    + asset_relationships_ics
                )

                for relationship in asset_relationships:
                    if (
                        "x_mitre_deprecated" not in relationship
                        or not relationship["x_mitre_deprecated"]
                    ) and (
                        "revoked" not in relationship or not relationship["revoked"]
                    ):
                        technique_stix = self.enterprise_attack.query(
                            [
                                Filter("id", "=", relationship["source_ref"]),
                            ]
                        )
                        domain = "enterprise-attack"
                        if not technique_stix:
                            technique_stix = self.mobile_attack.query(
                                [
                                    Filter("id", "=", relationship["source_ref"]),
                                ]
                            )
                            domain = "mobile-attack"
                        if not technique_stix:
                            technique_stix = self.ics_attack.query(
                                [
                                    Filter("id", "=", relationship["source_ref"]),
                                ]
                            )
                            domain = "ics-attack"

                        if technique_stix:
                            technique = technique_stix[0]
                            ext_refs = technique.get("external_references", [])
                            for ext_ref in ext_refs:
                                if ext_ref["source_name"] == "mitre-attack":
                                    technique_id = ext_ref["external_id"]

                            asset_obj.techniques_used = {
                                "technique_name": technique.name.replace("/", "／"),  # noqa: RUF001
                                "technique_id": technique_id,
                                "domain": domain,
                            }
                        else:
                            sys.exit(
                                f"Technique not found: {relationship['target_ref']}"
                            )

                self.assets.append(asset_obj)

    def _get_data_sources(self) -> None:  # noqa: PLR0912, PLR0915
        """Get and parse data sources from STIX data."""
        # Pre-cache all relationships and objects to avoid repeated queries
        print("Pre-caching relationships and objects for data sources...")
        cache_start = time_module.time()

        # Extract data sources
        data_sources_stix_enterprise = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="x-mitre-data-source"),
            ]
        )
        data_sources_stix_mobile = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="x-mitre-data-source"),
            ]
        )
        data_sources_stix_ics = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="x-mitre-data-source"),
            ]
        )

        data_sources_stix = (
            data_sources_stix_enterprise
            + data_sources_stix_mobile
            + data_sources_stix_ics
        )

        # Cache all data components by x_mitre_data_source_ref
        all_data_components_enterprise = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="x-mitre-data-component"),
            ]
        )
        all_data_components_mobile = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="x-mitre-data-component"),
            ]
        )
        all_data_components_ics = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="x-mitre-data-component"),
            ]
        )

        data_components_by_source = {}
        for dc in (
            all_data_components_enterprise
            + all_data_components_mobile
            + all_data_components_ics
        ):
            source_ref = dc.get("x_mitre_data_source_ref")
            if source_ref:
                if source_ref not in data_components_by_source:
                    data_components_by_source[source_ref] = []
                data_components_by_source[source_ref].append(dc)

        # Cache all "detects" relationships by source_ref
        all_detects_enterprise = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="detects"),
            ]
        )
        all_detects_mobile = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="detects"),
            ]
        )
        all_detects_ics = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="relationship"),
                Filter(prop="relationship_type", op="=", value="detects"),
            ]
        )

        detects_by_source = {}
        for rel in all_detects_enterprise + all_detects_mobile + all_detects_ics:
            source = rel.get("source_ref")
            if source:
                if source not in detects_by_source:
                    detects_by_source[source] = []
                detects_by_source[source].append(rel)

        # Cache all techniques by ID (across all domains)
        all_techniques_enterprise = self.enterprise_attack.query(
            [
                Filter(prop="type", op="=", value="attack-pattern"),
            ]
        )
        all_techniques_mobile = self.mobile_attack.query(
            [
                Filter(prop="type", op="=", value="attack-pattern"),
            ]
        )
        all_techniques_ics = self.ics_attack.query(
            [
                Filter(prop="type", op="=", value="attack-pattern"),
            ]
        )

        technique_cache = {}
        for tech in all_techniques_enterprise:
            technique_cache[tech["id"]] = (tech, "enterprise-attack")
        for tech in all_techniques_mobile:
            technique_cache[tech["id"]] = (tech, "mobile-attack")
        for tech in all_techniques_ics:
            technique_cache[tech["id"]] = (tech, "ics-attack")

        print(f"  Cache built in {time_module.time() - cache_start:.2f}s")

        self.data_sources = list()

        for data_source in data_sources_stix:
            if (
                "x_mitre_deprecated" not in data_source
                or not data_source["x_mitre_deprecated"]
            ) and ("revoked" not in data_source or not data_source["revoked"]):
                data_source_obj = MITREDataSource(name=data_source["name"])

                external_references_added = set()

                # Add attributes to the data source object
                data_source_obj.internal_id = data_source["id"]
                data_source_obj.description = data_source.get("description", "")
                data_source_obj.created = data_source.get("created", "")
                data_source_obj.modified = data_source.get("modified", "")
                data_source_obj.version = data_source.get("x_mitre_version", [])
                data_source_obj.contributors = data_source.get(
                    "x_mitre_contributors", []
                )
                data_source_obj.platforms = data_source.get("x_mitre_platforms", [])
                data_source_obj.collection_layers = data_source.get(
                    "x_mitre_collection_layers", []
                )

                # Get external references for the data source
                ext_refs = data_source.get("external_references", [])

                for ext_ref in ext_refs:
                    if ext_ref["source_name"] == "mitre-attack":
                        data_source_obj.id = ext_ref["external_id"]
                        data_source_obj.url = ext_ref["url"]
                    elif "url" in ext_ref and "description" in ext_ref:
                        item = {
                            "name": ext_ref["source_name"],
                            "url": ext_ref["url"],
                            "description": ext_ref["description"],
                        }
                        if ext_ref["source_name"] not in external_references_added:
                            data_source_obj.external_references = item
                            external_references_added.add(ext_ref["source_name"])

                # Get data components used by data source (using cache)
                data_source_relationships = data_components_by_source.get(
                    data_source_obj.internal_id, []
                )

                data_components = []
                for relationship in data_source_relationships:
                    if (
                        "x_mitre_deprecated" not in relationship
                        or not relationship["x_mitre_deprecated"]
                    ) and (
                        "revoked" not in relationship or not relationship["revoked"]
                    ):
                        data_component_name = relationship.get("name", "")
                        data_component_description = relationship.get("description", "")
                        data_component_parent = data_source_obj.name

                        # Get external references for the data component
                        ext_refs = relationship.get("external_references", [])

                        for ext_ref in ext_refs:
                            if "url" in ext_ref and "description" in ext_ref:
                                item = {
                                    "name": ext_ref["source_name"],
                                    "url": ext_ref["url"],
                                    "description": ext_ref["description"],
                                }
                                if (
                                    ext_ref["source_name"]
                                    not in external_references_added
                                ):
                                    data_source_obj.external_references = item
                                    external_references_added.add(
                                        ext_ref["source_name"]
                                    )

                        # Get techniques used by data source (using cache)
                        techniques_used_stix = detects_by_source.get(
                            relationship["id"], []
                        )

                        techniques_used = []
                        for techniques_relationship in techniques_used_stix:
                            technique_description = techniques_relationship.get(
                                "description", ""
                            )

                            # Get external references for the technique
                            ext_refs = techniques_relationship.get(
                                "external_references", []
                            )

                            for ext_ref in ext_refs:
                                if "url" in ext_ref and "description" in ext_ref:
                                    item = {
                                        "name": ext_ref["source_name"],
                                        "url": ext_ref["url"],
                                        "description": ext_ref["description"],
                                    }
                                    if (
                                        ext_ref["source_name"]
                                        not in external_references_added
                                    ):
                                        data_source_obj.external_references = item
                                        external_references_added.add(
                                            ext_ref["source_name"]
                                        )

                            # Get technique name and id (using cache)
                            target_ref = techniques_relationship["target_ref"]
                            if target_ref in technique_cache:
                                technique, domain = technique_cache[target_ref]
                                technique_name = technique["name"]
                                ext_refs = technique.get("external_references", [])
                                for ext_ref in ext_refs:
                                    if ext_ref["source_name"] == "mitre-attack":
                                        technique_id = ext_ref["external_id"]

                                item = {
                                    "technique_name": technique_name.replace("/", "／"),  # noqa: RUF001
                                    "technique_id": technique_id,
                                    "description": technique_description,
                                    "domain": domain,
                                }
                                techniques_used.append(item)
                            else:
                                sys.exit(
                                    f"Technique not found: {techniques_relationship['target_ref']} ({data_source_obj.internal_id})"
                                )
                        data_component = {
                            "data_component_name": data_component_name,
                            "data_component_description": data_component_description,
                            "data_component_parent": data_component_parent,
                            "techniques_used": techniques_used,
                        }

                        data_components.append(data_component)

                data_source_obj.data_components = data_components

                self.data_sources.append(data_source_obj)
