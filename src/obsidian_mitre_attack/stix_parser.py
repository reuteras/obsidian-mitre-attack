"""StixParser class to get and parse STIX data."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import gmtime, strftime

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
            futures = {executor.submit(download_domain, domain): domain for domain in domains}
            for future in as_completed(futures):
                domain, stix_json = future.result()
                domain_data[domain] = stix_json

        # Create MemoryStore instances for each domain
        self.enterprise_attack = MemoryStore(stix_data=domain_data["enterprise-attack"]["objects"])
        self.mobile_attack = MemoryStore(stix_data=domain_data["mobile-attack"]["objects"])
        self.ics_attack = MemoryStore(stix_data=domain_data["ics-attack"]["objects"])

        self.verbose_log(message="STIX data loaded successfully")

    def verbose_log(self, message) -> None:
        """Print a message if verbose mode is enabled."""
        if self.verbose:
            print(f"{strftime('%Y-%m-%d %H:%M:%S', gmtime())} - {message}", flush=True)

    @staticmethod
    def is_valid_stix_object(obj: dict) -> bool:
        """Check if STIX object is not deprecated or revoked.

        Args:
            obj: STIX object dictionary

        Returns:
            True if object is valid (not deprecated and not revoked), False otherwise
        """
        is_not_deprecated = "x_mitre_deprecated" not in obj or not obj["x_mitre_deprecated"]
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

                # Extract external references from relationships
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
                                            tactic_obj.external_references = item
                                            external_references_added.add(
                                                ext_ref["source_name"]
                                            )
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

        # Extract techniques
        techniques_stix = self.src.query([Filter("type", "=", "attack-pattern")])
        external_references_added = set()

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

        # Extract techniques
        for tech in techniques_stix:
            if (
                "x_mitre_deprecated" not in tech or not tech["x_mitre_deprecated"]
            ) and ("revoked" not in tech or not tech["revoked"]):
                technique_obj = MITRETechnique(name=tech["name"])
                added = []

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

                # Procedure examples
                procedure_examples_stix = self.src.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="target_ref", op="=", value=technique_obj.internal_id
                        ),
                    ]
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

                        if "malware" in relation["source_ref"]:
                            source_stix = self.src.query(
                                [
                                    Filter(prop="type", op="=", value="malware"),
                                    Filter(
                                        prop="id", op="=", value=relation["source_ref"]
                                    ),
                                ]
                            )
                        elif "tool" in relation["source_ref"]:
                            source_stix = self.src.query(
                                [
                                    Filter(prop="type", op="=", value="tool"),
                                    Filter(
                                        prop="id", op="=", value=relation["source_ref"]
                                    ),
                                ]
                            )
                        elif "intrusion-set" in relation["source_ref"]:
                            source_stix = self.src.query(
                                [
                                    Filter(prop="type", op="=", value="intrusion-set"),
                                    Filter(
                                        prop="id", op="=", value=relation["source_ref"]
                                    ),
                                ]
                            )
                        elif "campaign" in relation["source_ref"]:
                            source_stix = self.src.query(
                                [
                                    Filter(prop="type", op="=", value="campaign"),
                                    Filter(
                                        prop="id", op="=", value=relation["source_ref"]
                                    ),
                                ]
                            )
                        else:
                            sys.exit(f"Unknown source type: {relation['source_ref']}")

                        if source_stix:
                            source = source_stix[0]
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

                # Mitigations
                mitigations_relationships = self.src.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="mitigates"),
                        Filter(
                            prop="target_ref", op="=", value=technique_obj.internal_id
                        ),
                    ]
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
                    # Get mitigation id
                    mitigation = self.src.query(
                        [
                            Filter(prop="type", op="=", value="course-of-action"),
                            Filter(prop="id", op="=", value=relation["source_ref"]),
                        ]
                    )[0]
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
                        item not in added
                        and (
                            "x_mitre_deprecated" not in mitigation
                            or not mitigation["x_mitre_deprecated"]
                        )
                        and ("revoked" not in mitigation or not mitigation["revoked"])
                    ):
                        technique_obj.mitigations = item
                        added.append(item)

                # Detection
                detections_relationships = self.src.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="detects"),
                        Filter(
                            prop="target_ref", op="=", value=technique_obj.internal_id
                        ),
                    ]
                )
                for relation in detections_relationships:
                    data_component = self.src.query(
                        [
                            Filter(prop="type", op="=", value="x-mitre-data-component"),
                            Filter(prop="id", op="=", value=relation["source_ref"]),
                        ]
                    )[0]
                    data_component_name = data_component.get("name", "")
                    data_component_source_ref = data_component.get(
                        "x_mitre_data_source_ref", ""
                    )

                    data_source = self.src.query(
                        [
                            Filter(prop="type", op="=", value="x-mitre-data-source"),
                            Filter(prop="id", op="=", value=data_component_source_ref),
                        ]
                    )[0]
                    data_source_name = data_source.get("name", "")
                    data_source_id = ""
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
                            if ext_ref["source_name"] not in external_references_added:
                                technique_obj.external_references = item
                                external_references_added.add(ext_ref["source_name"])

                    item = {
                        "name": data_component_name,
                        "data_source": data_source_name,
                        "id": data_source_id,
                        "description": relation.get("description", ""),
                    }
                    if item not in added:
                        technique_obj.detections = item
                        added.append(item)

                # Subtechniques
                subtechniques = self.src.query(
                    [
                        Filter(prop="type", op="=", value="attack-pattern"),
                        Filter(prop="x_mitre_is_subtechnique", op="=", value=True),
                        Filter(
                            prop="external_references.external_id",
                            op="contains",
                            value=technique_obj.main_id,
                        ),
                    ]
                )
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
                    if item not in added:
                        technique_obj.targeted_assets = item
                        added.append(item)
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
                added = []

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

                # Get techniques used by group
                tech_group_enterprise_relationships = self.enterprise_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="target_ref", op="contains", value="attack-pattern"
                        ),
                        Filter(prop="source_ref", op="=", value=group_obj.internal_id),
                    ]
                )
                tech_group_mobile_relationships = self.mobile_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="target_ref", op="contains", value="attack-pattern"
                        ),
                        Filter(prop="source_ref", op="=", value=group_obj.internal_id),
                    ]
                )
                tech_group_ics_relationships = self.ics_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="target_ref", op="contains", value="attack-pattern"
                        ),
                        Filter(prop="source_ref", op="=", value=group_obj.internal_id),
                    ]
                )

                tech_group_relationships = (
                    tech_group_enterprise_relationships
                    + tech_group_mobile_relationships
                    + tech_group_ics_relationships
                )

                for tech_group_rel in tech_group_relationships:
                    if (
                        "x_mitre_deprecated" not in tech_group_rel
                        or not tech_group_rel["x_mitre_deprecated"]
                    ) and (
                        "revoked" not in tech_group_rel or not tech_group_rel["revoked"]
                    ):
                        technique_stix = self.enterprise_attack.query(
                            [
                                Filter(
                                    prop="id",
                                    op="=",
                                    value=tech_group_rel["target_ref"],
                                )
                            ]
                        )
                        domain = "enterprise-attack"
                        if not technique_stix:
                            technique_stix = self.mobile_attack.query(
                                [
                                    Filter(
                                        prop="id",
                                        op="=",
                                        value=tech_group_rel["target_ref"],
                                    )
                                ]
                            )
                            domain = "mobile-attack"
                        if not technique_stix:
                            technique_stix = self.ics_attack.query(
                                [
                                    Filter(
                                        prop="id",
                                        op="=",
                                        value=tech_group_rel["target_ref"],
                                    )
                                ]
                            )
                            domain = "ics-attack"

                        if technique_stix:
                            technique = technique_stix[0]

                            ext_refs = technique.get("external_references", [])
                            for ext_ref in ext_refs:
                                if ext_ref["source_name"] == "mitre-attack":
                                    technique_id = ext_ref["external_id"]
                            ext_refs = tech_group_rel.get("external_references", [])
                            if "url" in ext_ref and "description" in ext_ref:
                                item = {
                                    "name": ext_ref["source_name"].replace("/", "／"),  # noqa: RUF001
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
                                "technique_name": technique.name.replace("/", "／"),  # noqa: RUF001
                                "technique_id": technique_id,
                                "description": tech_group_rel.get("description", ""),
                                "domain": domain,
                            }
                        else:
                            sys.exit(
                                f"Technique not found: {tech_group_rel['target_ref']}"
                            )

                # Get software used by group
                software_enterprise_relationships_malware = (
                    self.enterprise_attack.query(
                        [
                            Filter(prop="type", op="=", value="relationship"),
                            Filter(prop="relationship_type", op="=", value="uses"),
                            Filter(prop="target_ref", op="contains", value="malware"),
                            Filter(
                                prop="source_ref", op="=", value=group_obj.internal_id
                            ),
                        ]
                    )
                )
                software_enterprise_relationships_tool = self.enterprise_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(prop="target_ref", op="contains", value="tool"),
                        Filter(prop="source_ref", op="=", value=group_obj.internal_id),
                    ]
                )
                software_mobile_relationships_malware = self.mobile_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(prop="target_ref", op="contains", value="malware"),
                        Filter(prop="source_ref", op="=", value=group_obj.internal_id),
                    ]
                )
                software_mobile_relationships_tool = self.mobile_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(prop="target_ref", op="contains", value="tool"),
                        Filter(prop="source_ref", op="=", value=group_obj.internal_id),
                    ]
                )
                software_ics_relationships_malware = self.ics_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(prop="target_ref", op="contains", value="malware"),
                        Filter(prop="source_ref", op="=", value=group_obj.internal_id),
                    ]
                )
                software_ics_relationships_tool = self.ics_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(prop="target_ref", op="contains", value="tool"),
                        Filter(prop="source_ref", op="=", value=group_obj.internal_id),
                    ]
                )
                software_relationships = (
                    software_enterprise_relationships_malware
                    + software_enterprise_relationships_tool
                    + software_mobile_relationships_malware
                    + software_mobile_relationships_tool
                    + software_ics_relationships_malware
                    + software_ics_relationships_tool
                )

                for group_software_rel in software_relationships:
                    if (
                        "x_mitre_deprecated" not in group_software_rel
                        or not group_software_rel["x_mitre_deprecated"]
                    ) and (
                        "revoked" not in group_software_rel
                        or not group_software_rel["revoked"]
                    ):
                        software_id: str = ""
                        software_name: str = ""

                        # Get software name
                        software_name_stix = self.enterprise_attack.query(
                            [
                                Filter(
                                    prop="id",
                                    op="=",
                                    value=group_software_rel["target_ref"],
                                ),
                            ]
                        )
                        domain = "enterprise-attack"
                        if not software_name_stix:
                            software_name_stix = self.mobile_attack.query(
                                [
                                    Filter(
                                        prop="id",
                                        op="=",
                                        value=group_software_rel["target_ref"],
                                    ),
                                ]
                            )
                            domain = "mobile-attack"
                        if not software_name_stix:
                            software_name_stix = self.ics_attack.query(
                                [
                                    Filter(
                                        prop="id",
                                        op="=",
                                        value=group_software_rel["target_ref"],
                                    ),
                                ]
                            )
                            domain = "ics-attack"

                        if software_name_stix:
                            software_name = software_name_stix[0].name
                            ext_refs = software_name_stix[0].get(
                                "external_references", []
                            )
                            for ext_ref in ext_refs:
                                if ext_ref["source_name"] == "mitre-attack":
                                    software_id = ext_ref["external_id"]

                        if not software_name or not software_id:
                            sys.exit(
                                f"Software not found: {group_software_rel['target_ref']}"
                            )

                        # Get technique name used by software
                        source_relationships_enterprise = self.enterprise_attack.query(
                            [
                                Filter(prop="type", op="=", value="relationship"),
                                Filter(prop="relationship_type", op="=", value="uses"),
                                Filter(
                                    prop="target_ref",
                                    op="contains",
                                    value="attack-pattern",
                                ),
                                Filter(
                                    prop="source_ref",
                                    op="=",
                                    value=group_software_rel["target_ref"],
                                ),
                            ]
                        )
                        source_relationships_mobile = self.mobile_attack.query(
                            [
                                Filter(prop="type", op="=", value="relationship"),
                                Filter(prop="relationship_type", op="=", value="uses"),
                                Filter(
                                    prop="target_ref",
                                    op="contains",
                                    value="attack-pattern",
                                ),
                                Filter(
                                    prop="source_ref",
                                    op="=",
                                    value=group_software_rel["target_ref"],
                                ),
                            ]
                        )
                        source_relationships_ics = self.ics_attack.query(
                            [
                                Filter(prop="type", op="=", value="relationship"),
                                Filter(prop="relationship_type", op="=", value="uses"),
                                Filter(
                                    prop="target_ref",
                                    op="contains",
                                    value="attack-pattern",
                                ),
                                Filter(
                                    prop="source_ref",
                                    op="=",
                                    value=group_software_rel["target_ref"],
                                ),
                            ]
                        )
                        source_relationships = (
                            source_relationships_enterprise
                            + source_relationships_mobile
                            + source_relationships_ics
                        )
                        markdown_links: str = ""

                        for relationship in source_relationships:
                            technique_relationship_enterprise = (
                                self.enterprise_attack.query(
                                    [
                                        Filter(
                                            prop="type", op="=", value="attack-pattern"
                                        ),
                                        Filter(
                                            prop="x_mitre_deprecated",
                                            op="=",
                                            value=False,
                                        ),
                                        Filter(prop="revoked", op="=", value=False),
                                        Filter(
                                            prop="id",
                                            op="=",
                                            value=relationship["target_ref"],
                                        ),
                                    ]
                                )
                            )
                            technique_relationship_mobile = self.mobile_attack.query(
                                [
                                    Filter(prop="type", op="=", value="attack-pattern"),
                                    Filter(
                                        prop="x_mitre_deprecated", op="=", value=False
                                    ),
                                    Filter(prop="revoked", op="=", value=False),
                                    Filter(
                                        prop="id",
                                        op="=",
                                        value=relationship["target_ref"],
                                    ),
                                ]
                            )
                            technique_relationship_ics = self.ics_attack.query(
                                [
                                    Filter(prop="type", op="=", value="attack-pattern"),
                                    Filter(
                                        prop="x_mitre_deprecated", op="=", value=False
                                    ),
                                    Filter(prop="revoked", op="=", value=False),
                                    Filter(
                                        prop="id",
                                        op="=",
                                        value=relationship["target_ref"],
                                    ),
                                ]
                            )
                            technique_relationship = (
                                technique_relationship_enterprise
                                + technique_relationship_mobile
                                + technique_relationship_ics
                            )

                            if technique_relationship:
                                technique_name = technique_relationship[0]["name"]
                                technique_id: str = ""
                                for ext_ref in technique_relationship[0].get(
                                    "external_references", []
                                ):
                                    if ext_ref["source_name"] == "mitre-attack":
                                        technique_id = ext_ref["external_id"]
                                if technique_relationship[0]["x_mitre_is_subtechnique"]:
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
                        if item not in added:
                            group_obj.software_used = item
                            added.append(item)

                self.groups.append(group_obj)

    def _get_software(self) -> None:  # noqa: PLR0912, PLR0915
        """Get and parse software from STIX data."""
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

        self.software = list()

        for software in software_stix:
            if (
                "x_mitre_deprecated" not in software
                or not software["x_mitre_deprecated"]
            ) and ("revoked" not in software or not software["revoked"]):
                software_obj = MITRESoftware(name=software["name"])
                added = []
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

                # Techniques used by software
                source_relationships_enterprise = self.enterprise_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="source_ref", op="=", value=software_obj.internal_id
                        ),
                    ]
                )
                source_relationships_mobile = self.mobile_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="source_ref", op="=", value=software_obj.internal_id
                        ),
                    ]
                )
                source_relationships_ics = self.ics_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="source_ref", op="=", value=software_obj.internal_id
                        ),
                    ]
                )

                source_relationships = (
                    source_relationships_enterprise
                    + source_relationships_mobile
                    + source_relationships_ics
                )

                for relationship in source_relationships:
                    techniques_enterprise_stix = self.enterprise_attack.query(
                        [
                            Filter(prop="type", op="=", value="attack-pattern"),
                            Filter(prop="id", op="=", value=relationship["target_ref"]),
                        ]
                    )
                    techniques_mobile_stix = self.mobile_attack.query(
                        [
                            Filter(prop="type", op="=", value="attack-pattern"),
                            Filter(prop="id", op="=", value=relationship["target_ref"]),
                        ]
                    )
                    techniques_ics_stix = self.ics_attack.query(
                        [
                            Filter(prop="type", op="=", value="attack-pattern"),
                            Filter(prop="id", op="=", value=relationship["target_ref"]),
                        ]
                    )

                    techniques_stix = (
                        techniques_enterprise_stix
                        + techniques_mobile_stix
                        + techniques_ics_stix
                    )
                    if techniques_stix:
                        technique = techniques_stix[0]
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

                # Software has been used in these campaigns
                source_relationships_enterprise = self.enterprise_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="target_ref", op="=", value=software_obj.internal_id
                        ),
                    ]
                )
                source_relationships_mobile = self.mobile_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="target_ref", op="=", value=software_obj.internal_id
                        ),
                    ]
                )
                source_relationships_ics = self.ics_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="target_ref", op="=", value=software_obj.internal_id
                        ),
                    ]
                )

                source_relationships = (
                    source_relationships_enterprise
                    + source_relationships_mobile
                    + source_relationships_ics
                )

                for relationship in source_relationships:
                    if relationship["source_ref"].startswith("campaign"):
                        campaign_enterprise_stix = self.enterprise_attack.query(
                            [
                                Filter(prop="type", op="=", value="campaign"),
                                Filter(
                                    prop="id", op="=", value=relationship["source_ref"]
                                ),
                            ]
                        )
                        campaign_mobile_stix = self.mobile_attack.query(
                            [
                                Filter(prop="type", op="=", value="campaign"),
                                Filter(
                                    prop="id", op="=", value=relationship["source_ref"]
                                ),
                            ]
                        )
                        campaign_ics_stix = self.ics_attack.query(
                            [
                                Filter(prop="type", op="=", value="campaign"),
                                Filter(
                                    prop="id", op="=", value=relationship["source_ref"]
                                ),
                            ]
                        )

                        campaigns_stix = (
                            campaign_enterprise_stix
                            + campaign_mobile_stix
                            + campaign_ics_stix
                        )

                        for campaign in campaigns_stix:
                            if (
                                "x_mitre_deprecated" not in campaign
                                or not campaign["x_mitre_deprecated"]
                            ) and (
                                "revoked" not in campaign or not campaign["revoked"]
                            ):
                                ext_refs = campaign.get("external_references", [])
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
                                if item not in added:
                                    software_obj.campaigns_using = item
                                    added.append(item)

                # Groups using the software
                target_relationships_enterprise = self.enterprise_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="target_ref", op="=", value=software_obj.internal_id
                        ),
                    ]
                )
                target_relationships_mobile = self.mobile_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="target_ref", op="=", value=software_obj.internal_id
                        ),
                    ]
                )
                target_relationships_ics = self.ics_attack.query(
                    [
                        Filter(prop="type", op="=", value="relationship"),
                        Filter(prop="relationship_type", op="=", value="uses"),
                        Filter(
                            prop="target_ref", op="=", value=software_obj.internal_id
                        ),
                    ]
                )

                target_relationships = (
                    target_relationships_enterprise
                    + target_relationships_mobile
                    + target_relationships_ics
                )

                group_added = []
                for relationship in target_relationships:
                    if (
                        relationship["source_ref"].startswith("intrusion-set")
                        and (
                            "x_mitre_deprecated" not in relationship
                            or not relationship["x_mitre_deprecated"]
                        )
                        and (
                            "revoked" not in relationship or not relationship["revoked"]
                        )
                    ):
                        group_enterprise_stix = self.enterprise_attack.query(
                            [
                                Filter(prop="type", op="=", value="intrusion-set"),
                                Filter(
                                    prop="id", op="=", value=relationship["source_ref"]
                                ),
                            ]
                        )
                        group_mobile_stix = self.mobile_attack.query(
                            [
                                Filter(prop="type", op="=", value="intrusion-set"),
                                Filter(
                                    prop="id", op="=", value=relationship["source_ref"]
                                ),
                            ]
                        )
                        group_ics_stix = self.ics_attack.query(
                            [
                                Filter(prop="type", op="=", value="intrusion-set"),
                                Filter(
                                    prop="id", op="=", value=relationship["source_ref"]
                                ),
                            ]
                        )

                        group_stix = (
                            group_enterprise_stix + group_mobile_stix + group_ics_stix
                        )

                        group_id: str = ""
                        descriptions: str = ""
                        for groupinfo in group_stix:
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

                            for software_campaign in software_obj.campaigns_using:
                                campaign_id = software_campaign.get(
                                    "campaign_internal_id"
                                )
                                campaign_enterprise_stix = self.enterprise_attack.query(
                                    [
                                        Filter(
                                            prop="type", op="=", value="relationship"
                                        ),
                                        Filter(
                                            prop="relationship_type",
                                            op="=",
                                            value="attributed-to",
                                        ),
                                        Filter(
                                            prop="source_ref", op="=", value=campaign_id
                                        ),
                                        Filter(
                                            prop="target_ref",
                                            op="=",
                                            value=groupinfo["id"],
                                        ),
                                    ]
                                )
                                campaign_mobile_stix = self.mobile_attack.query(
                                    [
                                        Filter(
                                            prop="type", op="=", value="relationship"
                                        ),
                                        Filter(
                                            prop="relationship_type",
                                            op="=",
                                            value="attributed-to",
                                        ),
                                        Filter(
                                            prop="source_ref", op="=", value=campaign_id
                                        ),
                                        Filter(
                                            prop="target_ref",
                                            op="=",
                                            value=groupinfo["id"],
                                        ),
                                    ]
                                )
                                campaign_ics_stix = self.ics_attack.query(
                                    [
                                        Filter(
                                            prop="type", op="=", value="relationship"
                                        ),
                                        Filter(
                                            prop="relationship_type",
                                            op="=",
                                            value="attributed-to",
                                        ),
                                        Filter(
                                            prop="source_ref", op="=", value=campaign_id
                                        ),
                                        Filter(
                                            prop="target_ref",
                                            op="=",
                                            value=groupinfo["id"],
                                        ),
                                    ]
                                )

                                campaigns_stix = (
                                    campaign_enterprise_stix
                                    + campaign_mobile_stix
                                    + campaign_ics_stix
                                )

                                for campaign in campaigns_stix:
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
                    added = []
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
                            if item not in added:
                                campaign_obj.external_references = item
                                added.append(item)

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
                                    if item not in added:
                                        campaign_obj.external_references = item
                                        added.append(item)

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

                # Get data components used by data source
                data_source_relationships_enterprise = self.enterprise_attack.query(
                    [
                        Filter(
                            prop="x_mitre_data_source_ref",
                            op="=",
                            value=data_source_obj.internal_id,
                        ),
                    ]
                )
                data_source_relationships_mobile = self.mobile_attack.query(
                    [
                        Filter(
                            prop="x_mitre_data_source_ref",
                            op="=",
                            value=data_source_obj.internal_id,
                        ),
                    ]
                )
                data_source_relationships_ics = self.ics_attack.query(
                    [
                        Filter(
                            prop="x_mitre_data_source_ref",
                            op="=",
                            value=data_source_obj.internal_id,
                        ),
                    ]
                )

                data_source_relationships = (
                    data_source_relationships_enterprise
                    + data_source_relationships_mobile
                    + data_source_relationships_ics
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

                        # Get techniques used by data source
                        enterprise_technique_stix = self.enterprise_attack.query(
                            [
                                Filter(prop="type", op="=", value="relationship"),
                                Filter(
                                    prop="relationship_type", op="=", value="detects"
                                ),
                                Filter(
                                    prop="source_ref", op="=", value=relationship["id"]
                                ),
                            ]
                        )
                        mobile_technique_stix = self.mobile_attack.query(
                            [
                                Filter(prop="type", op="=", value="relationship"),
                                Filter(
                                    prop="relationship_type", op="=", value="detects"
                                ),
                                Filter(
                                    prop="source_ref", op="=", value=relationship["id"]
                                ),
                            ]
                        )
                        ics_technique_stix = self.ics_attack.query(
                            [
                                Filter(prop="type", op="=", value="relationship"),
                                Filter(
                                    prop="relationship_type", op="=", value="detects"
                                ),
                                Filter(
                                    prop="source_ref", op="=", value=relationship["id"]
                                ),
                            ]
                        )

                        techniques_used_stix = (
                            enterprise_technique_stix
                            + mobile_technique_stix
                            + ics_technique_stix
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

                            # Get technique name and id
                            technique_stix = self.enterprise_attack.query(
                                [
                                    Filter(
                                        prop="id",
                                        op="=",
                                        value=techniques_relationship["target_ref"],
                                    ),
                                ]
                            )
                            domain = "enterprise-attack"

                            if not technique_stix:
                                technique_stix = self.mobile_attack.query(
                                    [
                                        Filter(
                                            prop="id",
                                            op="=",
                                            value=techniques_relationship["target_ref"],
                                        ),
                                    ]
                                )
                                domain = "mobile-attack"
                            if not technique_stix:
                                technique_stix = self.ics_attack.query(
                                    [
                                        Filter(
                                            prop="id",
                                            op="=",
                                            value=techniques_relationship["target_ref"],
                                        ),
                                    ]
                                )
                                domain = "ics-attack"

                            if technique_stix:
                                technique = technique_stix[0]
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
