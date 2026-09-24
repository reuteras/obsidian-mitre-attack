"""AtlasParser class to get and parse MITRE ATLAS data."""

from __future__ import annotations

from typing import Any

import requests
import yaml

from .atlas_models import (
    ATLASCaseStudy,
    ATLASMitigation,
    ATLASTactic,
    ATLASTechnique,
)

# The ATLAS matrix's own id in the "relationships" section, used to look up
# tactic ordering via "sequences" relationships.
ATLAS_MATRIX_ID = "ATLAS-matrix"

# format-version used by this parser. The manifest.yaml lists one or more
# formats per release; we always pick this one.
ATLAS_FORMAT_VERSION_PREFIX = "6."


class AtlasParser:
    """Get and parse MITRE ATLAS data, creating Tactic, Technique, Mitigation and Case Study objects.

    Gets the ATLAS data (YAML) from the mitre-atlas/atlas-data GitHub repository.
    """

    def __init__(
        self, repo_url: str, version: str = "latest", verbose: bool = False
    ) -> None:
        """Initialize the AtlasParser object."""
        self.url: str = repo_url
        self.version: str = version
        self.verbose: bool = verbose

        self.tactics: list[ATLASTactic] = []
        self.techniques: list[ATLASTechnique] = []
        self.mitigations: list[ATLASMitigation] = []
        self.case_studies: list[ATLASCaseStudy] = []

        self.resolved_version: str = ""
        self.data: dict[str, Any] = {}

    def verbose_log(self, message) -> None:
        """Print a message if verbose mode is enabled."""
        if self.verbose:
            print(message, flush=True)

    def _resolve_source_url(self) -> str:
        """Resolve the requested version to a concrete, non-symlink YAML URL.

        dist/ATLAS-latest.yaml (and dist/v6/ATLAS-latest.yaml) are git symlinks;
        GitHub's raw server returns their literal target path as text rather than
        resolving them, so we resolve the actual file via dist/manifest.yaml
        instead, which lists concrete paths per release.
        """
        manifest_url = f"{self.url}/dist/manifest.yaml"
        self.verbose_log(message=f"Getting ATLAS manifest from {manifest_url}")
        response = requests.get(url=manifest_url, timeout=30)
        response.raise_for_status()
        manifest: list[dict[str, Any]] = yaml.safe_load(response.text)

        if self.version == "latest":
            release = manifest[0]
        else:
            matches = [
                entry for entry in manifest if str(entry["release"]) == self.version
            ]
            if not matches:
                raise ValueError(
                    f"ATLAS release '{self.version}' not found in manifest.yaml"
                )
            release = matches[0]

        self.resolved_version = str(release["release"])
        format_matches = [
            entry
            for entry in release["versions"]
            if str(entry["format-version"]).startswith(ATLAS_FORMAT_VERSION_PREFIX)
        ]
        if not format_matches:
            raise ValueError(
                f"ATLAS release '{self.resolved_version}' has no format-version "
                f"{ATLAS_FORMAT_VERSION_PREFIX}x entry"
            )
        path = format_matches[0]["path"]
        return f"{self.url}/dist/{path}"

    def get_data(self) -> None:
        """Download and load the ATLAS YAML data."""
        source_url = self._resolve_source_url()
        self.verbose_log(
            message=f"Getting ATLAS data (release {self.resolved_version}) from {source_url}"
        )
        response = requests.get(url=source_url, timeout=30)
        response.raise_for_status()
        self.data = yaml.safe_load(response.text)
        self.verbose_log(message="ATLAS data loaded successfully")

    def parse(self) -> None:
        """Parse tactics, techniques, mitigations, and case studies from ATLAS data."""
        relationships: dict[str, dict[str, list[dict[str, Any]]]] = self.data.get(
            "relationships", {}
        )

        self.verbose_log(message="Parsing ATLAS tactics")
        self._parse_tactics(relationships=relationships)
        self.verbose_log(message="Parsing ATLAS techniques")
        self._parse_techniques(relationships=relationships)
        self.verbose_log(message="Parsing ATLAS mitigations")
        self._parse_mitigations(relationships=relationships)
        self.verbose_log(message="Parsing ATLAS case studies")
        self._parse_case_studies(relationships=relationships)
        self.verbose_log(message="Linking ATLAS tactics to techniques")
        self._link_tactics_to_techniques()
        self.verbose_log(message="ATLAS data parsed successfully")

    def _parse_tactics(
        self, relationships: dict[str, dict[str, list[dict[str, Any]]]]
    ) -> None:
        """Parse tactics and their position on the ATLAS matrix."""
        positions: dict[str, int] = {}
        for sequence in relationships.get(ATLAS_MATRIX_ID, {}).get("sequences", []):
            positions[sequence["target"]] = sequence.get("position", 0)

        for tactic_id, tactic in self.data.get("tactics", {}).items():
            tactic_obj = ATLASTactic(name=tactic["name"])
            tactic_obj.id = tactic_id
            tactic_obj.description = tactic.get("description", "")
            tactic_obj.created = tactic.get("created-date", "")
            tactic_obj.modified = tactic.get("modified-date", "")
            tactic_obj.url = f"https://atlas.mitre.org/tactics/{tactic_id}"
            tactic_obj.position = positions.get(tactic_id, 0)
            self.tactics.append(tactic_obj)

    def _parse_techniques(
        self, relationships: dict[str, dict[str, list[dict[str, Any]]]]
    ) -> None:
        """Parse techniques, resolving tactic and parent/subtechnique relationships."""
        techniques_data: dict[str, dict[str, Any]] = self.data.get("techniques", {})
        tactic_names: dict[str, str] = {
            tactic_id: tactic["name"]
            for tactic_id, tactic in self.data.get("tactics", {}).items()
        }

        technique_by_id: dict[str, ATLASTechnique] = {}

        for technique_id, technique in techniques_data.items():
            technique_obj = ATLASTechnique(name=technique["name"])
            technique_obj.id = technique_id
            technique_obj.description = technique.get("description", "")
            technique_obj.created = technique.get("created-date", "")
            technique_obj.modified = technique.get("modified-date", "")
            technique_obj.platforms = technique.get("platforms", [])
            technique_obj.maturity = technique.get("maturity", "")
            technique_obj.url = f"https://atlas.mitre.org/techniques/{technique_id}"

            attack_reference = technique.get("attack-reference")
            if attack_reference:
                technique_obj.attack_reference = {
                    "id": attack_reference.get("id", ""),
                    "url": attack_reference.get("url", ""),
                }

            technique_relationships = relationships.get(technique_id, {})

            for achieves in technique_relationships.get("achieves", []):
                tactic_id = achieves["target"]
                technique_obj.tactic_id = tactic_id
                technique_obj.tactic_name = tactic_names.get(tactic_id, "")

            for specializes in technique_relationships.get("specializes", []):
                technique_obj.is_subtechnique = True
                technique_obj.parent_id = specializes["target"]

            technique_obj.main_id = (
                technique_obj.parent_id
                if technique_obj.is_subtechnique
                else technique_id
            )

            technique_by_id[technique_id] = technique_obj
            self.techniques.append(technique_obj)

        # Resolve parent name and build the parent's subtechniques list.
        for technique_obj in self.techniques:
            if (
                technique_obj.is_subtechnique
                and technique_obj.parent_id in technique_by_id
            ):
                parent = technique_by_id[technique_obj.parent_id]
                technique_obj.parent_name = parent.name
                parent.subtechniques = {
                    "id": technique_obj.id,
                    "name": technique_obj.name,
                }

    def _parse_mitigations(
        self, relationships: dict[str, dict[str, list[dict[str, Any]]]]
    ) -> None:
        """Parse mitigations and their mitigated techniques, linking back to techniques."""
        technique_by_id: dict[str, ATLASTechnique] = {
            technique.id: technique for technique in self.techniques
        }
        technique_names: dict[str, str] = {
            technique_id: technique["name"]
            for technique_id, technique in self.data.get("techniques", {}).items()
        }

        for mitigation_id, mitigation in self.data.get("mitigations", {}).items():
            mitigation_obj = ATLASMitigation(name=mitigation["name"])
            mitigation_obj.id = mitigation_id
            mitigation_obj.description = mitigation.get("description", "")
            mitigation_obj.created = mitigation.get("created-date", "")
            mitigation_obj.modified = mitigation.get("modified-date", "")
            mitigation_obj.lifecycle_phases = mitigation.get("lifecycle-phases", [])
            mitigation_obj.categories = mitigation.get("categories", [])
            mitigation_obj.url = f"https://atlas.mitre.org/mitigations/{mitigation_id}"

            for mitigates in relationships.get(mitigation_id, {}).get("mitigates", []):
                technique_id = mitigates["target"]
                item = {
                    "id": technique_id,
                    "name": technique_names.get(technique_id, ""),
                    "description": mitigates.get("description", ""),
                }
                mitigation_obj.techniques_mitigated = item

                technique_obj = technique_by_id.get(technique_id)
                if technique_obj is not None:
                    technique_obj.mitigations = {
                        "id": mitigation_id,
                        "name": mitigation_obj.name,
                        "description": mitigates.get("description", ""),
                    }

            self.mitigations.append(mitigation_obj)

    def _parse_case_studies(
        self, relationships: dict[str, dict[str, list[dict[str, Any]]]]
    ) -> None:
        """Parse case studies and their procedure steps, linking back to techniques."""
        technique_by_id: dict[str, ATLASTechnique] = {
            technique.id: technique for technique in self.techniques
        }
        technique_names: dict[str, str] = {
            technique_id: technique["name"]
            for technique_id, technique in self.data.get("techniques", {}).items()
        }
        tactic_names: dict[str, str] = {
            tactic_id: tactic["name"]
            for tactic_id, tactic in self.data.get("tactics", {}).items()
        }

        for case_study_id, case_study in self.data.get("case-studies", {}).items():
            case_study_obj = ATLASCaseStudy(name=case_study["name"])
            case_study_obj.id = case_study_id
            case_study_obj.description = case_study.get("description", "")
            case_study_obj.created = case_study.get("created-date", "")
            case_study_obj.modified = case_study.get("modified-date", "")
            case_study_obj.type = case_study.get("type", "")
            case_study_obj.actor = case_study.get("actor", "")
            case_study_obj.target = case_study.get("target", "")
            case_study_obj.date = case_study.get("date", "")
            case_study_obj.date_granularity = case_study.get("date-granularity", "")
            # atlas.mitre.org's URL path for case studies is not confirmed against
            # the live site (it renders client-side and direct fetches 404'd); this
            # is a best-effort guess following the site's other "/{plural}/{id}"
            # patterns.
            case_study_obj.url = f"https://atlas.mitre.org/studies/{case_study_id}"

            for reference in case_study.get("references", []):
                case_study_obj.references = {
                    "id": reference.get("id", ""),
                    "title": reference.get("title", ""),
                    "url": reference.get("url", ""),
                }

            steps = relationships.get(case_study_id, {}).get("employs", [])
            for step in sorted(steps, key=lambda s: s.get("step-id", "")):
                technique_id = step["target"]
                tactic_id = step.get("tactic", "")
                step_item = {
                    "step_id": step.get("step-id", ""),
                    "tactic_id": tactic_id,
                    "tactic_name": tactic_names.get(tactic_id, ""),
                    "technique_id": technique_id,
                    "technique_name": technique_names.get(technique_id, ""),
                    "description": step.get("description", ""),
                }
                case_study_obj.procedure = step_item

                technique_obj = technique_by_id.get(technique_id)
                if technique_obj is not None:
                    technique_obj.case_studies = {
                        "id": case_study_id,
                        "name": case_study_obj.name,
                        "description": step.get("description", ""),
                    }

            self.case_studies.append(case_study_obj)

    def _link_tactics_to_techniques(self) -> None:
        """Populate each tactic's techniques_used list from parsed techniques."""
        tactics_by_id: dict[str, ATLASTactic] = {
            tactic.id: tactic for tactic in self.tactics
        }
        for technique in self.techniques:
            tactic_obj = tactics_by_id.get(technique.tactic_id)
            if tactic_obj is not None:
                tactic_obj.techniques_used = {
                    "id": technique.id,
                    "name": technique.name,
                    "description": technique.description,
                }
