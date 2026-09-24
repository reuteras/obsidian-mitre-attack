"""Generate markdown notes for MITRE ATLAS data."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# Matches inline markdown links to other ATLAS objects, e.g.
# "[Create Proxy AI Model](/techniques/AML.T0005)". These are the only
# relative-link prefixes actually used in the ATLAS data (verified against the
# 2026.09 release).
ATLAS_LINK_PATTERN = re.compile(
    r"\[([^\]]*?)\]\(/(?:techniques|tactics|mitigations)/([^\)]+?)\)"
)


def convert_atlas_local_links(text: str) -> str:
    """Convert inline ATLAS markdown links to Obsidian wikilinks."""

    def match_link(match: Any) -> str:
        name: str = match.group(1).replace("/", "／").replace(":", ";")  # noqa: RUF001
        atlas_id: str = match.group(2)
        return f"[[{name} - {atlas_id}]]"

    return ATLAS_LINK_PATTERN.sub(match_link, text)


class AtlasMarkdownGenerator:
    """Class to generate markdown notes for MITRE ATLAS data."""

    def __init__(
        self,
        output_dir: str,
        atlas_data,
        arguments,
        config: dict | None = None,
    ) -> None:
        """Initialize the class."""
        self.output_dir = Path(output_dir, "ATLAS")
        self.tactics = atlas_data.tactics
        self.techniques = atlas_data.techniques
        self.mitigations = atlas_data.mitigations
        self.case_studies = atlas_data.case_studies
        self.tags_prefix = arguments.tags
        self.config = config or {}

    def create_tactic_notes(self) -> None:
        """Function to create markdown notes for ATLAS tactics."""
        tactics_dir = Path(self.output_dir, "Tactics")
        tactics_dir.mkdir(parents=True, exist_ok=True)

        for tactic in self.tactics:
            tactic_file = Path(tactics_dir, f"{tactic.name} - {tactic.id}.md")

            lines = [
                "---\naliases:",
                f"  - {tactic.id}",
                f"  - {tactic.name}",
                f"  - {tactic.name} ({tactic.id})",
                f"  - {tactic.id} ({tactic.name})",
                "url: ATLAS_URL",
                "tags:",
                f"  - {self.tags_prefix}atlas",
                f"  - {self.tags_prefix}atlas_tactic",
                "---",
                "",
                f"## {tactic.id}",
                "",
                tactic.description,
                "",
                "> [!info]",
                f"> ID: {tactic.id}",
                f"> Created: {tactic.created}",
                f"> Last Modified: {tactic.modified}",
                "",
                "",
            ]

            if tactic.techniques_used:
                lines.extend(
                    [
                        "### Techniques",
                        "",
                        "| ID | Name | Description |",
                        "| --- | --- | --- |",
                    ]
                )
                for technique in sorted(tactic.techniques_used, key=lambda x: x["id"]):
                    description: str = technique["description"].split("\n")[0]
                    lines.append(
                        f"| [[{technique['name']} - {technique['id']} \\| {technique['id']}]] | {technique['name']} | {description} |"
                    )

            content = "\n".join(lines)
            content = convert_atlas_local_links(text=content)
            content = content.replace("ATLAS_URL", tactic.url)
            with open(file=tactic_file, mode="w", encoding="utf-8") as fd:
                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")

    def create_technique_notes(self) -> None:  # noqa: PLR0912, PLR0915
        """Function to create markdown notes for ATLAS techniques."""
        techniques_dir = Path(self.output_dir, "Techniques")
        techniques_dir.mkdir(parents=True, exist_ok=True)

        for technique in self.techniques:
            technique_file = Path(
                techniques_dir, f"{technique.name} - {technique.id}.md"
            )

            lines = [
                "---\naliases:",
                f"  - {technique.id}",
                f"  - {technique.name}",
                f"  - {technique.name} ({technique.id})",
                f"  - {technique.id} ({technique.name})",
                "url: ATLAS_URL",
                "tags:",
                f"  - {self.tags_prefix}atlas",
                f"  - {self.tags_prefix}atlas_technique",
            ]
            for platform in technique.platforms:
                if platform:
                    lines.append(f"  - {self.tags_prefix}{platform.replace(' ', '_')}")
            lines.extend(["---", ""])

            if technique.is_subtechnique:
                lines.append(f"## {technique.parent_name}: {technique.name}")
            else:
                lines.append(f"## {technique.name}")
            lines.extend(["", technique.description, ""])

            lines.append("> [!info]")
            lines.append(f"> ID: {technique.id}")
            if technique.is_subtechnique:
                lines.append(
                    f"> Sub-technique of: [[{technique.parent_name} - {technique.main_id} \\| {technique.main_id}]]"
                )
            elif technique.subtechniques:
                sub_links = [
                    f"[[{sub['name']} - {sub['id']} \\| {sub['id']}]]"
                    for sub in sorted(technique.subtechniques, key=lambda x: x["id"])
                ]
                lines.append(f"> Sub-techniques: {', '.join(sub_links)}")
            if technique.tactic_id:
                lines.append(
                    f"> Tactic: [[{technique.tactic_name} - {technique.tactic_id} \\| {technique.tactic_name}]]"
                )
            if technique.maturity:
                lines.append(f"> Maturity: {technique.maturity}")
            if technique.platforms:
                lines.append(f"> Platforms: {', '.join(technique.platforms)}")
            if technique.attack_reference:
                attack_id = technique.attack_reference.get("id", "")
                attack_url = technique.attack_reference.get("url", "")
                if attack_id and attack_url:
                    lines.append(f"> ATT&CK Technique: [{attack_id}]({attack_url})")
            lines.extend(
                [
                    f"> Created: {technique.created}",
                    f"> Last Modified: {technique.modified}",
                    "",
                    "",
                ]
            )

            lines.append("### Mitigations")
            if technique.mitigations:
                lines.extend(["", "| ID | Name | Description |", "| --- | --- | --- |"])
                for mitigation in sorted(technique.mitigations, key=lambda x: x["id"]):
                    description = mitigation["description"].replace("\n", "<br />")
                    lines.append(
                        f"| [[{mitigation['name']} - {mitigation['id']} \\| {mitigation['id']}]] | [[{mitigation['name']} - {mitigation['id']} \\| {mitigation['name']}]] | {description} |"
                    )
            else:
                lines.append("")
                lines.append("No mitigations documented for this technique.")

            if technique.case_studies:
                lines.extend(
                    [
                        "",
                        "",
                        "### Case Studies",
                        "",
                        "| ID | Name | Description |",
                        "| --- | --- | --- |",
                    ]
                )
                for case_study in sorted(technique.case_studies, key=lambda x: x["id"]):
                    description = case_study["description"].replace("\n", "<br />")
                    lines.append(
                        f"| [[{case_study['name']} - {case_study['id']} \\| {case_study['id']}]] | [[{case_study['name']} - {case_study['id']} \\| {case_study['name']}]] | {description} |"
                    )

            content = "\n".join(lines)
            content = convert_atlas_local_links(text=content)
            content = content.replace("ATLAS_URL", technique.url)
            with open(file=technique_file, mode="w", encoding="utf-8") as fd:
                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")

    def create_mitigation_notes(self) -> None:
        """Function to create markdown notes for ATLAS mitigations."""
        mitigations_dir = Path(self.output_dir, "Defenses", "Mitigations")
        mitigations_dir.mkdir(parents=True, exist_ok=True)

        for mitigation in self.mitigations:
            mitigation_file = Path(
                mitigations_dir, f"{mitigation.name} - {mitigation.id}.md"
            )

            lines = [
                "---\naliases:",
                f"  - {mitigation.id}",
                f"  - {mitigation.name}",
                f"  - {mitigation.name} ({mitigation.id})",
                f"  - {mitigation.id} ({mitigation.name})",
                "url: ATLAS_URL",
                "tags:",
                f"  - {self.tags_prefix}atlas",
                f"  - {self.tags_prefix}atlas_mitigation",
                "---",
                "",
                f"## {mitigation.id}",
                "",
                mitigation.description,
                "",
                "> [!info]",
                f"> ID: {mitigation.id}",
            ]
            if mitigation.lifecycle_phases:
                lines.append(
                    f"> Lifecycle Phases: {', '.join(mitigation.lifecycle_phases)}"
                )
            if mitigation.categories:
                lines.append(f"> Categories: {', '.join(mitigation.categories)}")
            lines.extend(
                [
                    f"> Created: {mitigation.created}",
                    f"> Last Modified: {mitigation.modified}",
                    "",
                    "",
                    "### Techniques Addressed by Mitigation",
                ]
            )

            if mitigation.techniques_mitigated:
                lines.extend(["", "| ID | Name | Description |", "| --- | --- | --- |"])
                for technique in sorted(
                    mitigation.techniques_mitigated, key=lambda x: x["id"]
                ):
                    description = technique["description"].replace("\n", "<br />")
                    lines.append(
                        f"| [[{technique['name']} - {technique['id']} \\| {technique['id']}]] | {technique['name']} | {description} |"
                    )

            content = "\n".join(lines)
            content = convert_atlas_local_links(text=content)
            content = content.replace("ATLAS_URL", mitigation.url)
            with open(file=mitigation_file, mode="w", encoding="utf-8") as fd:
                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")

    def create_case_study_notes(self) -> None:
        """Function to create markdown notes for ATLAS case studies."""
        case_studies_dir = Path(self.output_dir, "Case Studies")
        case_studies_dir.mkdir(parents=True, exist_ok=True)

        for case_study in self.case_studies:
            case_study_file = Path(
                case_studies_dir, f"{case_study.name} - {case_study.id}.md"
            )

            lines = [
                "---\naliases:",
                f"  - {case_study.id}",
                f"  - {case_study.name}",
                f"  - {case_study.name} ({case_study.id})",
                f"  - {case_study.id} ({case_study.name})",
                "url: ATLAS_URL",
                "tags:",
                f"  - {self.tags_prefix}atlas",
                f"  - {self.tags_prefix}atlas_case_study",
                "---",
                "",
                f"## {case_study.name}",
                "",
                case_study.description,
                "",
                "> [!info]",
                f"> ID: {case_study.id}",
            ]
            if case_study.type:
                lines.append(f"> Type: {case_study.type}")
            if case_study.actor:
                lines.append(f"> Actor: {case_study.actor}")
            if case_study.target:
                lines.append(f"> Target: {case_study.target}")
            if case_study.date:
                lines.append(
                    f"> Date: {case_study.date} ({case_study.date_granularity})"
                )
            lines.extend(
                [
                    f"> Created: {case_study.created}",
                    f"> Last Modified: {case_study.modified}",
                    "",
                    "",
                ]
            )

            if case_study.procedure:
                lines.extend(
                    [
                        "### Procedure",
                        "",
                        "| Step | Tactic | Technique | Description |",
                        "| --- | --- | --- | --- |",
                    ]
                )
                for step in case_study.procedure:
                    description = step["description"].replace("\n", "<br />")
                    tactic_cell = (
                        f"[[{step['tactic_name']} - {step['tactic_id']} \\| {step['tactic_name']}]]"
                        if step["tactic_id"]
                        else ""
                    )
                    technique_cell = f"[[{step['technique_name']} - {step['technique_id']} \\| {step['technique_name']}]]"
                    lines.append(
                        f"| {step['step_id']} | {tactic_cell} | {technique_cell} | {description} |"
                    )

            if case_study.references:
                lines.extend(["", "", "### References", ""])
                for reference in case_study.references:
                    title = reference.get("title", "")
                    url = reference.get("url", "")
                    if title and url:
                        lines.append(f"- [{title}]({url})")

            content = "\n".join(lines)
            content = convert_atlas_local_links(text=content)
            content = content.replace("ATLAS_URL", case_study.url)
            with open(file=case_study_file, mode="w", encoding="utf-8") as fd:
                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")
