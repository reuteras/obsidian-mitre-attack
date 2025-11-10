"""Generate markdown."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# Pre-compiled regex patterns for performance
CITATION_PATTERN = re.compile(r"\(Citation: ([^)]+?)\)")
MITRE_LINK_PATTERN = re.compile(
    r"\[([^\]]*?)\]\(https://attack.mitre.org/[^/]+/([^\)]+?)\)"
)
REFERENCE_PATTERN = re.compile(r"\[\^[^\]]+?\]")

# Utility functions


def fix_description(description_str: str) -> str:
    """Fix the description of a technique."""

    def match_citation(match) -> Any:
        return "[^" + match.group(1).replace(" ", "_") + "]"

    description: str = CITATION_PATTERN.sub(match_citation, description_str)
    return description


def convert_to_local_links(text: str) -> str:
    """Function to convert to local links."""

    def match_link(match) -> Any:
        if match.group(2)[0] == "T" or match.group(2)[0] == "M":
            return (
                "[["
                + match.group(1).replace("/", "／").replace(":", "：")  # noqa: RUF001
                + " - "
                + match.group(2).replace("/", ".")
                + "]]"
            )
        else:
            return "[[" + match.group(1).replace("/", "／").replace(":", "：") + "]]"  # noqa: RUF001

    # Fix inconsistent links from Mitre
    if "[Exaramel](https://attack.mitre.org/software/S0343)" in text:
        text = text.replace("[Exaramel]", "[Exaramel for Windows]")
    if "https://attack.mitre.org/techniques/T1086" in text:
        text = text.replace(
            "https://attack.mitre.org/techniques/T1086",
            "https://attack.mitre.org/techniques/T1059/001",
        )
    return MITRE_LINK_PATTERN.sub(match_link, text)


def remove_references(text: str) -> str:
    """Function to remove references from the text."""
    return REFERENCE_PATTERN.sub("", text)


class MarkdownGenerator:
    """Class to generate markdown notes for MITRE ATT&CK data."""

    def __init__(
        self,
        output_dir: str,
        stix_data,
        arguments,
        config: dict | None = None,
    ) -> None:
        """Initialize the class."""
        if output_dir:
            self.output_dir = Path(output_dir)
        self.tactics = stix_data.tactics
        self.techniques = stix_data.techniques
        self.mitigations = stix_data.mitigations
        self.groups = stix_data.groups
        self.software = stix_data.software
        self.campaigns = stix_data.campaigns
        self.assets = stix_data.assets
        self.data_sources = stix_data.data_sources
        self.data_components = stix_data.data_components
        self.detection_strategies = stix_data.detection_strategies
        self.analytics = stix_data.analytics
        self.tags_prefix = arguments.tags
        self.config = config or {}

    def create_tactic_notes(self, domain: str) -> None:
        """Function to create markdown notes for tactics."""
        dirname: str = domain.replace("-", " ").capitalize().replace("Ics ", "ICS ")
        tactics_dir = Path(self.output_dir, "Tactics", dirname)
        tactics_dir.mkdir(parents=True, exist_ok=True)

        for tactic in self.tactics:
            if tactic.domain == domain:
                tactic_file = Path(tactics_dir, f"{tactic.name} - {tactic.id}.md")

                # Create markdown file for current tactic
                with open(file=tactic_file, mode="w", encoding="utf-8") as fd:
                    lines = [
                        "---\naliases:",
                        f"  - {tactic.id}",
                        f"  - {tactic.name}",
                        f"  - {tactic.name} ({tactic.id})",
                        f"  - {tactic.id} ({tactic.name})",
                        "url: MITRE_URL",
                        "tags:",
                        f"  - {self.tags_prefix}tactic",
                        f"  - {self.tags_prefix}mitre_attack",
                        f"  - {self.tags_prefix}{tactic.domain}",
                        "---",
                        "",
                        f"## {tactic.id}",
                        "",
                    ]

                    tactic_description: str = fix_description(
                        description_str=tactic.description
                    )
                    lines.append(tactic_description)
                    lines.append("")

                    # Tactic Information
                    lines.extend(
                        [
                            "> [!info]",
                            f"> ID: {tactic.id}",
                            f"> Created: {str(object=tactic.created).split(sep=' ')[0]}",
                            f"> Last Modified: {str(object=tactic.modified).split(sep=' ')[0]}",
                            "",
                            "",
                        ]
                    )

                    # Techniques Used
                    if tactic.techniques_used:
                        lines.extend(
                            [
                                "### Techniques Used",
                                "",
                                "| ID | Name | Use |",
                                "| --- | --- | --- |",
                            ]
                        )
                        for technique in sorted(
                            tactic.techniques_used, key=lambda x: x["id"]
                        ):
                            description: str = fix_description(
                                description_str=technique["description"]
                            )
                            description = description[0 : description.find("\n")]
                            description = remove_references(text=description)
                            lines.append(
                                f"| [[{technique['name']} - {technique['id']} \\| {technique['id']}]] | {technique['name']} | {description} |"
                            )

                    content = "\n".join(lines)
                    content = convert_to_local_links(text=content)
                    content = content.replace("MITRE_URL", tactic.url)
                    fd.write(content)
                    if not content.endswith("\n"):
                        fd.write("\n")

    def create_technique_notes_header(self, technique) -> str:
        """Function to create markdown headers for techniques."""
        lines = [
            "---\naliases:",
            f"  - {technique.id}",
            f"  - {technique.name}",
            f"  - {technique.name} ({technique.id})",
            f"  - {technique.id} ({technique.name})",
            "url: MITRE_URL",
            "tags:",
            f"  - {self.tags_prefix}technique",
            f"  - {self.tags_prefix}mitre_attack",
            f"  - {self.tags_prefix}{technique.domain}",
        ]

        if technique.platforms and "None" not in technique.platforms:
            for platform in technique.platforms:
                if platform:
                    lines.append(f"  - {self.tags_prefix}{platform.replace(' ', '_')}")

        if technique.supports_remote:
            lines.append(f"  - {self.tags_prefix}supports_remote")

        lines.extend(["---", ""])
        return "\n".join(lines)

    def create_technique_notes_subtechnique(self, content: str, technique) -> str:
        """Function to create markdown notes for sub-techniques."""
        lines = []

        if technique.is_subtechnique:
            lines.append(f"## {technique.parent_name}: {technique.name}")
            lines.append("")
        else:
            lines.append(f"## {technique.name}")
            lines.append("")

        if technique.is_subtechnique:
            first = True
            for subt in sorted(technique.subtechniques, key=lambda x: x["id"]):
                if first:
                    lines.append(
                        f"> [!summary]- Other sub-techniques of {technique.parent_name} ({len(technique.subtechniques)})"
                    )
                    lines.append("> | ID | Name |")
                    lines.append("> | --- | --- |")
                    first = False
                if subt["id"] == technique.id:
                    lines.append(f"> | {subt['id']} | {subt['name']} |")
                else:
                    lines.append(
                        f"> | [[{subt['name']} - {subt['id']} \\| {subt['id']}]] | [[{subt['name']} - {subt['id']} \\| {subt['name']}]] |"
                    )
            lines.append("")
        elif technique.subtechniques:
            first = True
            for subt in sorted(technique.subtechniques, key=lambda x: x["id"]):
                if first:
                    lines.append(
                        f"> [!summary]- Sub-techniques ({len(technique.subtechniques)})"
                    )
                    lines.append("> | ID | Name |")
                    lines.append("> | --- | --- |")
                    first = False
                lines.append(
                    f"> | [[{subt['name']} - {subt['id']} \\| {subt['id']}]] | {subt['name']} |"
                )
            lines.append("")

        return content + "\n".join(lines)

    def create_technique_notes_information(self, content: str, technique) -> str:
        """Function to create markdown notes for technique information."""
        lines = []

        technique_description: str = fix_description(
            description_str=technique.description
        )
        lines.extend([technique_description, ""])

        # Information for the technique
        lines.append("> [!info]")
        lines.append(f"> ID: {technique.id}")

        if technique.is_subtechnique:
            lines.append(
                f"> Sub-technique of: [[{technique.parent_name} - {technique.id.split('.')[0]}|{technique.id.split('.')[0]}]]"
            )
        else:
            sub_techs = []
            for subt in sorted(self.techniques, key=lambda x: x.id):
                if subt.is_subtechnique and technique.id in subt.id:
                    sub_techs.append(f"[[{subt.name} - {subt.id} \\| {subt.id}]]")
            lines.append(
                f"> Sub-techniques: {', '.join(sub_techs) if sub_techs else ''}"
            )

        lines.append(
            f"> Tactic: [[{technique.tactic_name} - {technique.tactic_id} \\| {technique.tactic_name}]]"
        )

        if technique.platforms and "None" not in technique.platforms:
            lines.append(f"> Platforms: {', '.join(technique.platforms)}")
        if technique.permissions_required:
            lines.append(
                f"> Permissions Required: {', '.join(technique.permissions_required)}"
            )
        if technique.effective_permissions:
            lines.append(
                f"> Effective Permissions: {', '.join(technique.effective_permissions)}"
            )
        if technique.defense_bypassed:
            lines.append(f"> Defense Bypassed: {', '.join(technique.defense_bypassed)}")
        if technique.supports_remote:
            lines.append("> Remote Support: Yes")

        lines.extend(
            [
                f"> Version: {technique.version}",
                f"> Created: {str(object=technique.created).split(sep=' ')[0]}",
                f"> Last Modified: {str(object=technique.modified).split(sep=' ')[0]}",
                "",
            ]
        )

        return content + "\n".join(lines)

    def create_technique_notes_procedure_examples(self, content: str, technique) -> str:
        """Function to create markdown notes for procedure examples."""
        if technique.procedure_examples:
            lines = [
                "### Procedure Examples",
                "",
                "| ID | Name | Description |",
                "| --- | --- | --- |",
            ]
            for example in sorted(technique.procedure_examples, key=lambda x: x["id"]):
                description: str = fix_description(
                    description_str=example["description"]
                )
                description = description.replace("\n", "<br />")
                lines.append(
                    f"| [[{example['name'].replace('/', '／').replace(':', '：')} \\| {example['id']}]] | [[{example['name'].replace('/', '／').replace(':', '：')} \\| {example['name'].replace('/', '／').replace(':', '：')}]] | {description} |"  # noqa: RUF001
                )
            return content + "\n".join(lines)
        return content

    def create_technique_notes_targeted_assets(self, content: str, technique) -> str:
        """Function to create markdown notes for targeted assets."""
        if technique.targeted_assets:
            lines = [
                "",
                "",
                "### Targeted Assets",
                "",
                "| ID | Asset |",
                "| --- | --- |",
            ]
            for asset in sorted(technique.targeted_assets, key=lambda x: x["id"]):
                lines.append(
                    f"| [[{asset['name']} - {asset['id']} \\| {asset['id']}]] | [[{asset['name']} - {asset['id']} \\| {asset['name']}]] |"
                )
            return content + "\n".join(lines)
        return content

    def create_technique_notes_mitigations(self, content: str, technique) -> str:
        """Function to create markdown notes for mitigations."""
        lines = ["", "### Mitigations"]

        if technique.mitigations:
            mitigation_first = True
            for mitigation in sorted(technique.mitigations, key=lambda x: x["id"]):
                if mitigation["id"] == technique.id:
                    lines.extend(
                        [
                            "",
                            "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
                        ]
                    )
                else:
                    if mitigation_first:
                        lines.extend(
                            [
                                "",
                                "| ID | Name | Description |",
                                "| --- | --- | --- |",
                            ]
                        )
                        mitigation_first = False
                    description = fix_description(
                        description_str=mitigation["description"]
                    )
                    description = description.replace("\n", "<br />")
                    lines.append(
                        f"| [[{mitigation['name']} - {mitigation['id']} \\| {mitigation['id']}]] | [[{mitigation['name']} - {mitigation['id']} \\| {mitigation['name']}]] | {description} |"
                    )
        else:
            lines.extend(
                [
                    "",
                    "This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.",
                ]
            )

        return content + "\n".join(lines)

    def create_technique_notes_detection(self, content: str, technique) -> str:
        """Function to create markdown notes for detection strategies."""
        if technique.detection_strategies:
            lines = [
                "",
                "",
                "### Detection Strategy",
                "",
                "| ID | Name | Analytic ID | Analytic Description |",
                "| --- | --- | --- | --- |",
            ]
            embed_analytics = self.config.get("embed_analytics_in_detection_strategies", False)

            for detection_strategy in sorted(technique.detection_strategies, key=lambda x: x["id"]):
                ds_id = detection_strategy['id']
                ds_name = detection_strategy['name']
                analytics = detection_strategy.get('analytics', [])

                if analytics:
                    # First analytic row includes detection strategy ID and name
                    first_analytic = analytics[0]
                    analytic_desc = fix_description(description_str=first_analytic['description'])
                    analytic_desc = analytic_desc.replace("\n", " ")

                    if embed_analytics:
                        # Link to section within detection strategy file
                        analytic_link = f"[[{ds_name} - {ds_id}#{first_analytic['name']} \\| {first_analytic['id']}]]"
                    else:
                        # Link to separate analytic file
                        analytic_link = f"[[{first_analytic['name']} - {first_analytic['id']} \\| {first_analytic['id']}]]"

                    lines.append(
                        f"| [[{ds_name} - {ds_id} \\| {ds_id}]] | [[{ds_name} - {ds_id} \\| {ds_name}]] | {analytic_link} | {analytic_desc} |"
                    )

                    # Subsequent analytics for the same detection strategy (empty ID and name cells)
                    for analytic in analytics[1:]:
                        analytic_desc = fix_description(description_str=analytic['description'])
                        analytic_desc = analytic_desc.replace("\n", " ")

                        if embed_analytics:
                            # Link to section within detection strategy file
                            analytic_link = f"[[{ds_name} - {ds_id}#{analytic['name']} \\| {analytic['id']}]]"
                        else:
                            # Link to separate analytic file
                            analytic_link = f"[[{analytic['name']} - {analytic['id']} \\| {analytic['id']}]]"

                        lines.append(
                            f"|  |  | {analytic_link} | {analytic_desc} |"
                        )
                else:
                    # No analytics, just show detection strategy
                    lines.append(
                        f"| [[{ds_name} - {ds_id} \\| {ds_id}]] | [[{ds_name} - {ds_id} \\| {ds_name}]] |  |  |"
                    )
            return content + "\n".join(lines)
        return content

    def create_technique_notes(self, domain: str) -> None:
        """Function to create markdown notes for techniques."""
        dirname: str = domain.replace("-", " ").capitalize().replace("Ics ", "ICS ")
        techniques_dir = Path(self.output_dir, "Techniques", dirname)
        techniques_dir.mkdir(parents=True, exist_ok=True)

        for technique in self.techniques:
            if technique.domain == domain:
                tactic_folder = Path(techniques_dir, technique.tactic_name)
                tactic_folder.mkdir(parents=True, exist_ok=True)

                if technique.is_subtechnique:
                    technique_name_folder = Path(tactic_folder, technique.parent_name)
                else:
                    technique_name_folder = Path(tactic_folder, technique.name)
                technique_name_folder.mkdir(parents=True, exist_ok=True)
                technique_file = Path(
                    technique_name_folder, f"{technique.name} - {technique.id}.md"
                )

                content: str = self.create_technique_notes_header(technique=technique)
                content = self.create_technique_notes_subtechnique(
                    content=content, technique=technique
                )
                content = self.create_technique_notes_information(
                    content=content, technique=technique
                )
                content = self.create_technique_notes_procedure_examples(
                    content=content, technique=technique
                )
                content = self.create_technique_notes_targeted_assets(
                    content=content, technique=technique
                )
                content = self.create_technique_notes_mitigations(
                    content=content, technique=technique
                )
                content = self.create_technique_notes_detection(
                    content=content, technique=technique
                )
                content = convert_to_local_links(text=content)

                # References - only include footnotes that are actually cited in the content
                ref_lines = ["", "", "### References", ""]
                # Find all citation references in the content
                cited_refs = set()
                for match in REFERENCE_PATTERN.finditer(content):
                    ref_text = match.group(0)
                    ref_name = ref_text[2:-1]  # Remove [^ and ]
                    cited_refs.add(ref_name)

                # Only add footnotes for citations that are actually used
                for ref in technique.external_references:
                    name: str = ref["name"].replace(" ", "_")
                    if "url" in ref and name in cited_refs:
                        ref_lines.append(
                            f"[^{name}]: [{ref['description']}]({ref['url']})"
                        )

                content = content + "\n".join(ref_lines)
                content = content.replace("MITRE_URL", technique.url)

                # Create markdown file for current technique
                with open(file=technique_file, mode="w", encoding="utf-8") as fd:
                    fd.write(content)
                    if not content.endswith("\n"):
                        fd.write("\n")

    def create_mitigation_notes(self, domain: str) -> None:
        """Function to create markdown notes for mitigations."""
        dirname: str = domain.replace("-", " ").capitalize().replace("Ics ", "ICS ")
        mitigations_dir = Path(self.output_dir, "Defenses", "Mitigations", dirname)
        mitigations_dir.mkdir(parents=True, exist_ok=True)

        for mitigation in self.mitigations:
            if mitigation.domain == domain:
                mitigation_file = Path(
                    mitigations_dir, f"{mitigation.name} - {mitigation.id}.md"
                )

                # Create markdown file for current mitigation
                with open(file=mitigation_file, mode="w", encoding="utf-8") as fd:
                    lines = [
                        "---\naliases:",
                        f"  - {mitigation.id}",
                        f"  - {mitigation.name}",
                        f"  - {mitigation.name} ({mitigation.id})",
                        f"  - {mitigation.id} ({mitigation.name})",
                        "url: MITRE_URL",
                        "tags:",
                        f"  - {self.tags_prefix}mitigation",
                        f"  - {self.tags_prefix}mitre_attack",
                        f"  - {self.tags_prefix}{mitigation.domain}",
                        "---",
                        "",
                        f"## {mitigation.id}",
                        "",
                    ]

                    mitigation_description: str = fix_description(
                        description_str=mitigation.description
                    )
                    lines.extend([mitigation_description, ""])

                    # Mitigation Information
                    lines.extend(
                        [
                            "> [!info]",
                            f"> ID: {mitigation.id}",
                            f"> Version: {mitigation.version}",
                            f"> Created: {str(object=mitigation.created).split(sep=' ')[0]}",
                            f"> Last Modified: {str(object=mitigation.modified).split(sep=' ')[0]}",
                            "",
                            "",
                            "### Techniques Addressed by Mitigation",
                        ]
                    )

                    # Techniques Addressed by Mitigation
                    if mitigation.mitigates:
                        lines.extend(
                            [
                                "",
                                "| Domain | ID | Name | Description |",
                                "| --- | --- | --- | --- |",
                            ]
                        )
                        for technique in sorted(
                            mitigation.mitigates, key=lambda x: x["id"]
                        ):
                            domain_str = (
                                technique["domain"][0]
                                if isinstance(technique["domain"], list)
                                else technique["domain"]
                            )
                            mitre_domain: str = (
                                domain_str.replace("-", " ")
                                .capitalize()
                                .replace("Ics ", "ICS ")
                            )
                            description: str = fix_description(
                                description_str=technique["description"]
                            )
                            description = description.replace("\n", "<br />")
                            lines.append(
                                f"| {mitre_domain} | [[{technique['name']} - {technique['id']} \\| {technique['id']}]] | {technique['name']} | {description} |"
                            )

                    content = "\n".join(lines)
                    content = convert_to_local_links(text=content)

                    # References - only include footnotes that are actually cited in the content
                    ref_lines = ["", "", "### References", ""]
                    # Find all citation references in the content
                    cited_refs = set()
                    for match in REFERENCE_PATTERN.finditer(content):
                        ref_text = match.group(0)
                        ref_name = ref_text[2:-1]  # Remove [^ and ]
                        cited_refs.add(ref_name)

                    # Only add footnotes for citations that are actually used
                    for ref in mitigation.external_references:
                        name = ref["name"].replace(" ", "_")
                        if "url" in ref and name in cited_refs:
                            ref_lines.append(
                                f"[^{name}]: [{ref['description']}]({ref['url']})"
                            )

                    content = content + "\n".join(ref_lines)
                    content = content.replace("MITRE_URL", mitigation.url)
                    fd.write(content)
                    if not content.endswith("\n"):
                        fd.write("\n")

    def create_group_notes(self) -> None:  # noqa: PLR0912, PLR0915
        """Function to create markdown notes for groups in CTI folder."""
        groups_dir = Path(self.output_dir, "CTI", "Groups")
        groups_dir.mkdir(parents=True, exist_ok=True)

        for group in self.groups:
            group_file = Path(groups_dir, f"{group.name}.md")

            lines = ["---\naliases:"]
            for alias in group.aliases:
                lines.append(f"  - {alias}")
            lines.extend(
                [
                    "url: MITRE_URL",
                    "",
                    "tags:",
                    f"  - {self.tags_prefix}group",
                    f"  - {self.tags_prefix}mitre_attack",
                    "---",
                    "",
                    f"## {group.name}",
                    "",
                ]
            )

            group_description: str = fix_description(description_str=group.description)
            lines.extend([group_description, ""])

            # Group information
            lines.extend(
                [
                    "> [!info]",
                    f"> ID: {group.id}",
                ]
            )
            if group.aliases:
                lines.append(f"> Associated Groups: {', '.join(group.aliases)}")
            if group.contributors:
                lines.append(f"> Contributors: {', '.join(group.contributors)}")
            lines.extend(
                [
                    f"> Version: {group.version}",
                    f"> Created: {str(object=group.created).split(sep=' ')[0]}",
                    f"> Last Modified: {str(object=group.modified).split(sep=' ')[0]}",
                    "",
                    "",
                ]
            )

            if group.aliases_references:
                lines.extend(
                    [
                        "",
                        "### Associated Group Descriptions",
                        "",
                        "| Name | Description |",
                        "| --- | --- |",
                    ]
                )
                for alias in group.aliases_references:
                    if "url" not in alias:
                        description: str = fix_description(
                            description_str=alias["description"]
                        ).replace("\n", "<br />")
                        lines.append(f"| {alias['name']} | {description} |")
                lines.append("")

            # Techniques used by group
            if group.techniques_used:
                lines.extend(
                    [
                        "",
                        "### Techniques Used",
                        "",
                        "| Domain | ID | Name | Use |",
                        "| --- | --- | --- | --- |",
                    ]
                )
                for technique in sorted(
                    group.techniques_used, key=lambda x: x["technique_id"]
                ):
                    domain_str = (
                        technique["domain"][0]
                        if isinstance(technique["domain"], list)
                        else technique["domain"]
                    )
                    domain: str = (
                        domain_str.replace("-", " ")
                        .capitalize()
                        .replace("Ics ", "ICS ")
                    )
                    description = fix_description(
                        description_str=technique["description"]
                    )
                    description = description.replace("\n", "<br />")
                    lines.append(
                        f"| {domain} | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_id']}]] | {technique['technique_name']} | {description} |"
                    )

            # Software used by group
            if group.software_used:
                lines.extend(
                    [
                        "",
                        "",
                        "",
                        "### Software Used",
                        "",
                        "| ID | Name | References | Techniques |",
                        "| --- | --- | --- | --- |",
                    ]
                )
                for software in sorted(group.software_used, key=lambda x: x["id"]):
                    description = fix_description(
                        description_str=software["description"]
                    )
                    lines.append(
                        f"| [[{software['name']} \\| {software['id']}]] | [[{software['name']} \\| {software['name']}]] | {description} | {software['software_techniques']} |"
                    )

            content = "\n".join(lines)
            content = convert_to_local_links(text=content)

            # References - only include footnotes that are actually cited in the content
            ref_lines = ["", "", "### References", ""]
            # Find all citation references in the content
            cited_refs = set()
            for match in REFERENCE_PATTERN.finditer(content):
                ref_text = match.group(0)
                ref_name = ref_text[2:-1]  # Remove [^ and ]
                cited_refs.add(ref_name)

            # Only add footnotes for citations that are actually used
            for ref in group.external_references:
                name = ref["name"].replace(" ", "_")
                if "url" in ref and name in cited_refs:
                    ref_lines.append(f"[^{name}]: [{ref['description']}]({ref['url']})")

            if group.aliases_references:
                for alias in group.aliases_references:
                    if "url" in alias:
                        name: str = alias["name"].replace(" ", "_")
                        if name in cited_refs:
                            ref_lines.append(
                                f"[^{name}]: [{alias['description']}]({alias['url']})"
                            )

            content = content + "\n".join(ref_lines)
            content = content.replace("MITRE_URL", group.url)

            # Create markdown file for current group
            with open(file=group_file, mode="w", encoding="utf-8") as fd:
                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")

    def create_software_notes_header(self, software) -> str:
        """Function to create markdown headers for software."""
        lines = [
            f"---\naliases:\n  - {software.id}",
            f"  - {software.name} ({software.id})",
            f"  - {software.id} ({software.name})",
            "url: MITRE_URL",
            "tags:",
            f"  - {self.tags_prefix}software",
            f"  - {self.tags_prefix}mitre_attack",
            f"  - {self.tags_prefix}{software.type}",
        ]

        if software.platforms and software.platforms != "":
            for platform in software.platforms:
                if platform:
                    lines.append(
                        f"  - {self.tags_prefix}{platform[0].replace(' ', '_')}"
                    )

        lines.extend(["", "---", "", f"## {software.name}", ""])

        software_description: str = fix_description(
            description_str=software.description
        )
        lines.extend([software_description, ""])

        # Software information
        lines.extend(
            [
                "> [!info]",
                f"> ID: {software.id}",
                f"> Type: {software.type}",
            ]
        )

        if software.platforms and software.platforms != [[]]:
            platforms: list[str] = [
                ", ".join(platform) for platform in software.platforms
            ]
            lines.append(f"> Platforms: {''.join(platforms)}")
        if software.aliases:
            lines.append(f"> Associated Software: {', '.join(software.aliases)}")
        if software.contributors:
            lines.append(f"> Contributors: {', '.join(software.contributors)}")

        lines.extend(
            [
                f"> Version: {software.version}",
                f"> Created: {str(object=software.created).split(sep=' ')[0]}",
                f"> Last Modified: {str(object=software.modified).split(sep=' ')[0]}",
                "",
                "",
            ]
        )

        return "\n".join(lines)

    def create_software_notes_info(self, content: str, software) -> str:
        """Function to create markdown notes for software information."""
        lines = ["### Techniques Used"]

        if software.techniques_used:
            lines.extend(
                [
                    "",
                    "| Domain | ID | Name | Use |",
                    "| --- | --- | --- | --- |",
                ]
            )
            for technique in sorted(
                software.techniques_used, key=lambda x: x["technique"].id
            ):
                domain_str = (
                    technique["domain"][0]
                    if isinstance(technique["domain"], list)
                    else technique["domain"]
                )
                domain: str = (
                    domain_str.replace("-", " ").capitalize().replace("Ics ", "ICS ")
                )
                description: str = fix_description(
                    description_str=technique["description"]
                )
                description = description.replace("\n", "<br />")
                ext_refs = technique["technique"].get("external_references", "")
                external_id: str = ""
                for ref in ext_refs:
                    if ref["source_name"] == "mitre-attack":
                        external_id = ref["external_id"]
                lines.append(
                    f"| {domain} | [[{technique['technique'].name.replace('/', '／').replace(':', '：')} - {external_id} \\| {external_id}]] | {technique['technique'].name} | {description} |"  # noqa: RUF001
                )

        # Groups that use this software
        if software.groups_using:
            lines.extend(
                [
                    "",
                    "### Groups That Use This Software",
                    "",
                    "| ID | Name | Use |",
                    "| --- | --- | --- |",
                ]
            )
            for group in sorted(software.groups_using, key=lambda x: x["group_id"]):
                description = fix_description(description_str=group["description"])
                description = description.replace("\n", "<br />")
                lines.append(
                    f"| [[{group['group_name']} \\| {group['group_id']}]] | {group['group_name']} | {description} |"
                )

        return content + "\n".join(lines)

    def create_software_notes(self) -> None:
        """Function to create markdown notes for software in CTI folder."""
        software_dir = Path(self.output_dir, "CTI", "Software")
        software_dir.mkdir(parents=True, exist_ok=True)

        for software in self.software:
            software_file = Path(software_dir, f"{software.name}.md")

            # Create markdown file for current software
            content: str = self.create_software_notes_header(software=software)
            content = self.create_software_notes_info(
                content=content, software=software
            )

            # Software have been used in the following campaigns
            if software.campaigns_using:
                content += "\n\n### Campaigns\n"
                content += "\n| ID | Name | Description |\n| --- | --- | --- |\n"
                for campaign in sorted(
                    software.campaigns_using, key=lambda x: x["campaign_id"]
                ):
                    description = fix_description(
                        description_str=campaign["description"]
                    )
                    description = description.replace("\n", "<br />")
                    content += f"| [[{campaign['campaign_name']} \\| {campaign['campaign_id']}]] | {campaign['campaign_name']} | {description} |\n"

            content = convert_to_local_links(text=content)

            # References - only include footnotes that are actually cited in the content
            content += "\n\n### References\n\n"
            # Find all citation references in the content
            cited_refs = set()
            for match in REFERENCE_PATTERN.finditer(content):
                ref_text = match.group(0)
                ref_name = ref_text[2:-1]  # Remove [^ and ]
                cited_refs.add(ref_name)

            # Only add footnotes for citations that are actually used
            for ref in software.external_references:
                name: str = ref["name"].replace(" ", "_")
                if "url" in ref and name in cited_refs:
                    content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

            content = content.replace("MITRE_URL", software.url)

            with open(file=software_file, mode="w", encoding="utf-8") as fd:
                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")

    def create_campaign_notes_header(self, campaign) -> str:
        """Function to create markdown headers for campaigns."""
        lines = [
            "---\naliases:",
            f"  - {campaign.id}",
            "url: MITRE_URL",
            "tags:",
            f"  - {self.tags_prefix}campaign",
            f"  - {self.tags_prefix}mitre_attack",
            "---",
            "",
            f"## {campaign.name}",
            "",
        ]

        campaign_description: str = fix_description(
            description_str=campaign.description
        )
        lines.extend([campaign_description, ""])

        # Campaign information
        lines.extend(
            [
                "> [!info]",
                f"> ID: {campaign.id}",
                f"> First Seen: {str(object=campaign.first_seen).split(sep=' ')[0]}",
                f"> Last Seen: {str(object=campaign.last_seen).split(sep=' ')[0]}",
                f"> Version: {campaign.version}",
                f"> Created: {str(object=campaign.created).split(sep=' ')[0]}",
                f"> Last Modified: {str(object=campaign.modified).split(sep=' ')[0]}",
                "",
                "",
            ]
        )

        return "\n".join(lines)

    def create_campaign_notes(self) -> None:  # noqa: PLR0912
        """Function to create markdown notes for campaigns in CTI folder."""
        campaigns_dir = Path(self.output_dir, "CTI", "Campaigns")
        campaigns_dir.mkdir(parents=True, exist_ok=True)

        for campaign in self.campaigns:
            campaign_file = Path(campaigns_dir, f"{campaign.name}.md")

            # Create markdown file for current campaign
            with open(file=campaign_file, mode="w", encoding="utf-8") as fd:
                lines = []

                # Groups that use this campaign
                if campaign.groups:
                    lines.extend(
                        [
                            "",
                            "### Groups",
                            "",
                            "| ID | Name | Use |",
                            "| --- | --- | --- |",
                        ]
                    )
                    for group in sorted(campaign.groups, key=lambda x: x["group"].id):
                        description: str = fix_description(
                            description_str=group["description"]
                        )
                        description = description.replace("\n", "<br />")
                        lines.append(
                            f"| [[{group['group'].name} \\| {group['group'].id}]] | {group['group'].name} | {description} |"
                        )

                # Techniques used by campaign
                if campaign.techniques_used:
                    lines.extend(
                        [
                            "",
                            "",
                            "### Techniques Used",
                            "",
                            "| Domain | ID | Name | Use |",
                            "| --- | --- | --- | --- |",
                        ]
                    )
                    for technique in sorted(
                        campaign.techniques_used, key=lambda x: x["technique_id"]
                    ):
                        domain_str = (
                            technique["domain"][0]
                            if isinstance(technique["domain"], list)
                            else technique["domain"]
                        )
                        domain: str = (
                            domain_str.replace("-", " ")
                            .capitalize()
                            .replace("Ics", "ICS")
                        )
                        description = fix_description(
                            description_str=technique["description"]
                        )
                        description = description.replace("\n", "<br />")
                        lines.append(
                            f"| {domain} | [[{technique['technique_name'].replace('/', '／').replace(':', '：')} - {technique['technique_id']} \\| {technique['technique_id']}]] | {technique['technique_name']} | {description} |"  # noqa: RUF001
                        )

                # Software used in campaign
                if campaign.software_used:
                    lines.extend(
                        [
                            "",
                            "",
                            "",
                            "### Software",
                            "",
                            "| ID | Name | Description |",
                            "| --- | --- | --- |",
                        ]
                    )
                    for software in sorted(
                        campaign.software_used, key=lambda x: x["software"].id
                    ):
                        description = fix_description(
                            description_str=software["description"]
                        )
                        description = description.replace("\n", "<br />")
                        external_id: str = ""
                        for ref in software["software"].get("external_references", []):
                            if ref["source_name"] == "mitre-attack":
                                external_id = ref["external_id"]
                        lines.append(
                            f"| [[{software['software'].name} \\| {external_id}]] | {software['software'].name} | {description} |"
                        )

                content = self.create_campaign_notes_header(
                    campaign=campaign
                ) + "\n".join(lines)
                content = convert_to_local_links(text=content)

                # References - only include footnotes that are actually cited in the content
                ref_lines = ["", "", "### References", ""]
                # Find all citation references in the content
                cited_refs = set()
                for match in REFERENCE_PATTERN.finditer(content):
                    # Extract the reference name from [^name]
                    ref_text = match.group(0)
                    ref_name = ref_text[2:-1]  # Remove [^ and ]
                    cited_refs.add(ref_name)

                # Only add footnotes for citations that are actually used
                for ref in campaign.external_references:
                    name: str = ref["name"].replace(" ", "_")
                    if "url" in ref and name in cited_refs:
                        ref_lines.append(
                            f"[^{name}]: [{ref['description']}]({ref['url']})"
                        )

                content = content + "\n".join(ref_lines)
                content = content.replace("MITRE_URL", campaign.url)
                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")

    def create_tool_notes_header(self, asset) -> str:
        """Function to create markdown headers for tools."""
        lines = [
            f"---\naliases:\n  - {asset.id}",
            f"  - {asset.name} ({asset.id})",
            f"  - {asset.id} ({asset.name})",
            "url: MITRE_URL",
            "tags:",
            f"  - {self.tags_prefix}asset",
            f"  - {self.tags_prefix}mitre_attack",
        ]

        if asset.platforms and asset.platforms != "":
            for platform in asset.platforms[0]:
                if platform:
                    lines.append(f"  - {self.tags_prefix}{platform.replace(' ', '_')}")
        if asset.sectors and asset.sectors != "":
            for sector in asset.sectors[0]:
                if sector:
                    lines.append(f"  - {self.tags_prefix}{sector.replace(' ', '_')}")

        lines.extend(["---", "", f"## {asset.name}", ""])

        asset_description: str = fix_description(description_str=asset.description)
        lines.extend([asset_description, ""])

        # Asset information
        lines.extend(
            [
                "> [!info]",
                f"> ID: {asset.id}",
            ]
        )

        if asset.platforms and asset.platforms != [[]]:
            platforms: list[str] = [", ".join(platform) for platform in asset.platforms]
            lines.append(f"> Platforms: {''.join(platforms)}")
        if asset.sectors and asset.sectors != [[]]:
            sectors: list[str] = [", ".join(sector) for sector in asset.sectors]
            lines.append(f"> Sectors: {''.join(sectors)}")

        lines.extend(
            [
                f"> Version: {asset.version}",
                f"> Created: {str(object=asset.created).split(sep=' ')[0].split('T')[0]}",
                f"> Last Modified: {str(object=asset.modified).split(sep=' ')[0].split('T')[0]}",
                "",
                "",
            ]
        )

        return "\n".join(lines)

    def create_asset_notes(self) -> None:
        """Function to create markdown notes for assets in Defense folder."""
        assets_dir = Path(self.output_dir, "Defenses", "Assets")
        assets_dir.mkdir(parents=True, exist_ok=True)

        for asset in self.assets:
            asset_file = Path(assets_dir, f"{asset.name}.md")

            # Create markdown file for current asset
            with open(file=asset_file, mode="w", encoding="utf-8") as fd:
                lines = []

                # Related assets
                if asset.related_assets:
                    lines.extend(
                        [
                            "",
                            "### Related Assets",
                            "",
                            "| Name | Sectors | Description |",
                            "| --- | --- | --- |",
                        ]
                    )
                    for related_asset in sorted(
                        asset.related_assets, key=lambda x: x["name"]
                    ):
                        description: str = fix_description(
                            description_str=related_asset["description"]
                        )
                        description = description.replace("\n", "<br />")
                        try:
                            sectors = [
                                ", ".join(sector) for sector in related_asset.sectors
                            ]
                            lines.append(
                                f"| {related_asset['name']} | {', '.join(sectors)} | {description} |"
                            )
                        except AttributeError:
                            lines.append(
                                f"| {related_asset['name']} | | {description} |"
                            )

                # Techniques Addressed by Asset
                if asset.techniques_used:
                    lines.extend(
                        [
                            "### Techniques Addressed by Asset",
                            "",
                            "| Domain | ID | Name |",
                            "| --- | --- | --- |",
                        ]
                    )
                    for technique in sorted(
                        asset.techniques_used, key=lambda x: x["technique_id"]
                    ):
                        domain_str = (
                            technique["domain"][0]
                            if isinstance(technique["domain"], list)
                            else technique["domain"]
                        )
                        domain = (
                            domain_str.replace("-", " ")
                            .capitalize()
                            .replace("Ics ", "ICS ")
                        )
                        lines.append(
                            f"| {domain} | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_id']}]] | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_name']}]] |"
                        )

                content = self.create_tool_notes_header(asset=asset) + "\n".join(lines)
                content = convert_to_local_links(text=content)

                # References - only include footnotes that are actually cited in the content
                if asset.external_references and len(asset.external_references) > 0:
                    ref_lines = ["", "", "### References", ""]
                    # Find all citation references in the content
                    cited_refs = set()
                    for match in REFERENCE_PATTERN.finditer(content):
                        ref_text = match.group(0)
                        ref_name = ref_text[2:-1]  # Remove [^ and ]
                        cited_refs.add(ref_name)

                    # Only add footnotes for citations that are actually used
                    for ref in asset.external_references:
                        name = ref["name"].replace(" ", "_")
                        if "url" in ref and name in cited_refs:
                            ref_lines.append(
                                f"[^{name}]: [{ref['description']}]({ref['url']})"
                            )
                    content = content + "\n".join(ref_lines)

                content = content.replace("MITRE_URL", asset.url)

                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")

    def create_data_source_notes(self) -> None:
        """Function to create markdown notes for data sources in Defense folder."""
        data_sources_dir = Path(self.output_dir, "Defenses", "Detections", "Data Components")
        data_sources_dir.mkdir(parents=True, exist_ok=True)

        # Create domain subfolders (even if empty, to match ATT&CK structure)
        domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
        for domain in domains:
            dirname: str = (
                domain.replace("-", " ")
                .capitalize()
                .replace("Ics ", "ICS ")
            )
            domain_dir = Path(data_sources_dir, dirname)
            domain_dir.mkdir(parents=True, exist_ok=True)

        # Group data sources by domain
        for data_source in self.data_sources:
            dirname: str = (
                data_source.domain.replace("-", " ")
                .capitalize()
                .replace("Ics ", "ICS ")
            )
            domain_dir = Path(data_sources_dir, dirname)
            domain_dir.mkdir(parents=True, exist_ok=True)

            data_source_file = Path(domain_dir, f"{data_source.name}.md")

            # Create markdown file for current data source
            with open(file=data_source_file, mode="w", encoding="utf-8") as fd:
                lines = [
                    f"---\naliases:\n  - {data_source.id}",
                    f"  - {data_source.name} ({data_source.id})",
                    f"  - {data_source.id} ({data_source.name})",
                    "url: MITRE_URL",
                    "tags:",
                    f"  - {self.tags_prefix}data_source",
                    f"  - {self.tags_prefix}mitre_attack",
                    "---",
                    "",
                    f"## {data_source.name}",
                    "",
                ]

                data_source_description: str = fix_description(
                    description_str=data_source.description
                )
                lines.extend([data_source_description, ""])

                # Data source information
                lines.extend(
                    [
                        "> [!info]",
                        f"> ID: {data_source.id}",
                    ]
                )

                if data_source.platforms and data_source.platforms != [[]]:
                    platforms: list[str] = [
                        ", ".join(platform) for platform in data_source.platforms
                    ]
                    lines.append(f"> Platforms: {''.join(platforms)}")
                if data_source.collection_layers and data_source.collection_layers != [
                    []
                ]:
                    layers: list[str] = [
                        ", ".join(layer) for layer in data_source.collection_layers
                    ]
                    lines.append(f"> Collection Layers: {''.join(layers)}")

                lines.extend(
                    [
                        f"> Version: {data_source.version}",
                        f"> Created: {str(object=data_source.created).split(sep=' ')[0].split(sep='T')[0]}",
                        f"> Last Modified: {str(object=data_source.modified).split(sep=' ')[0].split('T')[0]}",
                        "",
                        "",
                        "## Data Components",
                    ]
                )

                # Data Components
                for related_data_source in data_source.data_components[0]:
                    lines.append(
                        f"- [[#{related_data_source['data_component_parent']}: {related_data_source['data_component_name']} \\| {related_data_source['data_component_name']}]]"
                    )

                lines.append("")

                for related_data_source in data_source.data_components[0]:
                    lines.append(
                        f"### {related_data_source['data_component_parent']}: {related_data_source['data_component_name']}"
                    )
                    if related_data_source["data_component_description"]:
                        description: str = fix_description(
                            description_str=related_data_source[
                                "data_component_description"
                            ]
                        )
                        description = description.replace("\n", "<br />")
                        lines.extend([description, ""])

                    lines.extend(
                        [
                            "| Domain | ID | Name | Detects |",
                            "| --- | --- | --- | --- |",
                        ]
                    )

                    for technique in related_data_source["techniques_used"]:
                        detects: str = fix_description(
                            description_str=technique["description"]
                        )
                        detects = detects.replace("\n", "<br />")
                        lines.append(
                            f"| {technique['domain']} | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_id']}]] | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_name']}]] | {detects} |"
                        )

                content = "\n".join(lines)
                content = convert_to_local_links(text=content)

                # References - only include footnotes that are actually cited in the content
                if (
                    data_source.external_references
                    and len(data_source.external_references) > 0
                ):
                    ref_lines = ["", "", "### References", ""]
                    # Find all citation references in the content
                    cited_refs = set()
                    for match in REFERENCE_PATTERN.finditer(content):
                        ref_text = match.group(0)
                        ref_name = ref_text[2:-1]  # Remove [^ and ]
                        cited_refs.add(ref_name)

                    # Only add footnotes for citations that are actually used
                    for ref in data_source.external_references:
                        name: str = ref["name"].replace(" ", "_")
                        if "url" in ref and name in cited_refs:
                            ref_lines.append(
                                f"[^{name}]: [{ref['description']}]({ref['url']})"
                            )
                    content = content + "\n".join(ref_lines)

                content = content.replace("MITRE_URL", data_source.url)

                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")

    def create_data_component_notes(self) -> None:
        """Function to create markdown notes for data components in Defense folder."""
        data_components_dir = Path(self.output_dir, "Defenses", "Detections", "Data Components")
        data_components_dir.mkdir(parents=True, exist_ok=True)

        # Create domain subfolders
        domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
        for domain in domains:
            dirname: str = (
                domain.replace("-", " ")
                .capitalize()
                .replace("Ics ", "ICS ")
            )
            domain_dir = Path(data_components_dir, dirname)
            domain_dir.mkdir(parents=True, exist_ok=True)

        # Group data components by domain
        for data_component in self.data_components:
            dirname: str = (
                data_component.domain.replace("-", " ")
                .capitalize()
                .replace("Ics ", "ICS ")
            )
            domain_dir = Path(data_components_dir, dirname)
            domain_dir.mkdir(parents=True, exist_ok=True)

            # Use format: "Data Source Name: Data Component Name - DC0001.md"
            full_name = f"{data_component.data_source_name}: {data_component.name} - {data_component.id}.md"
            data_component_file = Path(domain_dir, full_name)

            # Create markdown file for current data component
            with open(file=data_component_file, mode="w", encoding="utf-8") as fd:
                lines = [
                    f"---\naliases:\n  - {data_component.id}",
                    f"  - {data_component.data_source_name}: {data_component.name}",
                    f"  - {data_component.name} ({data_component.id})",
                    f"  - {data_component.id} ({data_component.name})",
                    "url: MITRE_URL",
                    "tags:",
                    f"  - {self.tags_prefix}data_component",
                    f"  - {self.tags_prefix}mitre_attack",
                    "---",
                    "",
                    f"## {data_component.data_source_name}: {data_component.name}",
                    "",
                ]

                data_component_description: str = fix_description(
                    description_str=data_component.description
                )
                lines.extend([data_component_description, ""])

                # Data component information
                lines.extend(
                    [
                        "> [!info]",
                        f"> ID: {data_component.id}",
                    ]
                )

                if data_component.data_source_name:
                    if data_component.data_source_id:
                        lines.append(f"> Data Source: [[{data_component.data_source_name} ({data_component.data_source_id})]] ({data_component.data_source_id})")
                    else:
                        lines.append(f"> Data Source: {data_component.data_source_name}")

                lines.extend(
                    [
                        f"> Version: {data_component.version}",
                        f"> Created: {str(object=data_component.created).split(sep=' ')[0].split(sep='T')[0]}",
                        f"> Last Modified: {str(object=data_component.modified).split(sep=' ')[0].split('T')[0]}",
                        "",
                        "",
                    ]
                )

                # Detection table
                if data_component.techniques_used:
                    lines.extend(
                        [
                            "## Techniques Detected",
                            "",
                            "| Domain | ID | Name | Detects |",
                            "| --- | --- | --- | --- |",
                        ]
                    )

                    for technique in data_component.techniques_used:
                        detects: str = fix_description(
                            description_str=technique["description"]
                        )
                        detects = detects.replace("\n", "<br />")
                        lines.append(
                            f"| {technique['domain']} | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_id']}]] | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_name']}]] | {detects} |"
                        )

                content = "\n".join(lines)
                content = convert_to_local_links(text=content)

                # References - only include footnotes that are actually cited in the content
                if (
                    data_component.external_references
                    and len(data_component.external_references) > 0
                ):
                    ref_lines = ["", "", "### References", ""]
                    # Find all citation references in the content
                    cited_refs = set()
                    for match in REFERENCE_PATTERN.finditer(content):
                        ref_text = match.group(0)
                        ref_name = ref_text[2:-1]  # Remove [^ and ]
                        cited_refs.add(ref_name)

                    # Only add footnotes for citations that are actually used
                    for ref in data_component.external_references:
                        name: str = ref["name"].replace(" ", "_")
                        if "url" in ref and name in cited_refs:
                            ref_lines.append(
                                f"[^{name}]: [{ref['description']}]({ref['url']})"
                            )
                    content = content + "\n".join(ref_lines)

                content = content.replace("MITRE_URL", data_component.url)

                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")

    def _generate_analytic_content(self, analytic) -> str:
        """Generate the content for an analytic (for embedding in detection strategies).

        Args:
            analytic: The analytic object to generate content for

        Returns:
            str: The markdown content for the analytic
        """
        lines = [f"## {analytic.name}", ""]

        # Analytic description
        if analytic.description:
            analytic_description: str = fix_description(
                description_str=analytic.description
            )
            lines.extend([analytic_description, ""])

        # Analytic information
        lines.extend(
            [
                "> [!info]",
                f"> ID: {analytic.id}",
            ]
        )

        if analytic.platforms:
            lines.append(f"> Platforms: {', '.join(analytic.platforms)}")

        lines.extend(
            [
                f"> Version: {analytic.version}",
                f"> Created: {str(object=analytic.created).split(sep=' ')[0]}",
                f"> Last Modified: {str(object=analytic.modified).split(sep=' ')[0]}",
                f"> URL: {analytic.url}",
                "",
                "",
            ]
        )

        # Log sources
        if analytic.log_source_references:
            lines.extend(
                [
                    "### Log Sources",
                    "",
                    "| Name | Data Component | Channel |",
                    "| --- | --- | --- |",
                ]
            )
            for log_source in analytic.log_source_references:
                data_component_name = log_source.get("data_component_name", "")
                name = log_source.get("name", "")
                channel = log_source.get("channel", "")
                lines.append(f"| {name} | {data_component_name} | {channel} |")

        # Mutable elements
        if analytic.mutable_elements:
            lines.extend(
                [
                    "",
                    "",
                    "### Mutable Elements",
                    "",
                    "| Field | Description |",
                    "| --- | --- |",
                ]
            )
            for element in analytic.mutable_elements:
                field = element.get("field", "")
                description = element.get("description", "")
                lines.append(f"| {field} | {description} |")

        content = "\n".join(lines)
        content = convert_to_local_links(text=content)
        return content

    def create_detection_strategy_notes(self) -> None:  # noqa: PLR0912
        """Function to create markdown notes for detection strategies in Defense folder."""
        detection_strategies_dir = Path(
            self.output_dir, "Defenses", "Detections", "Detection Strategies"
        )
        detection_strategies_dir.mkdir(parents=True, exist_ok=True)

        # Group detection strategies by domain
        for detection_strategy in self.detection_strategies:
            dirname: str = (
                detection_strategy.domain.replace("-", " ")
                .capitalize()
                .replace("Ics ", "ICS ")
            )
            domain_dir = Path(detection_strategies_dir, dirname)
            domain_dir.mkdir(parents=True, exist_ok=True)

            ds_file = Path(
                domain_dir, f"{detection_strategy.name} - {detection_strategy.id}.md"
            )

            # Create markdown file for current detection strategy
            with open(file=ds_file, mode="w", encoding="utf-8") as fd:
                lines = [
                    f"---\naliases:\n  - {detection_strategy.id}",
                    f"  - {detection_strategy.name}",
                    f"  - {detection_strategy.name} ({detection_strategy.id})",
                    f"  - {detection_strategy.id} ({detection_strategy.name})",
                    "url: MITRE_URL",
                    "tags:",
                    f"  - {self.tags_prefix}detection_strategy",
                    f"  - {self.tags_prefix}mitre_attack",
                    f"  - {self.tags_prefix}{detection_strategy.domain}",
                    "---",
                    "",
                    f"## {detection_strategy.name}",
                    "",
                ]

                # Detection Strategy information
                lines.extend(
                    [
                        "> [!info]",
                        f"> ID: {detection_strategy.id}",
                        f"> Version: {detection_strategy.version}",
                        f"> Created: {str(object=detection_strategy.created).split(sep=' ')[0]}",
                        f"> Last Modified: {str(object=detection_strategy.modified).split(sep=' ')[0]}",
                        "",
                        "",
                    ]
                )

                # Techniques detected by this strategy
                if detection_strategy.techniques:
                    lines.extend(
                        [
                            "### Techniques Detected",
                            "",
                            "| ID | Name |",
                            "| --- | --- |",
                        ]
                    )
                    for technique in sorted(
                        detection_strategy.techniques, key=lambda x: x["technique_id"]
                    ):
                        lines.append(
                            f"| [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_id']}]] | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_name']}]] |"
                        )

                # Analytics associated with this strategy
                if detection_strategy.analytic_refs:
                    embed_analytics = self.config.get(
                        "embed_analytics_in_detection_strategies", False
                    )

                    if embed_analytics:
                        # Embed analytics using tab-panels syntax
                        lines.extend(
                            [
                                "",
                                "",
                                "### Associated Analytics",
                                "",
                                "```tabs",
                            ]
                        )

                        for analytic_ref in detection_strategy.analytic_refs:
                            # Find the analytic object
                            for analytic in self.analytics:
                                if analytic.internal_id == analytic_ref:
                                    # Build the tab name with platform info if available
                                    platforms_str = ""
                                    if analytic.platforms:
                                        platforms_str = (
                                            f" ({', '.join(analytic.platforms)})"
                                        )
                                    tab_name = f"{analytic.id}{platforms_str}"

                                    lines.append(f"--- {tab_name}")

                                    # Generate and embed the analytic content
                                    analytic_content = self._generate_analytic_content(
                                        analytic
                                    )
                                    lines.append(analytic_content)
                                    lines.append("")  # Add blank line between tabs
                                    break

                        lines.append("```")
                    else:
                        # Default behavior: link to analytics files
                        lines.extend(
                            [
                                "",
                                "",
                                "### Associated Analytics",
                                "",
                                "| ID | Name |",
                                "| --- | --- |",
                            ]
                        )
                        for analytic_ref in detection_strategy.analytic_refs:
                            # Find the analytic object
                            for analytic in self.analytics:
                                if analytic.internal_id == analytic_ref:
                                    # Build the name with platform info if available
                                    platforms_str = ""
                                    if analytic.platforms:
                                        platforms_str = (
                                            f" ({', '.join(analytic.platforms)})"
                                        )
                                    display_name = f"{analytic.id}{platforms_str}"
                                    lines.append(
                                        f"| [[{analytic.name} - {analytic.id} \\| {analytic.id}]] | [[{analytic.name} - {analytic.id} \\| {display_name}]] |"
                                    )
                                    break

                content = "\n".join(lines)
                content = convert_to_local_links(text=content)
                content = content.replace("MITRE_URL", detection_strategy.url)

                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")

    def create_analytic_notes(self) -> None:
        """Function to create markdown notes for analytics in Defense folder."""
        analytics_dir = Path(self.output_dir, "Defenses", "Detections", "Analytics")
        analytics_dir.mkdir(parents=True, exist_ok=True)

        # Always create Analytics.md index file
        index_file = Path(analytics_dir, "Analytics.md")
        with open(file=index_file, mode="w", encoding="utf-8") as fd:
            lines = [
                "---",
                "tags:",
                f"  - {self.tags_prefix}analytics",
                f"  - {self.tags_prefix}mitre_attack",
                "---",
                "",
                "## Analytics",
                "",
                "This page lists all analytics across all domains.",
                "",
            ]

            # Add note about embedded analytics if applicable
            if self.config.get("embed_analytics_in_detection_strategies", False):
                lines.append("Individual analytics are embedded within their corresponding Detection Strategy pages.")
                lines.append("")

            lines.extend([
                "| ID | Platform | Domain | Detection Strategy | Description |",
                "| --- | --- | --- | --- | --- |",
            ])

            # Sort analytics by ID
            for analytic in sorted(self.analytics, key=lambda x: x.id):
                platforms_str = ", ".join(analytic.platforms) if analytic.platforms else ""
                domain_str = (
                    analytic.domain.replace("-", " ")
                    .capitalize()
                    .replace("Ics ", "ICS ")
                )

                # Find the detection strategy this analytic belongs to
                detection_strategy_name = ""
                detection_strategy_id = ""
                for ds in self.detection_strategies:
                    if analytic.internal_id in ds.analytic_refs:
                        detection_strategy_name = ds.name
                        detection_strategy_id = ds.id
                        break

                # Create link for ID column
                if self.config.get("embed_analytics_in_detection_strategies", False):
                    # Link to detection strategy when embedded (ID links to the detection strategy page)
                    id_link = f"[[{detection_strategy_name} - {detection_strategy_id} \\| {analytic.id}]]" if detection_strategy_name else analytic.id
                    ds_link = f"[[{detection_strategy_name} - {detection_strategy_id} \\| {detection_strategy_name}]]" if detection_strategy_name else ""
                else:
                    # Link to individual analytic file when not embedded
                    id_link = f"[[{analytic.name} - {analytic.id} \\| {analytic.id}]]"
                    ds_link = f"[[{analytic.name} - {analytic.id} \\| {detection_strategy_name}]]" if detection_strategy_name else ""

                description = fix_description(description_str=analytic.description) if analytic.description else ""
                description = description.replace("\n", " ").strip()
                # Limit description length for table readability
                if len(description) > 200:
                    description = description[:197] + "..."

                lines.append(
                    f"| {id_link} | {platforms_str} | {domain_str} | {ds_link} | {description} |"
                )

            content = "\n".join(lines)
            content = convert_to_local_links(text=content)
            fd.write(content)
            if not content.endswith("\n"):
                fd.write("\n")

        # Skip creating individual analytic files if they're embedded in detection strategies
        if self.config.get("embed_analytics_in_detection_strategies", False):
            return

        # Create all analytics in a flat structure (no domain subfolders)
        for analytic in self.analytics:
            analytic_file = Path(analytics_dir, f"{analytic.name} - {analytic.id}.md")

            # Create markdown file for current analytic
            with open(file=analytic_file, mode="w", encoding="utf-8") as fd:
                lines = [
                    f"---\naliases:\n  - {analytic.id}",
                    f"  - {analytic.name}",
                    f"  - {analytic.name} ({analytic.id})",
                    f"  - {analytic.id} ({analytic.name})",
                    "url: MITRE_URL",
                    "tags:",
                    f"  - {self.tags_prefix}analytic",
                    f"  - {self.tags_prefix}mitre_attack",
                    f"  - {self.tags_prefix}{analytic.domain}",
                ]

                # Add platform tags
                if analytic.platforms:
                    for platform in analytic.platforms:
                        if platform:
                            lines.append(
                                f"  - {self.tags_prefix}{platform.replace(' ', '_')}"
                            )

                lines.extend(["---", "", f"## {analytic.name}", ""])

                # Analytic description
                if analytic.description:
                    analytic_description: str = fix_description(
                        description_str=analytic.description
                    )
                    lines.extend([analytic_description, ""])

                # Analytic information
                lines.extend(
                    [
                        "> [!info]",
                        f"> ID: {analytic.id}",
                    ]
                )

                if analytic.platforms:
                    lines.append(f"> Platforms: {', '.join(analytic.platforms)}")

                lines.extend(
                    [
                        f"> Version: {analytic.version}",
                        f"> Created: {str(object=analytic.created).split(sep=' ')[0]}",
                        f"> Last Modified: {str(object=analytic.modified).split(sep=' ')[0]}",
                        "",
                        "",
                    ]
                )

                # Log sources
                if analytic.log_source_references:
                    lines.extend(
                        [
                            "### Log Sources",
                            "",
                            "| Name | Data Component | Channel |",
                            "| --- | --- | --- |",
                        ]
                    )
                    for log_source in analytic.log_source_references:
                        data_component_name = log_source.get("data_component_name", "")
                        name = log_source.get("name", "")
                        channel = log_source.get("channel", "")
                        lines.append(f"| {name} | {data_component_name} | {channel} |")

                # Mutable elements
                if analytic.mutable_elements:
                    lines.extend(
                        [
                            "",
                            "",
                            "### Mutable Elements",
                            "",
                            "| Field | Description |",
                            "| --- | --- |",
                        ]
                    )
                    for element in analytic.mutable_elements:
                        field = element.get("field", "")
                        description = element.get("description", "")
                        lines.append(f"| {field} | {description} |")

                content = "\n".join(lines)
                content = convert_to_local_links(text=content)
                content = content.replace("MITRE_URL", analytic.url)

                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")
