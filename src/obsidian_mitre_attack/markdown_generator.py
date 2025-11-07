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
                + match.group(1).replace("/", "／")  # noqa: RUF001
                + " - "
                + match.group(2).replace("/", ".")
                + "]]"
            )
        else:
            return "[[" + match.group(1).replace("/", "／") + "]]"  # noqa: RUF001

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
        self.tags_prefix = arguments.tags

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
                    lines.append(">")
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
                    lines.append(">")
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
                    f"| [[{example['name'].replace('/', '／')} \\| {example['id']}]] | [[{example['name'].replace('/', '／')} \\| {example['name'].replace('/', '／')}]] | {description} |"
                )  # noqa: RUF001
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
        """Function to create markdown notes for detection."""
        if technique.detections:
            lines = [
                "",
                "",
                "### Detection",
                "",
                "| ID | Data Source | Data Source Type | Detects |",
                "| --- | --- | --- | --- |",
            ]
            for detection in sorted(technique.detections, key=lambda x: x["id"]):
                description = fix_description(description_str=detection["description"])
                description = description.replace("\n", "<br />")
                lines.append(
                    f"| {detection['id']} | {detection['data_source']} | {detection['name']} | {description} |"
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

                # References
                ref_lines = ["", "", "### References", ""]
                for ref in technique.external_references:
                    name: str = ref["name"].replace(" ", "_")
                    if "url" in ref:
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

                    # References
                    ref_lines = ["", "", "### References", ""]
                    for ref in mitigation.external_references:
                        name = ref["name"].replace(" ", "_")
                        if "url" in ref:
                            ref_lines.append(
                                f"[^{name}]: [{ref['description']}]({ref['url']})"
                            )

                    if mitigation.external_references:
                        for alias in mitigation.external_references:
                            if "url" in alias:
                                name: str = alias["name"].replace(" ", "_")
                                ref_lines.append(
                                    f"[^{name}]: [{alias['description']}]({alias['url']})"
                                )

                    content = content + "\n".join(ref_lines)
                    content = content.replace("MITRE_URL", mitigation.url)
                    fd.write(content)
                    if not content.endswith("\n"):
                        fd.write("\n")

    def create_group_notes(self) -> None:  # noqa: PLR0912
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

            # References
            ref_lines = ["", "", "### References", ""]
            for ref in group.external_references:
                name = ref["name"].replace(" ", "_")
                if "url" in ref:
                    ref_lines.append(f"[^{name}]: [{ref['description']}]({ref['url']})")

            if group.aliases_references:
                for alias in group.aliases_references:
                    if "url" in alias:
                        name: str = alias["name"].replace(" ", "_")
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
                    f"| {domain} | [[{technique['technique'].name.replace('/', '／')} - {external_id} \\| {external_id}]] | {technique['technique'].name} | {description} |"
                )  # noqa: RUF001

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

            # References
            content += "\n\n### References\n\n"

            for ref in software.external_references:
                name: str = ref["name"].replace(" ", "_")
                if "url" in ref:
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

    def create_campaign_notes(self) -> None:
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
                            f"| {domain} | [[{technique['technique_name'].replace('/', '／')} - {technique['technique_id']} \\| {technique['technique_id']}]] | {technique['technique_name']} | {description} |"
                        )  # noqa: RUF001

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

                # References
                ref_lines = ["", "", "### References", ""]
                for ref in campaign.external_references:
                    name: str = ref["name"].replace(" ", "_")
                    if "url" in ref:
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

                # References
                if asset.external_references and len(asset.external_references) > 0:
                    ref_lines = ["", "", "### References", ""]
                    for ref in asset.external_references:
                        name = ref["name"].replace(" ", "_")
                        if "url" in ref:
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
        data_sources_dir = Path(self.output_dir, "Defenses", "Data_Sources")
        data_sources_dir.mkdir(parents=True, exist_ok=True)

        for data_source in self.data_sources:
            data_source_file = Path(data_sources_dir, f"{data_source.name}.md")

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

                # References
                if (
                    data_source.external_references
                    and len(data_source.external_references) > 0
                ):
                    ref_lines = ["", "", "### References", ""]
                    for ref in data_source.external_references:
                        name: str = ref["name"].replace(" ", "_")
                        if "url" in ref:
                            ref_lines.append(
                                f"[^{name}]: [{ref['description']}]({ref['url']})"
                            )
                    content = content + "\n".join(ref_lines)

                content = content.replace("MITRE_URL", data_source.url)

                fd.write(content)
                if not content.endswith("\n"):
                    fd.write("\n")
