"""Generate markdown."""
import re
from pathlib import Path
from typing import Any

# Utility functions

def fix_description(description_str) -> str:
    """Fix the description of a technique."""
    def match_citation(match) -> Any:
        return '[^' + match.group(1).replace(" ", "_") + ']'
    description: str = re.sub(pattern=r'\(Citation: ([^)]+?)\)', repl=match_citation, string=description_str)
    return description


def convert_to_local_links(text: str) -> str:
    """Function to convert to local links."""
    def match_link(match) -> Any:
        if match.group(2)[0] == 'T' or match.group(2)[0] == 'M':
            return '[[' + match.group(1).replace('/', '／') + ' - ' + match.group(2).replace('/', '.') + ']]'  # noqa: RUF001
        else:
            return '[[' + match.group(1).replace('/', '／') + ']]'  # noqa: RUF001
    # Fix inconsistent links from Mitre
    if "[Exaramel](https://attack.mitre.org/software/S0343)" in text:
        text = text.replace("[Exaramel]", "[Exaramel for Windows]")
    if "https://attack.mitre.org/techniques/T1086" in text:
        text = text.replace("https://attack.mitre.org/techniques/T1086", "https://attack.mitre.org/techniques/T1059/001")
    return re.sub(pattern=r'\[([^\]]*?)\]\(https://attack.mitre.org/[^/]+/([^\)]+?)\)', repl=match_link, string=text)


def remove_references(text) -> str:
    """Function to remove references from the text."""
    return re.sub(pattern=r'\[\^[^\]]+?\]', repl='', string=text)

class MarkdownGenerator:
    """Class to generate markdown notes for MITRE ATT&CK data."""
    def __init__(self,
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
        dirname: str = domain.replace('-', ' ').capitalize().replace('Ics ', 'ICS ')
        tactics_dir = Path(self.output_dir, "Tactics", dirname)
        tactics_dir.mkdir(parents=True, exist_ok=True)

        for tactic in self.tactics:
            if tactic.domain == domain:
                tactic_file = Path(tactics_dir, f"{tactic.name} - {tactic.id}.md")

                # Create markdown file for current tactic
                with open(file=tactic_file, mode='w') as fd:
                    content: str = "---\naliases:\n"
                    content += f"  - {tactic.id}\n"
                    content += f"  - {tactic.name}\n"
                    content += f"  - {tactic.name} ({tactic.id})\n"
                    content += f"  - {tactic.id} ({tactic.name})\n"
                    content += "url: MITRE_URL\n"
                    content += "tags:\n"
                    content += f"  - {self.tags_prefix}tactic\n"
                    content += f"  - {self.tags_prefix}mitre_attack\n"
                    content += f"  - {self.tags_prefix}{tactic.domain}\n"
                    content += "---"

                    content += f"\n\n## {tactic.id}\n"
                    tactic_description: str = fix_description(description_str=tactic.description)
                    content += f"\n{tactic_description}\n\n"

                    # Tactic Information
                    content += "> [!info]\n"
                    content += f"> ID: {tactic.id}\n"
                    content += f"> Created: {str(object=tactic.created).split(sep=' ')[0]}\n"
                    content += f"> Last Modified: {str(object=tactic.modified).split(sep=' ')[0]}\n\n\n"

                    # Techniques Used
                    if tactic.techniques_used:
                        content += "### Techniques Used\n"
                        content += "\n| ID | Name | Use |\n| --- | --- | --- |\n"
                        for technique in sorted(tactic.techniques_used, key=lambda x: x['id']):
                            description: str = fix_description(description_str=technique['description'])
                            description = description[0:description.find('\n')]
                            description = remove_references(text=description)
                            content += f"| [[{technique['name']} - {technique['id']} \\| {technique['id']}]] | {technique['name']} | {description} |\n"

                    content: str = convert_to_local_links(text=content)
                    content = content.replace("MITRE_URL", tactic.url)
                    fd.write(content)


    def create_technique_notes_header(self, technique) -> str:
        """Function to create markdown headers for techniques."""
        content: str = "---\naliases:\n"
        content += f"  - {technique.id}\n"
        content += f"  - {technique.name}\n"
        content += f"  - {technique.name} ({technique.id})\n"
        content += f"  - {technique.id} ({technique.name})\n"
        content += "url: MITRE_URL\n"
        content += "tags:\n"
        content += f"  - {self.tags_prefix}technique\n"
        content += f"  - {self.tags_prefix}mitre_attack\n"
        content += f"  - {self.tags_prefix}{technique.domain}\n"
        if technique.platforms and 'None' not in technique.platforms:
            for platform in technique.platforms:
                if platform:
                    content += f"  - {self.tags_prefix}{platform.replace(' ', '_')}\n"

        if technique.supports_remote:
            content += f"  - {self.tags_prefix}supports_remote\n"
        content += "---\n\n"
        return content


    def create_technique_notes_subtechnique(self, content: str, technique) -> str:
        """Function to create markdown notes for sub-techniques."""
        if technique.is_subtechnique:
            content += f"## {technique.parent_name}: {technique.name}\n\n"
        else:
            content += f"## {technique.name}\n\n"

        if technique.is_subtechnique:
            first = True
            for subt in sorted(technique.subtechniques, key=lambda x: x['id']):
                if first:
                    content += f"> [!summary]- Other sub-techniques of {technique.parent_name} ({len(technique.subtechniques)})\n" # TODO
                    content += ">"
                    content += "> | ID | Name |\n| --- | --- |\n"
                    first = False
                if subt['id'] == technique.id:
                    content += f"> | {subt['id']} | {subt['name']} |\n"
                else:
                    content += f"> | [[{subt['name']} - {subt['id']} \\| {subt['id']}]] | [[{subt['name']} - {subt['id']} \\| {subt['name']}]] |\n"
            content += "\n\n"
        elif technique.subtechniques:
            first = True
            for subt in sorted(technique.subtechniques, key=lambda x: x['id']):
                if first:
                    content += f"> [!summary]- Sub-techniques ({len(technique.subtechniques)})\n"
                    content += ">"
                    content += "> | ID | Name |\n| --- | --- |\n"
                    first = False
                content += f"> | [[{subt['name']} - {subt['id']} \\| {subt['id']}]] | {subt['name']} |\n"
            content += "\n\n"
        return content


    def create_technique_notes_information(self, content: str, technique) -> str:
        """Function to create markdown notes for technique information."""
        technique_description: str = fix_description(description_str=technique.description)
        content += f"{technique_description}\n\n\n"

        # Information for the technique
        content += "> [!info]\n"
        content += f"> ID: {technique.id}\n"
        if technique.is_subtechnique:
            content += f"> Sub-technique of: [[{technique.parent_name} - {technique.id.split('.')[0]}|{technique.id.split('.')[0]}]]\n"
        else:
            content += "> Sub-techniques: "
            tech_first = True
            for subt in sorted(self.techniques, key=lambda x: x.id):
                if subt.is_subtechnique and technique.id in subt.id:
                    if tech_first:
                        content += f"[[{subt.name} - {subt.id} \\| {subt.id}]]"
                        tech_first = False
                    else:
                        content += f", [[{subt.name} - {subt.id} \\| {subt.id}]]"
            content += "\n"
        content += f"> Tactic: [[{technique.tactic_name} - {technique.tactic_id} \\| {technique.tactic_name}]]\n"
        if technique.platforms and 'None' not in technique.platforms:
            content += f"> Platforms: {', '.join(technique.platforms)}\n"
        if technique.permissions_required:
            content += f"> Permissions Required: {', '.join(technique.permissions_required)}\n"
        if technique.effective_permissions:
            content += f"> Effective Permissions: {', '.join(technique.effective_permissions)}\n"
        if technique.defense_bypassed:
            content += f"> Defense Bypassed: {', '.join(technique.defense_bypassed)}\n"
        if technique.supports_remote:
            content += "> Remote Support: Yes\n"
        content += f"> Version: {technique.version}\n"
        content += f"> Created: {str(object=technique.created).split(sep=' ')[0]}\n"
        content += f"> Last Modified: {str(object=technique.modified).split(sep=' ')[0]}\n\n\n"
        return content


    def create_technique_notes_procedure_examples(self, content: str, technique) -> str:
        """Function to create markdown notes for procedure examples."""
        if technique.procedure_examples:
            content += "### Procedure Examples\n"
            content += "\n| ID | Name | Description |\n| --- | --- | --- |\n"
            for example in sorted(technique.procedure_examples, key=lambda x: x['id']):
                description: str = fix_description(description_str=example['description'])
                description = description.replace('\n', '<br />')
                content += f"| [[{example['name'].replace('/', '／')} \\| {example['id']}]] | [[{example['name'].replace('/', '／')} \\| {example['name'].replace('/', '／')}]] | {description} |\n"  # noqa: RUF001
        return content


    def create_technique_notes_targeted_assets(self, content: str, technique) -> str:
        """Function to create markdown notes for targeted assets."""
        if technique.targeted_assets:
            content += "\n\n### Targeted Assets\n"
            content += "\n| ID | Asset |\n| --- | --- |\n"
            for asset in sorted(technique.targeted_assets, key=lambda x: x['id']):
                content += f"| [[{asset['name']} - {asset['id']} \\| {asset['id']}]] | [[{asset['name']} - {asset['id']} \\| {asset['name']}]] |\n"
        return content


    def create_technique_notes_mitigations(self, content: str, technique) -> str:
        """Function to create markdown notes for mitigations."""
        content += "\n### Mitigations\n"
        if technique.mitigations:
            mitigation_first = True
            for mitigation in sorted(technique.mitigations, key=lambda x: x['id']):
                if mitigation['id'] == technique.id:
                    content += "\nThis type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.\n"
                else:
                    if mitigation_first:
                        content += "\n| ID | Name | Description |\n| --- | --- | --- |\n"
                        mitigation_first = False
                    description = fix_description(description_str=mitigation['description'])
                    description = description.replace('\n', '<br />')
                    content += f"| [[{mitigation['name']} - {mitigation['id']} \\| {mitigation['id']}]] | [[{mitigation['name']} - {mitigation['id']} \\| {mitigation['name']}]] | {description} |\n"
        else:
            content += "\nThis type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of system features.\n"
        return content


    def create_technique_notes_detection(self, content: str, technique) -> str:
        """Function to create markdown notes for detection."""
        if technique.detections:
            content += "\n\n### Detection\n"
            content += "\n| ID | Data Source | Data Source Type | Detects |\n| --- | --- | --- | --- |\n"
            for detection in sorted(technique.detections, key=lambda x: x['id']):
                description = fix_description(description_str=detection['description'])
                description = description.replace('\n', '<br />')
                content += f"| {detection['id']} | {detection['data_source']} | {detection['name']} | {description} |\n"
        return content


    def create_technique_notes(self, domain: str) -> None:
        """Function to create markdown notes for techniques."""
        dirname: str= domain.replace('-', ' ').capitalize().replace('Ics ', 'ICS ')
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
                technique_file = Path(technique_name_folder, f"{technique.name} - {technique.id}.md")

                content: str = self.create_technique_notes_header(technique=technique)
                content = self.create_technique_notes_subtechnique(content=content, technique=technique)
                content = self.create_technique_notes_information(content=content, technique=technique)
                content = self.create_technique_notes_procedure_examples(content=content, technique=technique)
                content = self.create_technique_notes_targeted_assets(content=content, technique=technique)
                content = self.create_technique_notes_mitigations(content=content, technique=technique)
                content = self.create_technique_notes_detection(content=content, technique=technique)
                content = convert_to_local_links(text=content)

                # References
                content += "\n\n### References\n\n"
                for ref in technique.external_references:
                    name: str = ref['name'].replace(' ', '_')
                    if 'url' in ref:
                        content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

                content = content.replace("MITRE_URL", technique.url)

                # Create markdown file for current technique
                with open(file=technique_file, mode='w') as fd:
                    fd.write(content)


    def create_mitigation_notes(self, domain: str) -> None:
        """Function to create markdown notes for mitigations."""
        dirname: str = domain.replace('-', ' ').capitalize().replace('Ics ', 'ICS ')
        mitigations_dir = Path(self.output_dir, "Defenses", "Mitigations", dirname)
        mitigations_dir.mkdir(parents=True, exist_ok=True)


        for mitigation in self.mitigations:
            if mitigation.domain == domain:
                mitigation_file = Path(mitigations_dir, f"{mitigation.name} - {mitigation.id}.md")

                # Create markdown file for current mitigation
                with open(file=mitigation_file, mode='w') as fd:
                    content: str = "---\naliases:\n"
                    content += f"  - {mitigation.id}\n"
                    content += f"  - {mitigation.name}\n"
                    content += f"  - {mitigation.name} ({mitigation.id})\n"
                    content += f"  - {mitigation.id} ({mitigation.name})\n"
                    content += "url: MITRE_URL\n"
                    content += "tags:\n"
                    content += f"  - {self.tags_prefix}mitigation\n"
                    content += f"  - {self.tags_prefix}mitre_attack\n"
                    content += f"  - {self.tags_prefix}{mitigation.domain}\n"
                    content += "---\n\n"

                    content += f"## {mitigation.id}\n\n"
                    mitigation_description: str = fix_description(description_str=mitigation.description)
                    content += f"{mitigation_description}\n\n\n"

                    # Mitigation Information
                    content += "> [!info]\n"
                    content += f"> ID: {mitigation.id}\n"
                    content += f"> Version: {mitigation.version}\n"
                    content += f"> Created: {str(object=mitigation.created).split(sep=' ')[0]}\n"
                    content += f"> Last Modified: {str(object=mitigation.modified).split(sep=' ')[0]}\n\n\n"

                    # Techniques Addressed by Mitigation
                    content += "### Techniques Addressed by Mitigation\n"
                    if mitigation.mitigates:
                        content += "\n| Domain | ID | Name | Description |\n| --- | --- | --- | --- |\n"
                        for technique in sorted(mitigation.mitigates, key=lambda x: x['id']):
                            mitre_domain: str = technique['domain'][0].replace('-', ' ').capitalize().replace('Ics ', 'ICS ')
                            description: str = fix_description(description_str=technique['description'])
                            description = description.replace('\n', '<br />')
                            content += f"| {mitre_domain} | [[{technique['name']} - {technique['id']} \\| {technique['id']}]] | {technique['name']} | {description} |\n"

                    content: str = convert_to_local_links(text=content)

                    # References
                    content += "\n\n### References\n\n"
                    for ref in mitigation.external_references:
                        name = ref['name'].replace(' ', '_')
                        if 'url' in ref:
                            content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

                    if mitigation.external_references:
                        for alias in mitigation.external_references:
                            if 'url' in alias:
                                name: str = alias['name'].replace(' ', '_')
                                content += f"[^{name}]: [{alias['description']}]({alias['url']})\n"

                    content = content.replace("MITRE_URL", mitigation.url)
                    fd.write(content)


    def create_group_notes(self) -> None:  # noqa: PLR0912, PLR0915
        """Function to create markdown notes for groups in CTI folder."""
        groups_dir = Path(self.output_dir, "CTI", "Groups")
        groups_dir.mkdir(parents=True, exist_ok=True)

        for group in self.groups:
            group_file = Path(groups_dir, f"{group.name}.md")

            content: str = "---\naliases:\n"
            for alias in group.aliases:
                content += f"  - {alias}\n"
            content += "url: MITRE_URL\n"
            content += "\ntags:\n"
            content += f"  - {self.tags_prefix}group\n"
            content += f"  - {self.tags_prefix}mitre_attack\n"
            content += "---\n\n"

            content += f"## {group.name}\n\n"
            group_description: str = fix_description(description_str=group.description)
            content += f"{group_description}\n\n\n"
            # Group information
            content += "> [!info]\n"
            content += f"> ID: {group.id}\n"
            if group.aliases:
                content += f"> Associated Groups: {', '.join(group.aliases)}\n"
            if group.contributors:
                content += f"> Contributors: {', '.join(group.contributors)}\n"
            content += f"> Version: {group.version}\n"
            content += f"> Created: {str(object=group.created).split(sep=' ')[0]}\n"
            content += f"> Last Modified: {str(object=group.modified).split(sep=' ')[0]}\n\n\n"
            if group.aliases_references:
                content += "\n### Associated Group Descriptions\n"
                content += "\n| Name | Description |\n| --- | --- |\n"
                for alias in group.aliases_references:
                    if 'url' not in alias:
                        description: str = fix_description(description_str=alias['description']).replace('\n', '<br />')
                        content += f"| {alias['name']} | {description} |\n"
                content += "\n\n"

            # Techniques used by group
            if group.techniques_used:
                content += "\n### Techniques Used\n"
                content += "\n| Domain | ID | Name | Use |\n| --- | --- | --- | --- |\n"
                for technique in sorted(group.techniques_used, key=lambda x: x['technique_id']):
                    domain: str = technique['domain'][0].replace('-', ' ').capitalize().replace('Ics ', 'ICS ')
                    description = fix_description(description_str=technique['description'])
                    description = description.replace('\n', '<br />')
                    content += f"| {domain} | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_id']}]] | {technique['technique_name']} | {description} |\n"

            # Software used by group
            if group.software_used:
                content += "\n\n\n### Software Used\n"
                content += "\n| ID | Name | References | Techniques |\n| --- | --- | --- | --- |\n"
                for software in sorted(group.software_used, key=lambda x: x['id']):
                    description = fix_description(description_str=software['description'])
                    content += f"| [[{software['name']} \\| {software['id']}]] | [[{software['name']} \\| {software['name']}]] | {description} | {software['software_techniques']} |\n"

            content = convert_to_local_links(text=content)

            # References
            content += "\n\n### References\n\n"
            for ref in group.external_references:
                name = ref['name'].replace(' ', '_')
                if 'url' in ref:
                    content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

            if group.aliases_references:
                for alias in group.aliases_references:
                    if 'url' in alias:
                        name: str = alias['name'].replace(' ', '_')
                        content += f"[^{name}]: [{alias['description']}]({alias['url']})\n"

            content = content.replace("MITRE_URL", group.url)

            # Create markdown file for current group
            with open(file=group_file, mode='w') as fd:
                fd.write(content)


    def create_software_notes_header(self, software) -> str:
        """Function to create markdown headers for software."""
        content: str =  f"---\naliases:\n  - {software.id}\n"
        content += f"  - {software.name} ({software.id})\n"
        content += f"  - {software.id} ({software.name})\n"
        content += "url: MITRE_URL\n"
        content += "tags:\n"
        content += f"  - {self.tags_prefix}software\n"
        content += f"  - {self.tags_prefix}mitre_attack\n"
        content += f"  - {self.tags_prefix}{software.type}\n"
        if software.platforms and software.platforms != '':
            for platform in software.platforms:
                if platform:
                    content += f"  - {self.tags_prefix}{platform[0].replace(' ', '_')}\n"
        content += "\n---\n\n"

        content += f"## {software.name}\n\n"
        software_description: str = fix_description(description_str=software.description)
        content += f"{software_description}\n\n\n"

        # Software information
        content += "> [!info]\n"
        content += f"> ID: {software.id}\n"
        content += f"> Type: {software.type}\n"
        if software.platforms and software.platforms != [[]]:
            platforms: list[str] = [ ', '.join(platform) for platform in software.platforms ]
            content += f"> Platforms: {''.join(platforms)}\n"
        if software.aliases:
            content += f"> Associated Software: {', '.join(software.aliases)}\n"
        if software.contributors:
            content += f"> Contributors: {', '.join(software.contributors)}\n"
        content += f"> Version: {software.version}\n"
        content += f"> Created: {str(object=software.created).split(sep=' ')[0]}\n"
        content += f"> Last Modified: {str(object=software.modified).split(sep=' ')[0]}\n\n\n"
        return content


    def create_software_notes_info(self, content: str, software) -> str:
        """Function to create markdown notes for software information."""
        # Software information
        content += "### Techniques Used\n"
        if software.techniques_used:
            content += "\n| Domain | ID | Name | Use |\n| --- | --- | --- | --- |\n"
            for technique in sorted(software.techniques_used, key=lambda x: x['technique'].id):
                domain: str = technique['domain'][0].replace('-', ' ').capitalize().replace('Ics ', 'ICS ')
                description: str = fix_description(description_str=technique['description'])
                description = description.replace('\n', '<br />')
                ext_refs= technique['technique'].get('external_references', '')
                external_id: str = ''
                for ref in ext_refs:
                    if ref['source_name'] == 'mitre-attack':
                        external_id = ref['external_id']
                content += f"| {domain} | [[{technique['technique'].name.replace('/', '／')} - {external_id} \\| {external_id}]] | {technique['technique'].name} | {description} |\n"  # noqa: RUF001

        # Groups that use this software
        if software.groups_using:
                content += "\n### Groups That Use This Software\n"
                content += "\n| ID | Name | Use |\n| --- | --- | --- |\n"
                for group in sorted(software.groups_using, key=lambda x: x['group_id']):
                    description = fix_description(description_str=group['description'])
                    description = description.replace('\n', '<br />')
                    content += f"| [[{group['group_name']} \\| {group['group_id']}]] | {group['group_name']} | {description} |\n"
        return content


    def create_software_notes(self) -> None:
        """Function to create markdown notes for software in CTI folder."""
        software_dir = Path(self.output_dir, "CTI", "Software")
        software_dir.mkdir(parents=True, exist_ok=True)

        for software in self.software:
            software_file = Path(software_dir, f"{software.name}.md")

            # Create markdown file for current software
            content: str = self.create_software_notes_header(software=software)
            content = self.create_software_notes_info(content=content, software=software)

            # Software have been used in the following campaigns
            if software.campaigns_using:
                content += "\n\n### Campaigns\n"
                content += "\n| ID | Name | Description |\n| --- | --- | --- |\n"
                for campaign in sorted(software.campaigns_using, key=lambda x: x['campaign_id']):
                    description = fix_description(description_str=campaign['description'])
                    description = description.replace('\n', '<br />')
                    content += f"| [[{campaign['campaign_name']} \\| {campaign['campaign_id']}]] | {campaign['campaign_name']} | {description} |\n"

            content = convert_to_local_links(text=content)

            # References
            content += "\n\n### References\n\n"

            for ref in software.external_references:
                name: str = ref['name'].replace(' ', '_')
                if 'url' in ref:
                    content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

            content = content.replace("MITRE_URL", software.url)

            with open(file=software_file, mode='w') as fd:
                fd.write(content)


    def create_campaign_notes_header(self, campaign) -> str:
        """Function to create markdown headers for campaigns."""
        content: str = "---\naliases:\n"
        content += f"  - {campaign.id}\n"
        content += "url: MITRE_URL\n"
        content += "tags:\n"
        content += f"  - {self.tags_prefix}campaign\n"
        content += f"  - {self.tags_prefix}mitre_attack\n"
        content += "---\n\n"

        content += f"## {campaign.name}\n\n"
        campaign_description: str = fix_description(description_str=campaign.description)
        content += f"{campaign_description}\n\n\n"

        # Campaign information
        content += "> [!info]\n"
        content += f"> ID: {campaign.id}\n"
        content += f"> First Seen: {str(object=campaign.first_seen).split(sep=' ')[0]}\n"
        content += f"> Last Seen: {str(object=campaign.last_seen).split(sep=' ')[0]}\n"
        content += f"> Version: {campaign.version}\n"
        content += f"> Created: {str(object=campaign.created).split(sep=' ')[0]}\n"
        content += f"> Last Modified: {str(object=campaign.modified).split(sep=' ')[0]}\n\n\n"
        return content


    def create_campaign_notes(self) -> None:
        """Function to create markdown notes for campaigns in CTI folder."""
        campaigns_dir = Path(self.output_dir, "CTI", "Campaigns")
        campaigns_dir.mkdir(parents=True, exist_ok=True)

        for campaign in self.campaigns:
            campaign_file = Path(campaigns_dir, f"{campaign.name}.md")

            # Create markdown file for current campaign
            with open(file=campaign_file, mode='w') as fd:
                content: str = self.create_campaign_notes_header(campaign=campaign)
                # Groups that use this campaign
                if campaign.groups:
                    content += "\n### Groups\n"
                    content += "\n| ID | Name | Use |\n| --- | --- | --- |\n"
                    for group in sorted(campaign.groups, key=lambda x: x['group'].id):
                        description: str = fix_description(description_str=group['description'])
                        description = description.replace('\n', '<br />')
                        content += f"| [[{group['group'].name} \\| {group['group'].id}]] | {group['group'].name} | {description} |\n"

                # Techniques used by campaign
                if campaign.techniques_used:
                    content += "\n\n### Techniques Used\n"
                    content += "\n| Domain | ID | Name | Use |\n| --- | --- | --- | --- |\n"
                    for technique in sorted(campaign.techniques_used, key=lambda x: x['technique_id']):
                        domain: str = technique['domain'][0].replace('-', ' ').capitalize().replace('Ics', 'ICS')
                        description = fix_description(description_str=technique['description'])
                        description = description.replace('\n', '<br />')
                        content += f"| {domain} | [[{technique['technique_name'].replace('/', '／')} - {technique['technique_id']} \\| {technique['technique_id']}]] | {technique['technique_name']} | {description} |\n"  # noqa: RUF001

                # Software used in campaign
                if campaign.software_used:
                    content += "\n\n\n### Software\n"
                    content += "\n| ID | Name | Description |\n| --- | --- | --- |\n"
                    for software in sorted(campaign.software_used, key=lambda x: x['software'].id):
                        description = fix_description(description_str=software['description'])
                        description = description.replace('\n', '<br />')
                        external_id: str = ''
                        for ref in software['software'].get('external_references', []):
                            if ref['source_name'] == 'mitre-attack':
                                external_id = ref['external_id']
                        content += f"| [[{software['software'].name} \\| {external_id}]] | {software['software'].name} | {description} |\n"

                content = convert_to_local_links(text=content)

                # References
                content += "\n\n### References\n\n"

                for ref in campaign.external_references:
                    name: str = ref['name'].replace(' ', '_')
                    if 'url' in ref:
                        content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

                content = content.replace("MITRE_URL", campaign.url)
                fd.write(content)


    def create_tool_notes_header(self, asset) -> str:
        """Function to create markdown headers for tools."""
        content: str = f"---\naliases:\n  - {asset.id}\n"
        content += f"  - {asset.name} ({asset.id})\n"
        content += f"  - {asset.id} ({asset.name})\n"
        content += "url: MITRE_URL\n"
        content += "tags:\n"
        content += f"  - {self.tags_prefix}asset\n"
        content += f"  - {self.tags_prefix}mitre_attack\n"
        if asset.platforms and asset.platforms != '':
            for platform in asset.platforms[0]:
                if platform:
                    content += f"  - {self.tags_prefix}{platform.replace(' ', '_')}\n"
        if asset.sectors and asset.sectors != '':
            for sector in asset.sectors[0]:
                if sector:
                    content += f"  - {self.tags_prefix}{sector.replace(' ', '_')}\n"
        content += "---\n\n"

        content += f"## {asset.name}\n\n"
        asset_description: str = fix_description(description_str=asset.description)
        content += f"{asset_description}\n\n\n"

        # Asset information
        content += "> [!info]\n"
        content += f"> ID: {asset.id}\n"
        if asset.platforms and asset.platforms != [[]]:
            platforms: list[str] = [ ', '.join(platform) for platform in asset.platforms ]
            content += f"> Platforms: {''.join(platforms)}\n"
        if asset.sectors and asset.sectors != [[]]:
            sectors: list[str] = [ ', '.join(sector) for sector in asset.sectors ]
            content += f"> Sectors: {''.join(sectors)}\n"
        content += f"> Version: {asset.version}\n"
        content += f"> Created: {str(object=asset.created).split(sep=' ')[0].split('T')[0]}\n"
        content += f"> Last Modified: {str(object=asset.modified).split(sep=' ')[0].split('T')[0]}\n\n\n"
        return content


    def create_asset_notes(self) -> None:
        """Function to create markdown notes for assets in Defense folder."""
        assets_dir = Path(self.output_dir, "Defenses", "Assets")
        assets_dir.mkdir(parents=True, exist_ok=True)

        for asset in self.assets:
            asset_file = Path(assets_dir, f"{asset.name}.md")

            # Create markdown file for current asset
            with open(file=asset_file, mode='w') as fd:
                content: str = self.create_tool_notes_header(asset=asset)

                # Related assets
                if asset.related_assets:
                    content += "\n### Related Assets\n"
                    content += "\n| Name | Sectors | Description |\n| --- | --- | --- |\n"
                    for related_asset in sorted(asset.related_assets, key=lambda x: x['name']):
                        description: str = fix_description(description_str=related_asset['description'])
                        description = description.replace('\n', '<br />')
                        try:
                            sectors = [ ', '.join(sector) for sector in related_asset.sectors ]
                            content += f"| {related_asset['name']} | {', '.join(sectors)} | {description} |\n"
                        except AttributeError:
                            content += f"| {related_asset['name']} | | {description} |\n"

                # Techniques Addressed by Asset
                if asset.techniques_used:
                    content += "### Techniques Addressed by Asset\n"
                    content += "\n| Domain | ID | Name |\n| --- | --- | --- |\n"
                    for technique in sorted(asset.techniques_used, key=lambda x: x['technique_id']):
                        domain = technique['domain'][0].replace('-', ' ').capitalize().replace('Ics ', 'ICS ')
                        content += f"| {domain} | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_id']}]] | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_name']}]] |\n"

                content = convert_to_local_links(text=content)

                # References
                if asset.external_references and len(asset.external_references) > 0:
                    content += "\n\n### References\n\n"
                    for ref in asset.external_references:
                        name = ref['name'].replace(' ', '_')
                        if 'url' in ref:
                            content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

                content = content.replace("MITRE_URL", asset.url)

                fd.write(content)


    def create_data_source_notes(self) -> None:
        """Function to create markdown notes for data sources in Defense folder."""
        data_sources_dir = Path(self.output_dir, "Defenses", "Data_Sources")
        data_sources_dir.mkdir(parents=True, exist_ok=True)

        for data_source in self.data_sources:
            data_source_file = Path(data_sources_dir, f"{data_source.name}.md")

            # Create markdown file for current data source
            with open(file=data_source_file, mode='w') as fd:
                content: str = f"---\naliases:\n  - {data_source.id}\n"
                content += f"  - {data_source.name} ({data_source.id})\n"
                content += f"  - {data_source.id} ({data_source.name})\n"
                content += "url: MITRE_URL\n"
                content += "tags:\n"
                content += f"  - {self.tags_prefix}data_source\n"
                content += f"  - {self.tags_prefix}mitre_attack\n"
                content += "---\n\n"

                content += f"## {data_source.name}\n\n"
                data_source_description: str = fix_description(description_str=data_source.description)
                content += f"{data_source_description}\n\n\n"

                # Data source information
                content += "> [!info]\n"
                content += f"> ID: {data_source.id}\n"
                if data_source.platforms and data_source.platforms != [[]]:
                    platforms: list[str] = [ ', '.join(platform) for platform in data_source.platforms ]
                    content += f"> Platforms: {''.join(platforms)}\n"
                if data_source.collection_layers and data_source.collection_layers != [[]]:
                    layers: list[str] = [ ', '.join(layer) for layer in data_source.collection_layers ]
                    content += f"> Collection Layers: {''.join(layers)}\n"
                content += f"> Version: {data_source.version}\n"
                content += f"> Created: {str(object=data_source.created).split(sep=' ')[0].split(sep='T')[0]}\n"
                content += f"> Last Modified: {str(object=data_source.modified).split(sep=' ')[0].split('T')[0]}\n\n\n"

                content += "## Data Components\n"

                # Data Components

                for related_data_source in data_source.data_components[0]:
                    content += f"- [[#{related_data_source['data_component_parent']}: {related_data_source['data_component_name']} \\| {related_data_source['data_component_name']}]]\n"

                content += "\n\n"

                for related_data_source in data_source.data_components[0]:
                    content += f"### {related_data_source['data_component_parent']}: {related_data_source['data_component_name']}\n"
                    if related_data_source['data_component_description']:
                        description: str = fix_description(description_str=related_data_source['data_component_description'])
                        description = description.replace('\n', '<br />')
                        content += f"{description}\n\n"

                    content += "| Domain | ID | Name | Detects |\n| --- | --- | --- | --- |\n"

                    for technique in related_data_source['techniques_used']:
                        detects: str = fix_description(description_str=technique['description'])
                        detects = detects.replace('\n', '<br />')
                        content += f"| {technique['domain'][0]} | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_id']}]] | [[{technique['technique_name']} - {technique['technique_id']} \\| {technique['technique_name']}]] | {detects} |\n"

                content = convert_to_local_links(text=content)

                # References
                if data_source.external_references and len(data_source.external_references) > 0:
                    content += "\n\n### References\n\n"
                    for ref in data_source.external_references:
                        name: str = ref['name'].replace(' ', '_')
                        if 'url' in ref:
                            content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

                content = content.replace("MITRE_URL", data_source.url)

                fd.write(content)

