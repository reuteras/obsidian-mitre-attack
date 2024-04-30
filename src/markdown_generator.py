from . import ROOT

import os
import re

# Utility functions

# Function to fix the description of a technique
def fix_description(description_str):
    def match_citation(match):
        return '[^' + match.group(1).replace(" ", "_") + ']'
    description = re.sub(r'\(Citation: ([^)]+?)\)', match_citation, description_str)
    return description

# Function to convert to local links
def convert_to_local_links(text):
    def match_link(match):
        return '[[' + match.group(1).replace('/', '／') + ']]'
    return re.sub(r'\[([^\]]*?)\]\((https://attack.mitre.org/[^\)]+?)\)', match_link, text)

# Class to generate markdown notes
class MarkdownGenerator():
    def __init__(self, output_dir=None, techniques=[], groups=[], tactics=[], mitigations=[], software=[], campaigns=[]):
        if output_dir:
            self.output_dir = os.path.join(ROOT, output_dir)
        self.tactics = tactics
        self.techniques = techniques
        self.mitigations = mitigations
        self.groups = groups
        self.software = software
        self.campaigns = campaigns


    # Function to create markdown notes for tactics
    def create_tactic_notes(self, domain):
        base_dir = os.path.join(self.output_dir, "Tactics")
        if not os.path.exists(base_dir):
            os.mkdir(base_dir)
        tactics_dir = os.path.join(base_dir, domain)
        if not os.path.exists(tactics_dir):
            os.mkdir(tactics_dir)

        for tactic in self.tactics:
            tactic_file = os.path.join(tactics_dir, f"{tactic.name}.md")

            # Create markdown file for current tactic
            with open(tactic_file, 'w') as fd:
                content = "---\naliases:\n"
                content += f"  - {tactic.id}\n"
                content += f"  - {tactic.name} ({tactic.id})\n"
                content += f"  - {tactic.id} ({tactic.name})\n"
                content += "tags:\n"
                content += "  - tactic\n"
                content += "---"

                content += f"\n\n## {tactic.id}\n"
                tactic_description = fix_description(tactic.description)
                content += f"\n{tactic_description}\n\n"

                # Tactic Information
                content += "```ad-info\n"
                content += f"ID: {tactic.id}\n"
                content += f"Created: {str(tactic.created).split(' ')[0]}\n"
                content += f"Last Modified: {str(tactic.modified).split(' ')[0]}\n"
                content += "```\n\n\n"

                # Techniques Used
                if tactic.techniques_used:
                    content += "### Techniques Used\n"
                    content += "\n| ID | Name | Use |\n| --- | --- | --- |\n"
                    for technique in tactic.techniques_used:
                        description = fix_description(technique['description'])
                        description = description[0:description.find('\n')]
                        content += f"| [[{technique['name']}\\|{technique['id']}]] | {technique['name']} | {description} |\n"

                # External References
                content += "\n\n\n"
                content += "### External References\n\n"
                for ref in tactic.external_references:
                    name = ref['name'].replace(' ', '_')
                    if 'url' in ref:
                        content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

                content = convert_to_local_links(content)
                fd.write(content)


    # Function to create markdown notes for techniques
    def create_technique_notes(self, domain):
        base_dir = os.path.join(self.output_dir, "Techniques")
        if not os.path.exists(base_dir):
            os.mkdir(base_dir)
        techniques_dir = os.path.join(base_dir, domain)
        if not os.path.exists(techniques_dir):
            os.mkdir(techniques_dir)

        for technique in self.techniques:
            tactic_folder = os.path.join(techniques_dir, technique.tactic_name)
            if not os.path.exists(tactic_folder):
                os.mkdir(tactic_folder)

            if technique.is_subtechnique:
                parent_technique = [ t for t in self.techniques if t.id in technique.id.split('.')[0]]
                parent_technique = parent_technique[0].name
                technique_name_folder = os.path.join(tactic_folder, parent_technique)
            else:
                technique_name_folder = os.path.join(tactic_folder, technique.name)
            if not os.path.exists(technique_name_folder):
                os.mkdir(technique_name_folder)
            technique_file = os.path.join(technique_name_folder, f"{technique.name}.md")

            # Create markdown file for current technique
            with open(technique_file, 'w') as fd:
                content = "---\naliases:\n"
                content += f"  - {technique.id}\n"
                content += f"  - {technique.name} ({technique.id})\n"
                content += f"  - {technique.id} ({technique.name})\n"
                content += "tags:\n"
                content += "  - technique\n"
                if technique.platforms and 'None' not in technique.platforms:
                    for platform in technique.platforms:
                        if platform:
                            content += f"  - {platform.replace(' ', '_')}\n"

                if technique.supports_remote:
                    content += "  - supports_remote\n"
                content += "---\n\n"

                content += f"## {technique.id}\n\n"
                technique_description = fix_description(technique.description)
                content += f"{technique_description}\n\n\n"

                # Information for the technique
                content += "```ad-info\n"
                content += f"ID: {technique.id}\n"
                if technique.is_subtechnique:
                    content += f"Sub-technique of: {technique.id.split('.')[0]}\n"
                else:
                    content += f"Sub-techniques: {', '.join([ subt.id for subt in self.techniques if subt.is_subtechnique and technique.id in subt.id ])}\n"
                content += f"Data Sources: {', '.join(technique.data_sources)}\n"
                if technique.platforms and 'None' not in technique.platforms:
                    content += f"Platforms: {', '.join(technique.platforms)}\n"
                if technique.permissions_required:
                    content += f"Permissions Required: {', '.join(technique.permissions_required)}\n"
                if technique.effective_permissions:
                    content += f"Effective Permissions: {', '.join(technique.effective_permissions)}\n"
                if technique.defense_bypassed:
                    content += f"Defense Bypassed: {', '.join(technique.defense_bypassed)}\n"
                if technique.supports_remote:
                    content += "Remote Support: Yes\n"
                content += f"Version: {technique.version}\n"
                content += f"Created: {str(technique.created).split(' ')[0]}\n"
                content += f"Last Modified: {str(technique.modified).split(' ')[0]}\n"
                content += "```\n\n\n"

                content += "### Tactic\n"
                for kill_chain in technique.kill_chain_phases:
                    if kill_chain['kill_chain_name'] == 'mitre-attack':
                        tactic = [ t for t in self.tactics if t.name.lower().replace(' ', '-') == kill_chain['phase_name'].lower() ]
                        if tactic:
                            for t in tactic:
                                content += f"  - [[{t.name}]] ({t.id})\n"

                # Mitigations for the technique
                content += "\n\n### Mitigations\n"
                if technique.mitigations:
                    content += "\n| ID | Name | Description |\n| --- | --- | --- |\n"
                    for mitigation in technique.mitigations:
                        description = mitigation['description'].replace('\n', '<br />')
                        content += f"| [[{mitigation['mitigation'].name}\\|{mitigation['mitigation'].id}]] | {mitigation['mitigation'].name} | {description} |\n"

                # List of sub-techniques if the technique is not a sub-technique
                if not technique.is_subtechnique:
                    content += "\n\n### Sub-techniques\n"
                    subtechniques = [ subt for subt in self.techniques if subt.is_subtechnique and technique.id in subt.id ]
                    if subtechniques:
                        content += "\n| ID | Name |\n| --- | --- |\n"
                    for subt in subtechniques:
                        content += f"| [[{subt.name}\\|{subt.id}]] | {subt.name} |\n"

                # References
                content += "\n\n### References\n\n"
                for ref in technique.external_references:
                    name = ref['name'].replace(' ', '_')
                    if 'url' in ref:
                        content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

                content = convert_to_local_links(content)
                fd.write(content)


    # Function to create markdown notes for mitigations
    def create_mitigation_notes(self, domain):
        base_dir = os.path.join(self.output_dir, "Defenses")
        if not os.path.exists(base_dir):
            os.mkdir(base_dir)
        defenses_dir = os.path.join(base_dir, "Mitigations")
        if not os.path.exists(defenses_dir):
            os.mkdir(defenses_dir)
        mitigations_dir = os.path.join(defenses_dir, domain)
        if not os.path.exists(mitigations_dir):
            os.mkdir(mitigations_dir)

        for mitigation in self.mitigations:
            mitigation_file = os.path.join(mitigations_dir, f"{mitigation.name}.md")

            # Create markdown file for current mitigation
            with open(mitigation_file, 'w') as fd:
                content = "---\naliases:\n"
                content += f"  - {mitigation.id}\n"
                content += f"  - {mitigation.name} ({mitigation.id})\n" 
                content += f"  - {mitigation.id} ({mitigation.name})\n" 
                content += "tags:\n"
                content += "  - mitigation\n"
                content += "---\n\n"

                content += f"## {mitigation.id}\n\n"
                mitigation_description = fix_description(mitigation.description)
                content += f"{mitigation_description}\n\n\n"

                # Mitigation Information
                content += "```ad-info\n"
                content += f"ID: {mitigation.id}\n"
                content += f"Version: {mitigation.version}\n"
                content += f"Created: {str(mitigation.created).split(' ')[0]}\n"
                content += f"Last Modified: {str(mitigation.modified).split(' ')[0]}\n"
                content += "```\n\n\n"

                # Techniques Addressed by Mitigation
                content += "### Techniques Addressed by Mitigation\n"
                if mitigation.mitigates:
                    content += "\n| ID | Name | Description |\n| --- | --- | --- |\n"
                    for technique in mitigation.mitigates:
                        description = fix_description(technique['description'])
                        description = description.replace('\n', '<br />')
                        content += f"| [[{technique['technique'].name}\\|{technique['technique'].id}]] | {technique['technique'].name} | {description} |\n"

                # References
                content += "\n\n### References\n\n"
                for ref in mitigation.external_references:
                    name = ref['name'].replace(' ', '_')
                    if 'url' in ref:
                        content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

                if mitigation.external_references:
                    for alias in mitigation.external_references:
                        if 'url' in alias:
                            name = alias['name'].replace(' ', '_')
                            content += f"[^{name}]: [{alias['description']}]({alias['url']})\n"

                content = convert_to_local_links(content)
                fd.write(content)


    # Function to create markdown notes for groups in CTI folder
    def create_group_notes(self):
        cti_dir = os.path.join(self.output_dir, "CTI")
        if not os.path.exists(cti_dir):
            os.mkdir(cti_dir)
        groups_dir = os.path.join(cti_dir, "Groups")
        if not os.path.exists(groups_dir):
            os.mkdir(groups_dir)

        for group in self.groups:
            group_file = os.path.join(groups_dir, f"{group.name}.md")

            # Create markdown file for current group
            with open(group_file, 'w') as fd:
                content = f"---\naliases:\n  - {'\n  - '.join(group.aliases)}\n"
                content += "tags:\n"
                content += "  - group\n"
                content += "---\n\n"

                content += f"## {group.name}\n\n"
                group_description = fix_description(group.description)
                content += f"{group_description}\n\n\n"

                # Group information
                content += "```ad-info\n"
                content += f"ID: {group.id}\n"
                if group.aliases:
                    content += f"Associated Groups: {', '.join(group.aliases)}\n"
                if group.contributors:
                    content += f"Contributors: {', '.join(group.contributors)}\n"
                content += f"Version: {group.version}\n"
                content += f"Created: {str(group.created).split(' ')[0]}\n"
                content += f"Last Modified: {str(group.modified).split(' ')[0]}\n"
                content += "```\n\n\n"

                # Associated group descriptions
                if group.aliases_references:
                    content += "\n### Associated Group Descriptions\n"
                    content += "\n| Name | Description |\n| --- | --- |\n"
                    for alias in group.aliases_references:
                        if 'url' not in alias:
                            description = fix_description(alias['description']).replace('\n', '<br />')
                            content += f"| {alias['name']} | {description} |\n"
                    content += "\n\n"

                # Techniques used by group
                if group.techniques_used:
                    content += "\n### Techniques Used\n"
                    content += "\n| ID | Name | Use |\n| --- | --- | --- |\n"
                    for technique in group.techniques_used:
                        description = fix_description(technique['description'])
                        description = description.replace('\n', '<br />')
                        content += f"| [[{technique['technique'].name}\\|{technique['technique'].id}]] | {technique['technique'].name} | {description} |\n"

                # Software used by group
                if group.software_used:
                    content += "\n\n\n### Software Used\n"
                    content += "\n| ID | Name | References |\n| --- | --- | --- |\n"
                    for software in group.software_used:
                        description = fix_description(software['description'])
                        content += f"| [[{software['name']}\\|{software['id']}]] | [[{software['name']}\\|{software['name']}]] | {description} |\n"

                # References
                content += "\n\n### References\n\n"
                for ref in group.external_references:
                    name = ref['name'].replace(' ', '_')
                    if 'url' in ref:
                        content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

                if group.aliases_references:
                    for alias in group.aliases_references:
                        if 'url' in alias:
                            name = alias['name'].replace(' ', '_')
                            content += f"[^{name}]: [{alias['description']}]({alias['url']})\n"

                content = convert_to_local_links(content)
                fd.write(content)


    # Function to create markdown notes for software in CTI folder
    def create_software_notes(self):
        cti_dir = os.path.join(self.output_dir, "CTI")
        if not os.path.exists(cti_dir):
            os.mkdir(cti_dir)
        software_dir = os.path.join(cti_dir, "Software")
        if not os.path.exists(software_dir):
            os.mkdir(software_dir)

        for software in self.software:
            software_file = os.path.join(software_dir, f"{software.name}.md")

            # Create markdown file for current software
            with open(software_file, 'w') as fd:
                content = f"---\naliases:\n  - {software.id}\n"
                content += f"  - {software.name} ({software.id})\n"
                content += f"  - {software.id} ({software.name})\n"  
                content += "tags:\n"
                content += "  - software\n"
                content += f"  - {software.type}\n"
                if software.platforms:
                    for platform in software.platforms:
                        if platform:
                            content += f"  - {platform[0].replace(' ', '_')}\n"
                content += "\n---\n\n"

                content += f"## {software.name}\n\n"
                software_description = fix_description(software.description)
                content += f"{software_description}\n\n\n"

                # Software information
                content += "```ad-info\n"
                content += f"ID: {software.id}\n"
                content += f"Type: {software.type}\n"
                platforms =[ ', '.join(platform) for platform in software.platforms ]
                content += f"Platforms: {''.join(platforms)}\n"
                if software.aliases:
                    content += f"Associated Software: {', '.join(software.aliases)}\n"
                if software.contributors:
                    content += f"Contributors: {', '.join(software.contributors)}\n"
                content += f"Version: {software.version}\n"
                content += f"Created: {str(software.created).split(' ')[0]}\n"
                content += f"Last Modified: {str(software.modified).split(' ')[0]}\n"
                content += "```\n\n\n"

                # Techniques used by software
                content += "### Techniques Used\n"
                if software.techniques_used:
                    content += "\n| ID | Name | Use |\n| --- | --- | --- |\n"
                    for technique in software.techniques_used:
                        description = fix_description(technique['description'])
                        description = description.replace('\n', '<br />')
                        content += f"| [[{technique['technique'].name}\\|{technique['technique'].id}]] | {technique['technique'].name} | {description} |\n"

                # Groups that use this software
                try:
                    if software.groups_using:
                        content += "\n### Groups That Use This Software\n"
                        content += "\n| ID | Name | Use |\n| --- | --- | --- |\n"
                        for group in software.groups_using:
                            description = fix_description(group['description'])
                            description = description.replace('\n', '<br />')
                            content += f"| [[{group['group'].name}\\|{group['group'].id}]] | {group['group'].name} | {description} |\n"
                except AttributeError:
                    pass

                # Software have been used in the following campaigns
                if software.campaigns_using:
                    content += "\n\n### Campaigns\n"
                    content += "\n| ID | Name | Description |\n| --- | --- | --- |\n"
                    for campaign in software.campaigns_using:
                        description = fix_description(campaign['description'])
                        description = description.replace('\n', '<br />')
                        content += f"| [[{campaign['campaign'].name}\\|{campaign['campaign'].id}]] | {campaign['campaign'].name} | {description} |\n"

                # References
                content += "\n\n### References\n\n"

                for ref in software.external_references:
                    name = ref['name'].replace(' ', '_')
                    if 'url' in ref:
                        content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

                content = convert_to_local_links(content)
                fd.write(content)


    # Function to create markdown notes for campaigns in CTI folder
    def create_campaign_notes(self):
        cti_dir = os.path.join(self.output_dir, "CTI")
        if not os.path.exists(cti_dir):
            os.mkdir(cti_dir)
        campaigns_dir = os.path.join(cti_dir, "Campaigns")
        if not os.path.exists(campaigns_dir):
            os.mkdir(campaigns_dir)

        for campaign in self.campaigns:
            campaign_file = os.path.join(campaigns_dir, f"{campaign.name}.md")

            # Create markdown file for current campaign
            with open(campaign_file, 'w') as fd:
                content = "---\naliases:\n"
                content += f"  - {campaign.id}\n"
                content += "---\n\n"

                content += f"## {campaign.name}\n\n"
                campaign_description = fix_description(campaign.description)
                content += f"{campaign_description}\n\n\n"

                # Campaign information
                content += "```ad-info\n"
                content += f"ID: {campaign.id}\n"
                content += f"First Seen: {str(campaign.first_seen).split(' ')[0]}\n"
                content += f"Last Seen: {str(campaign.last_seen).split(' ')[0]}\n"
                content += f"Version: {campaign.version}\n"
                content += f"Created: {str(campaign.created).split(' ')[0]}\n"
                content += f"Last Modified: {str(campaign.modified).split(' ')[0]}\n"
                content += "```\n"

                # Groups that use this campaign
                if campaign.groups:
                    content += "\n### Groups\n"
                    content += "\n| ID | Name | Use |\n| --- | --- | --- |\n"
                    for group in campaign.groups:
                        description = fix_description(group['description'])
                        description = description.replace('\n', '<br />')
                        content += f"| [[{group['group'].name}\\|{group['group'].id}]] | {group['group'].name} | {description} |\n"

                # Techniques used by campaign
                if campaign.techniques_used:
                    content += "\n\n### Techniques Used\n"
                    content += "\n| ID | Name | Use |\n| --- | --- | --- |\n"
                    for technique in campaign.techniques_used:
                        description = fix_description(technique['description'])
                        description = description.replace('\n', '<br />')
                        content += f"| [[{technique['technique'].name}\\|{technique['technique'].id}]] | {technique['technique'].name} | {description} |\n"

                # Software used in campaign
                if campaign.software_used:
                    content += "\n\n\n### Software\n"
                    content += "\n| ID | Name | Description |\n| --- | --- | --- |\n"
                    for software in campaign.software_used:
                        description = fix_description(software['description'])
                        description = description.replace('\n', '<br />')
                        external_id = ''
                        for ref in software['software'].get('external_references', []):
                            if ref['source_name'] == 'mitre-attack':
                                external_id = ref['external_id']
                        content += f"| [[{software['software'].name}\\|{external_id}]] | {software['software'].name} | {description} |\n"

                # References
                content += "\n\n### References\n\n"

                for ref in campaign.external_references:
                    name = ref['name'].replace(' ', '_')
                    if 'url' in ref:
                        content += f"[^{name}]: [{ref['description']}]({ref['url']})\n"

                content = convert_to_local_links(content)
                fd.write(content)
