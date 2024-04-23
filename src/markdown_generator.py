from . import ROOT

import os
import json
import uuid

class MarkdownGenerator():

    def __init__(self, output_dir=None, software=[], tactics=[], techniques=[], mitigations=[], groups=[]):
        if output_dir:
            self.output_dir = os.path.join(ROOT, output_dir)
        self.tactics = tactics
        self.techniques = techniques
        self.mitigations = mitigations
        self.groups = groups
        self.software = software


    def create_tactic_notes(self):
        tactics_dir = os.path.join(self.output_dir, "tactics")
        if not os.path.exists(tactics_dir):
            os.mkdir(tactics_dir)

        for tactic in self.tactics:
            tactic_file = os.path.join(tactics_dir, f"{tactic.name}.md")

            with open(tactic_file, 'w') as fd:
                content = f"---\nalias: {tactic.id}\n---"
                content += f"\n\n## {tactic.id}\n"
                content += f"\n{tactic.description}\n\n"
                
                content += "### References\n"
                for ref in tactic.references.keys():
                    content += f"- {ref}: {tactic.references[ref]}\n"
                fd.write(content)


    def create_technique_notes(self):
        techniques_dir = os.path.join(self.output_dir, "techniques")
        if not os.path.exists(techniques_dir):
            os.mkdir(techniques_dir)

        for technique in self.techniques:
            technique_file = os.path.join(techniques_dir, f"{technique.name}.md")

            with open(technique_file, 'w') as fd:
                content = f"---\nalias: {technique.id}\n---\n\n"

                content += f"## {technique.id}\n\n"
                content += f"{technique.description}\n\n\n"


                content += "### Tactic\n"
                for kill_chain in technique.kill_chain_phases:
                    if kill_chain['kill_chain_name'] == 'mitre-attack':
                        tactic = [ t for t in self.tactics if t.name.lower().replace(' ', '-') == kill_chain['phase_name'].lower() ]
                        if tactic:
                            for t in tactic:
                                content += f"- [[{t.name}]] ({t.id})\n" 

                content += "\n### Platforms\n"
                for platform in technique.platforms:
                    content += f"- {platform}\n"

                content += "\n### Permissions Required\n"
                for permission in technique.permissions_required:
                    content += f"- {permission}\n"

                content += "\n### Mitigations\n"
                if technique.mitigations:
                    content += "\n| ID | Name | Description |\n| --- | --- | --- |\n"
                    for mitigation in technique.mitigations:
                        description = mitigation['description'].replace('\n', '<br />')
                        content += f"| [[{mitigation['mitigation'].name}\\|{mitigation['mitigation'].id}]] | {mitigation['mitigation'].name} | {description} |\n"

                if not technique.is_subtechnique:
                    content += "\n### Sub-techniques\n"
                    subtechniques = [ subt for subt in self.techniques if subt.is_subtechnique and technique.id in subt.id ]
                    if subtechniques:
                        content += "\n| ID | Name |\n| --- | --- |\n"
                    for subt in subtechniques:
                        content += f"| [[{subt.name}\\|{subt.id}]] | {subt.name} |\n"


                content += "\n\n---\n### References\n\n"
                for ref in technique.references.keys():
                    content += f"- {ref}: {technique.references[ref]}\n"

                fd.write(content)


    def create_mitigation_notes(self):
        mitigations_dir = os.path.join(self.output_dir, "mitigations")
        if not os.path.exists(mitigations_dir):
            os.mkdir(mitigations_dir)

        for mitigation in self.mitigations:
            mitigation_file = os.path.join(mitigations_dir, f"{mitigation.name}.md")

            with open(mitigation_file, 'w') as fd:
                content = f"---\nalias: {mitigation.id}\n---\n\n"

                content += f"## {mitigation.id}\n\n"
                content += f"{mitigation.description}\n\n\n"


                content += "### Techniques Addressed by Mitigation\n"
                if mitigation.mitigates:
                    content += "\n| ID | Name | Description |\n| --- | --- | --- |\n"
                    for technique in mitigation.mitigates:
                        description = technique['description'].replace('\n', '<br />')
                        content += f"| [[{technique['technique'].name}\\|{technique['technique'].id}]] | {technique['technique'].name} | {description} |\n"


                fd.write(content)


    def create_group_notes(self):
        groups_dir = os.path.join(self.output_dir, "groups")
        if not os.path.exists(groups_dir):
            os.mkdir(groups_dir)

        for group in self.groups:
            group_file = os.path.join(groups_dir, f"{group.name}.md")

            with open(group_file, 'w') as fd:
                content = f"---\nalias: {', '.join(group.aliases)}\n---\n\n"

                content += f"## {group.name}\n\n"
                content += f"{group.description}\n\n\n"

                content += "```ad-info\n"
                content += f"ID: {group.id}\n"
                content += f"Contributors: {', '.join(group.contributors)}\n"
                content += f"Version: {group.version}\n"
                content += f"Created: {group.created}\n"
                content += f"Last Modified: {group.modified}\n"
                content += "```\n"

                content += "### Techniques Used\n"

                if group.techniques_used:
                    content += "\n| ID | Name | Use |\n| --- | --- | --- |\n"
                    for technique in group.techniques_used:
                        description = technique['description'].replace('\n', '<br />')
                        content += f"| [[{technique['technique'].name}\\|{technique['technique'].id}]] | {technique['technique'].name} | {description} |\n"

                content += "\n\n### References\n\n"

                for reference in group.references:
                    content += f"{reference}\n"

                for ref in group.references.keys():
                    content += f"- {ref}: {group.references[ref]}\n"

                fd.write(content)


    def create_software_notes(self):
        software_dir = os.path.join(self.output_dir, "software")
        if not os.path.exists(software_dir):
            os.mkdir(software_dir)

        for software in self.software:
            software_file = os.path.join(software_dir, f"{software.name}.md")

            with open(software_file, 'w') as fd:
                content = f"---\nalias: {software.id}\n---\n\n"

                content += f"## {software.name}\n\n"
                content += f"{software.description}\n\n\n"

                content += "```ad-info\n"
                content += f"ID: {software.id}\n"
                content += f"Type: {software.type}\n"
                platforms =[ ', '.join(platform) for platform in software.platforms ]
                content += f"Platforms: {''.join(platforms)}\n"
                content += f"Contributors: {', '.join(software.contributors)}\n"
                content += f"Version: {software.version}\n"
                content += f"Created: {software.created}\n"
                content += f"Last Modified: {software.modified}\n"
                content += "```\n"

                content += "### Techniques Used\n"
                if software.techniques_used:
                    content += "\n| ID | Name | Use |\n| --- | --- | --- |\n"
                    for technique in software.techniques_used:
                        description = technique['description'].replace('\n', '<br />')
                        content += f"| [[{technique['technique'].name}\\|{technique['technique'].id}]] | {technique['technique'].name} | {description} |\n"

                content += "\n### Groups That Use This Software\n"
                try:
                    if software.groups_using:
                        content += "\n| ID | Name | Use |\n| --- | --- | --- |\n"
                        for group in software.groups_using:
                            description = group['description'].replace('\n', '<br />')
                            content += f"| [[{group['group'].name}\\|{group['group'].id}]] | {group['group'].name} | {description} |\n"
                except AttributeError:
                    pass

                content += "\n\n### References\n\n"
                for ref in software.references.keys():
                    content += f"- {ref}: {software.references[ref]}\n"

                fd.write(content)

    def create_canvas(self, canvas_name, filtered_techniques):
        canvas = {
                "nodes": [],
                "edges": []
            }

        x = 0
        columns = {
                    "Reconnaissance": 0,
                    "Resource Development": 500,
                    "Initial Access": 1000,
                    "Execution": 1500,
                    "Persistence": 2000,
                    "Privilege Escalation": 2500,
                    "Defense Evasion": 3000,
                    "Credential Access": 3500,
                    "Discovery": 4000,
                    "Lateral Movement": 4500,
                    "Collection": 5000,
                    "Command and Control": 5500,
                    "Exfiltration": 6000,
                    "Impact": 6500,
                }


        rows = dict()
        height = 144
        y = 50
        max_height = y
        for technique in self.techniques:
            if technique.id in filtered_techniques:
                if not technique.is_subtechnique:
                    for kill_chain in technique.kill_chain_phases:
                        if kill_chain['kill_chain_name'] == 'mitre-attack':
                            tactic = [ t for t in self.tactics if t.name.lower().replace(' ', '-') == kill_chain['phase_name'].lower() ]
                            if tactic:
                                if tactic[0].name in rows.keys():
                                    y = rows[tactic[0].name]
                                else:
                                    y = 50
                                    rows[tactic[0].name] = y
                                x = columns[tactic[0].name] + 20

                    technique_node = {
                                "type": "file",
                                "file": f"techniques/{technique.name}.md",
                                "id": uuid.uuid4().hex,
                                "x": x,
                                "y": y,
                                "width": 450,
                                "height": height
                            }
                    canvas['nodes'].append(technique_node)
                    y = y + height + 20
                    subtechniques = [ subt for subt in self.techniques if subt.is_subtechnique and technique.id in subt.id ]
                    if subtechniques:
                        for subt in subtechniques:
                            subtech_node = {
                                        "type": "file",
                                        "file": f"techniques/{subt.name}.md",
                                        "id": uuid.uuid4().hex,
                                        "x": x + 50,
                                        "y": y,
                                        "width": 400,
                                        "height": height
                                    }
                            y = y + height + 20
                            canvas['nodes'].append(subtech_node)
                    
                    rows[tactic[0].name] = y
                    if y > max_height:
                        max_height = y

        for tactic in self.tactics:
            container_node = {
                        "type": "group",
                        "label": f"{tactic.name}",
                        "id": uuid.uuid4().hex,
                        "x": columns[tactic.name],
                        "y": 0,
                        "width": 500,
                        "height": max_height + 20
                    }
            canvas['nodes'].append(container_node)
                        
            
        with open(f"{canvas_name}.canvas", 'w') as fd:
            fd.write(json.dumps(canvas, indent=2))
            

